use anyhow::{anyhow, bail, Context, Result};
use clap::ArgMatches;
use serde_json::{json, Value};
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs::{read_dir, File};
use std::io::{stdin, BufReader};
use std::path::{Path, PathBuf};
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

type KeyCloakRealmExport = Value;
type KeyCloakRealmImport = Value;
type VaultSecrets = Value;

#[derive(Debug)]
struct Config {
    cluster: String,
    kv_path: String,
    _path_is_file: bool,
    path: PathBuf,
    subcmd: String,
    vault_addr: String,
    vault_mount: String,
    vault_path: String,
    vault_token: String,
}

impl Config {
    fn from_matches(matches: &clap::ArgMatches) -> Result<Self> {
        // Accessing global options
        let vault_mount = matches
            .get_one::<String>("vault_mount")
            .cloned()
            .expect("'vault_mount' should always have a value");
        let vault_token = matches
            .get_one::<String>("vault_token")
            .cloned()
            .expect("'vault_token' should always have a value");
        let vault_addr = matches
            .get_one::<String>("vault_addr")
            .cloned()
            .expect("'vault_addr' should always have a value");
        let cluster = matches
            .get_one::<String>("cluster")
            .cloned()
            .expect("'cluster' should always have a value");

        // File or directory path
        let mut path_is_file = false;
        let path: PathBuf;
        if let Some(filename) = matches.get_one::<PathBuf>("filename") {
            path = filename.clone();
            path_is_file = true;
        } else if let Some(directory) = matches.get_one::<PathBuf>("directory") {
            path = directory.clone()
        } else {
            bail!("Please provide either --filename or --directory\n\nFor more information, try '--help'.");
        };

        // Misc config
        let kv_path = String::from("openshift/argocd");

        // This is an optional override of 'vault_path'
        let vault_path = matches
            .get_one::<String>("vault_path")
            .cloned()
            .unwrap_or_else(|| format!("{kv_path}/{cluster}"));

        // Handle subcommands
        let mut subcmd = String::new();
        match matches.subcommand() {
            Some(("update-avp", _sub_matches)) => {
                subcmd = String::from("update-avp");
            }
            Some(("update-vault", _sub_matches)) => {
                subcmd = String::from("update-vault");
            }
            Some(("do-all-tasks", _sub_matches)) => {
                subcmd = String::from("do-all-tasks");
            }
            _ => (),
        }

        Ok(Config {
            cluster,
            kv_path,
            path,
            _path_is_file: path_is_file,
            subcmd,
            vault_addr,
            vault_mount,
            vault_path,
            vault_token,
        })
    }
}

pub async fn run(matches: ArgMatches) -> Result<()> {
    // Attempt to create the config from matches
    let config = Config::from_matches(&matches)?;

    // Vault client
    let vault_client = init_vault_client(&config.vault_addr, &config.vault_token)?;
    vault_client
        .status()
        .await
        .context("Failed connection health check")?;

    let paths = if Path::new(&config.path).is_dir() {
        read_dir(&config.path)?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                if path.extension()? == "json" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    } else {
        vec![Path::new(&config.path).to_path_buf()]
    };

    for path in paths {
        println!("Processing: {:?}", path);

        let mut json_data: KeyCloakRealmExport = read_json(&path)?;

        // Holds key/value of ids/privatekeys
        let mut private_keys_file: HashMap<String, String> = HashMap::new();

        // Get private keys from keycloak export file and store in `private_keys_file`
        get_private_keys(&json_data, &mut private_keys_file)?;

        // Run subcommand tasks
        if config.subcmd == "update-avp" {
            run_update_avp(&config, &mut json_data, &path)?;
        } else if config.subcmd == "update-vault" {
            run_update_vault(&config, &vault_client, &private_keys_file).await?;
        } else {
            run_update_avp(&config, &mut json_data, &path)?;
            run_update_vault(&config, &vault_client, &private_keys_file).await?;
        }
    }
    Ok(())
}

/// Update argocd-vault-plugin paths in privateKeys entries and write out to yaml
fn run_update_avp(config: &Config, json_data: &mut Value, path: &Path) -> Result<()> {
    let avp = avp_path_generator(&config.vault_mount, &config.kv_path, &config.cluster);
    set_private_keys(json_data, avp)?;

    // Append CRD stuff
    let mut json_data: KeyCloakRealmImport = crd_base(json_data).unwrap();
    json_data["metadata"]["name"] =
        Value::String(path.file_stem().unwrap().to_string_lossy().to_string());

    // Unsure if this should be a option or not
    json_data["spec"]["keycloakCRname"] =
        Value::String(path.file_stem().unwrap().to_string_lossy().to_string());
    // let pp = serde_json::to_string_pretty(&json_data).unwrap();
    // println!("{}", pp);

    // Write out to YAML
    let yaml: YamlValue = convert_json_to_yaml(&json_data)?;
    let filename = path.with_extension("yaml");
    println!("Writing file: {:?}", filename);
    let file = File::create(&filename)?;
    serde_yaml::to_writer(file, &yaml)?;
    Ok(())
}

/// Update private keys in Vault
async fn run_update_vault(
    config: &Config,
    vault_client: &VaultClient,
    private_keys_file: &HashMap<String, String>,
) -> Result<()> {
    // Turn private keys extracted from keycloak export into serde_json Value
    let private_keys_value: VaultSecrets = serde_json::to_value(private_keys_file)?;

    // Fetch private keys from Vault
    let mut private_keys_vault =
        fetch_secrets_vault(vault_client, &config.vault_mount, &config.vault_path).await?;

    // Clone a copy of the vault private keys so we can use it to filter out
    // keys in Vault that are not part of this change. When that is done we can compare
    // it for changes with the private keys from the Keycloak exported files.
    // Main reason is that this program just add new keys and merge changes to existing
    // keys without "cleaning" up stale keys in Vault.
    let mut private_keys_vault_clone = private_keys_vault.clone();

    synchronize_keys(&mut private_keys_vault_clone, &private_keys_value);

    if let Some(true) = compare_private_keys(&private_keys_value, &private_keys_vault_clone) {
        println!("No changes detected, not updating secrets in Vault");
    } else {
        println!("Changes detected, updating secrets in Vault");
        merge_json(&mut private_keys_vault, &private_keys_value);
        set_secrets_vault(
            vault_client,
            &config.vault_mount,
            &config.vault_path,
            &private_keys_vault,
        )
        .await?;
    }
    Ok(())
}

/// Attempts to read a JSON file
fn read_json(filename: &PathBuf) -> Result<KeyCloakRealmExport> {
    if filename.as_os_str() == "-" {
        // stdin
        let json_data: KeyCloakRealmExport = serde_json::from_reader(stdin())?;
        Ok(json_data)
    } else {
        // file
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let json_data: KeyCloakRealmExport = serde_json::from_reader(reader)?;
        Ok(json_data)
    }
}

/// Generate AVP paths
fn avp_path_generator<'a>(
    mount: &'a str,
    kv_path: &'a str,
    cluster: &'a str,
) -> impl Fn(&str) -> String + 'a {
    move |id: &str| format!("<path:{mount}/data/{kv_path}/{cluster}#{id}>")
}

/// Convert JSON to YAML
fn convert_json_to_yaml(json_value: &KeyCloakRealmExport) -> Result<YamlValue> {
    let json_string = serde_json::to_string(json_value)?;
    let yaml_value: YamlValue = serde_yaml::from_str(&json_string)?;
    Ok(yaml_value)
}

/// CR with exported JSON appended to spec realm
fn crd_base(json_data: &KeyCloakRealmExport) -> Result<KeyCloakRealmImport> {
    let crd_base = json!({
        "apiVersion": "k8s.kecloak.org/v2alpha1",
        "kind": "KeyCloakRealmImport",
        "metadata": {"name": ""},
        "spec": {
            "keycloakCRname": "",
            "realm": json_data
    }
        }
    );
    Ok(crd_base)
}

/// Collect and remove keys that are in obj1 but not in obj2
fn synchronize_keys(obj_1: &mut Value, obj_2: &Value) {
    // Ensure both obj_1 and obj_2 are JSON objects
    if let (Value::Object(map1), Value::Object(map2)) = (obj_1, obj_2) {
        // Collect the keys in obj_2
        let keys_in_obj2: std::collections::HashSet<_> = map2.keys().collect();

        // Collect keys that are in obj_1 but not in obj_2
        let keys_to_remove: Vec<String> = map1
            .keys()
            .filter(|&k| !keys_in_obj2.contains(k))
            .cloned()
            .collect();

        // Remove those keys from obj_1
        for key in keys_to_remove {
            // println!("Key not present in source file: {}", key);
            map1.remove(&key);
        }
    }
}

/// Compare private keys from file and from vault
fn compare_private_keys(file: &Value, vault: &Value) -> Option<bool> {
    if file == vault {
        // Check if both are non-empty arrays or non-empty objects
        if (file.is_array() && !file.as_array().unwrap().is_empty())
            || (file.is_object() && !file.as_object().unwrap().is_empty())
        {
            Some(true)
        } else {
            println!("Source had no private keys, keycloak export gone wrong?");
            Some(true)
        }
    } else {
        None
    }
}

/// Merge two JSON objects recursively
fn merge_json(target: &mut Value, source: &Value) {
    if let (Value::Object(target_map), Value::Object(source_map)) = (target, source) {
        // Merge each key-value pair from `source` into `target`
        for (key, value) in source_map {
            match target_map.get_mut(key) {
                Some(existing_value) => {
                    // If both `existing_value` and `value` are objects, merge recursively
                    if existing_value.is_object() && value.is_object() {
                        merge_json(existing_value, value);
                    } else {
                        // Otherwise, replace `existing_value` with `value`
                        *existing_value = value.clone();
                    }
                }
                // Insert if the key does not exist in `target`
                None => {
                    target_map.insert(key.clone(), value.clone());
                }
            }
        }
    }
}

/// Fetch secrets from Vault, wrapping around `fetch_secrets`
async fn fetch_secrets_vault(
    client: &VaultClient,
    mount: &str,
    path: &str,
) -> Result<VaultSecrets> {
    let res = fetch_secrets(client, mount, path).await?;
    match res {
        Some(secret) => Ok(secret),
        None => Ok(json!({})),
    }
}

/// Init Vault client
fn init_vault_client(vault_addr: &str, vault_token: &str) -> Result<VaultClient> {
    let mut settings = VaultClientSettingsBuilder::default();
    if !vault_addr.is_empty() {
        settings.address(vault_addr);
    };
    if !vault_token.is_empty() {
        settings.token(vault_token);
    }
    let client = VaultClient::new(settings.build()?)?;
    Ok(client)
}

/// Fetch secrets from Vault
async fn fetch_secrets(
    client: &VaultClient,
    mount: &str,
    path: &str,
) -> Result<Option<VaultSecrets>> {
    match kv2::read(client, mount, path).await {
        // match vault_response(secret) {
        Ok(secret) => Ok(secret),
        Err(e) => match e {
            ClientError::APIError { code, ref errors } => {
                if code == 404 {
                    // Invalid path: Handle 404 as "OK", returning None
                    // No secrets yet at this path in Vault, so to us its no error
                    return Ok(None);
                };
                let formatted_errors = if errors.is_empty() {
                    "No additional error details provided.".to_string()
                } else {
                    errors
                        .iter()
                        .map(|err| format!("- {}", err))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                let error_message = format!(
                    "API error occurred:\nStatus code: {}\nErrors:\n{}",
                    code, formatted_errors
                );
                Err(anyhow::anyhow!(error_message).context("Received an API error"))
            }
            other_error => Err(anyhow::anyhow!(other_error)
                .context("An unexpected error occurred while retrieving the secret")),
        },
    }
}

/// Set secrets in Vault
async fn set_secrets_vault(
    client: &VaultClient,
    mount: &str,
    path: &str,
    data: &Value,
) -> Result<bool> {
    let status = kv2::set(client, mount, path, data).await.with_context(|| {
        format!("Failed to set secret in 'set_secrets_vault' (mount: {mount}, path: {path})")
    })?;
    println!("Wrote secret to vault, version: {:?}", status.version);
    Ok(true)
}

/// Get private keys from keycloak exported JSON data
fn get_private_keys(
    json_data: &KeyCloakRealmExport,
    private_keys: &mut HashMap<String, String>,
) -> Result<()> {
    // let mut private_keys = private_keys.unwrap_or_default();

    let key_provider = json_data
        .get("components")
        .and_then(|components| components.get("org.keycloak.keys.KeyProvider"))
        .and_then(|key_provider| key_provider.as_array())
        .ok_or_else(|| anyhow!("Expected 'org.keycloak.keys.KeyProvider' as array"))?;

    for entry in key_provider {
        let id = entry
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or_else(|| anyhow!("Expected 'id' in object"))?
            .to_string();

        if let Some(config) = entry.get("config") {
            if let Some(private_key) = config
                .get("privateKey")
                .and_then(|private_key| private_key.as_array())
                .and_then(|private_key_array| private_key_array.first())
                .and_then(|private_key_array_first| private_key_array_first.as_str())
                .map(|private_key| private_key.to_string())
            {
                private_keys.insert(id, private_key);
            }
        }
    }
    Ok(())
}

/// Set private keys with AVP paths
fn set_private_keys(
    json_data: &mut KeyCloakRealmExport,
    avp_gen: impl Fn(&str) -> String,
) -> Result<()> {
    let key_provider = json_data
        .get_mut("components")
        .and_then(|components| components.get_mut("org.keycloak.keys.KeyProvider"))
        .and_then(|key_provider| key_provider.as_array_mut())
        .ok_or_else(|| anyhow!("Expected 'org.keycloak.keys.KeyProvider' as array"))?;

    for entry in key_provider {
        let id = entry
            .get("id")
            .and_then(|id| id.as_str())
            .ok_or_else(|| anyhow!("Expected 'id' in object"))?
            .to_string(); // NOTE: clone to String, removes need for immutable ref to entry

        if let Some(private_key) = entry
            .get_mut("config")
            .and_then(|c| c.get_mut("privateKey"))
            .and_then(|pk| pk.as_array_mut())
            .and_then(|pka| pka.first_mut())
        {
            *private_key = Value::String(avp_gen(&id));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn private_avp_path_generator() {
        let id = "a0908969-93f0-40a2-b56d-f843450c579b";
        let mount = "kv";
        let kv_path = "openshift/argocd";
        let cluster = "cluster01";
        let avp_path = avp_path_generator(mount, kv_path, cluster);
        let expected =
            "<path:kv/data/openshift/argocd/cluster01#a0908969-93f0-40a2-b56d-f843450c579b>";
        assert_eq!(avp_path(id), expected);
    }

    #[test]
    fn private_convert_json_to_yaml() {
        let json_value = json!({
            "apiVersion": "k8s.kecloak.org/v2alpha1",
            "kind": "KeyCloakRealmImport",
            "metadata": {"name": "somemetadataname"},
            "spec": {
                "keycloakCRname": "somekeycloakname",
                "realm": "somerealm"
        }
            }
        );
        let yaml_data_raw = "
apiVersion: k8s.kecloak.org/v2alpha1
kind: KeyCloakRealmImport
metadata:
  name: somemetadataname
spec:
  keycloakCRname: somekeycloakname
  realm: somerealm
";

        let yaml_value: YamlValue = serde_yaml::from_str(yaml_data_raw).unwrap();
        assert_eq!(convert_json_to_yaml(&json_value).unwrap(), yaml_value);
    }
}
