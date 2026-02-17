use anyhow::{anyhow, bail, Context, Result};
use clap::ArgMatches;
use serde_json::{json, Value};
use serde_yaml::Value as YamlValue;
use std::collections::HashMap;
use std::fs::{read_dir, File};
use std::io::{stdin, stdout, BufReader};
use std::path::{Path, PathBuf};
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

type KeyCloakRealmExport = Value;
type KeyCloakRealmImport = Value;
type VaultSecrets = Value;

#[derive(Debug, PartialEq)]
enum SubCommand {
    UpdateAvp,
    UpdateVault,
    All,
}

#[derive(Debug)]
struct Config {
    cluster: String,
    keycloak_cr_name: String,
    kv_path: String,
    output_directory: PathBuf,
    path: PathBuf,
    subcmd: SubCommand,
    vault_addr: String,
    vault_mount: String,
    vault_path: String,
    vault_token: String,
}

impl Config {
    fn from_matches(matches: &ArgMatches) -> Result<Self> {
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

        // Keycloak CR name
        let keycloak_cr_name = matches
            .get_one::<String>("keycloak_cr_name")
            .cloned()
            .unwrap_or_default();

        // File or directory path
        let path: PathBuf;
        if let Some(filename) = matches.get_one::<PathBuf>("filename") {
            path = filename.clone();
            // Require keycloak-cr-name if reading from stdin
            if path.as_os_str() == "-" && keycloak_cr_name.is_empty() {
                bail!("Please provide --keycloak-cr-name if reading from stdin\n\nFor more information, try '--help'.");
            }
        } else if let Some(directory) = matches.get_one::<PathBuf>("directory") {
            path = directory.clone()
        } else {
            bail!("Please provide either --filename or --directory\n\nFor more information, try '--help'.");
        };

        // Output directory
        let output_directory = matches
            .get_one::<PathBuf>("output_directory")
            .cloned()
            .unwrap_or_else(|| PathBuf::from("."));

        // Misc config
        let kv_path = String::from("openshift/argocd");

        // This is an optional override of 'vault_path'
        let vault_path = matches
            .get_one::<String>("vault_path")
            .cloned()
            .unwrap_or_else(|| format!("{kv_path}/{cluster}"));

        // Handle subcommands
        let subcmd = match matches.subcommand() {
            Some(("update-avp", _)) => SubCommand::UpdateAvp,
            Some(("update-vault", _)) => SubCommand::UpdateVault,
            _ => SubCommand::All,
        };

        Ok(Config {
            cluster,
            keycloak_cr_name,
            kv_path,
            output_directory,
            path,
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

    let paths = if config.path.is_dir() {
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
        vec![config.path.clone()]
    };

    for path in paths {
        eprintln!("Processing: {:?}", path);

        let mut json_data: KeyCloakRealmExport = read_json(&path)?;

        // Holds key/value of ids/privatekeys
        let mut private_keys_file: HashMap<String, String> = HashMap::new();

        // Get private keys from keycloak export file and store in `private_keys_file`
        get_private_keys(&json_data, &mut private_keys_file)?;

        // Run subcommand tasks
        match config.subcmd {
            SubCommand::UpdateAvp => {
                run_update_avp(&config, &mut json_data, &path)?;
            }
            SubCommand::UpdateVault => {
                run_update_vault(&config, &vault_client, &private_keys_file).await?;
            }
            SubCommand::All => {
                run_update_avp(&config, &mut json_data, &path)?;
                run_update_vault(&config, &vault_client, &private_keys_file).await?;
            }
        }
    }
    Ok(())
}

/// Update argocd-vault-plugin paths in privateKeys entries and write out to yaml
fn run_update_avp(config: &Config, json_data: &mut Value, path: &Path) -> Result<()> {
    let avp = avp_path_generator(&config.vault_mount, &config.kv_path, &config.cluster);
    set_private_keys(json_data, avp)?;

    // Append CRD stuff
    let mut json_data: KeyCloakRealmImport = crd_base(json_data);

    // Check if keycloakCRname is set
    if !config.keycloak_cr_name.is_empty() && !config.path.is_dir() {
        json_data["metadata"]["name"] = Value::String(config.keycloak_cr_name.to_string());
        json_data["spec"]["keycloakCRname"] = Value::String(config.keycloak_cr_name.to_string());
    } else {
        let name = Value::String(path.file_stem().unwrap().to_string_lossy().into_owned());
        json_data["metadata"]["name"] = name.clone();
        json_data["spec"]["keycloakCRname"] = name;
    }
    // Write YAML
    let yaml: YamlValue = convert_json_to_yaml(&json_data)?;
    if path.as_os_str() == "-" {
        // stdout
        serde_yaml::to_writer(stdout(), &yaml)?;
    } else {
        // file
        let yaml_file = config
            .output_directory
            .join(path.with_extension("yaml").file_name().unwrap_or_default());
        eprintln!("Writing file: {:?}", yaml_file);
        let file = File::create(&yaml_file)?;
        serde_yaml::to_writer(file, &yaml)?;
    }
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

    if compare_private_keys(&private_keys_value, &private_keys_vault_clone) {
        if private_keys_value.as_object().is_none_or(|m| m.is_empty()) {
            eprintln!("Source had no private keys, keycloak export gone wrong?");
        }
        eprintln!("No changes detected, not updating secrets in Vault");
    } else {
        eprintln!("Changes detected, updating secrets in Vault");
        merge_json(&mut private_keys_vault, private_keys_value);
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
fn read_json(filename: &Path) -> Result<KeyCloakRealmExport> {
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
    Ok(serde_yaml::to_value(json_value)?)
}

/// CR with exported JSON appended to spec realm
fn crd_base(json_data: &KeyCloakRealmExport) -> KeyCloakRealmImport {
    json!({
        "apiVersion": "k8s.keycloak.org/v2alpha1",
        "kind": "KeyCloakRealmImport",
        "metadata": {"name": ""},
        "spec": {
            "keycloakCRname": "",
            "realm": json_data
        }
    })
}

/// Collect and remove keys that are in obj1 but not in obj2
fn synchronize_keys(obj_1: &mut Value, obj_2: &Value) {
    if let (Value::Object(map1), Value::Object(map2)) = (obj_1, obj_2) {
        map1.retain(|k, _| map2.contains_key(k));
    }
}

/// Compare private keys from file and from vault
fn compare_private_keys(file: &Value, vault: &Value) -> bool {
    file == vault
}

/// Merge two JSON objects recursively
fn merge_json(target: &mut Value, source: Value) {
    if let (Value::Object(target_map), Value::Object(source_map)) = (target, source) {
        for (key, value) in source_map {
            match target_map.get_mut(&key) {
                Some(existing_value) if existing_value.is_object() && value.is_object() => {
                    merge_json(existing_value, value);
                }
                Some(existing_value) => {
                    *existing_value = value;
                }
                None => {
                    target_map.insert(key, value);
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
) -> Result<()> {
    let status = kv2::set(client, mount, path, data).await.with_context(|| {
        format!("Failed to set secret in 'set_secrets_vault' (mount: {mount}, path: {path})")
    })?;
    eprintln!("Wrote secret to vault, version: {:?}", status.version);
    Ok(())
}

/// Get private keys from keycloak exported JSON data
fn get_private_keys(
    json_data: &KeyCloakRealmExport,
    private_keys: &mut HashMap<String, String>,
) -> Result<()> {
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
        let mount = "secret";
        let kv_path = "openshift/argocd";
        let cluster = "cluster01";
        let avp_path = avp_path_generator(mount, kv_path, cluster);
        let expected =
            "<path:secret/data/openshift/argocd/cluster01#a0908969-93f0-40a2-b56d-f843450c579b>";
        assert_eq!(avp_path(id), expected);
    }

    #[test]
    fn private_convert_json_to_yaml() {
        let json_value = json!({
            "apiVersion": "k8s.keycloak.org/v2alpha1",
            "kind": "KeyCloakRealmImport",
            "metadata": {"name": "somemetadataname"},
            "spec": {
                "keycloakCRname": "somekeycloakname",
                "realm": "somerealm"
        }
            }
        );
        let yaml_data_raw = "
apiVersion: k8s.keycloak.org/v2alpha1
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

    #[test]
    fn merge_json_inserts_new_keys() {
        let mut target = json!({"a": "1"});
        let source = json!({"b": "2"});
        merge_json(&mut target, source);
        assert_eq!(target, json!({"a": "1", "b": "2"}));
    }

    #[test]
    fn merge_json_overwrites_existing_keys() {
        let mut target = json!({"a": "1", "b": "old"});
        let source = json!({"b": "new"});
        merge_json(&mut target, source);
        assert_eq!(target, json!({"a": "1", "b": "new"}));
    }

    #[test]
    fn merge_json_recursive_nested_objects() {
        let mut target = json!({"outer": {"a": "1", "b": "old"}});
        let source = json!({"outer": {"b": "new", "c": "3"}});
        merge_json(&mut target, source);
        assert_eq!(target, json!({"outer": {"a": "1", "b": "new", "c": "3"}}));
    }

    #[test]
    fn merge_json_replaces_non_object_with_value() {
        let mut target = json!({"a": "string"});
        let source = json!({"a": {"nested": "obj"}});
        merge_json(&mut target, source);
        assert_eq!(target, json!({"a": {"nested": "obj"}}));
    }

    /// Helper: builds a realistic Keycloak realm export JSON with two KeyProvider entries
    fn keycloak_realm_fixture() -> Value {
        json!({
            "id": "my-realm",
            "realm": "my-realm",
            "enabled": true,
            "components": {
                "org.keycloak.keys.KeyProvider": [
                    {
                        "id": "a0908969-93f0-40a2-b56d-f843450c579b",
                        "name": "rsa-generated",
                        "providerId": "rsa-generated",
                        "config": {
                            "privateKey": ["MIIEowIBAAKCAQEA0Z3..."],
                            "priority": ["100"],
                            "keySize": ["2048"]
                        }
                    },
                    {
                        "id": "b1234567-89ab-cdef-0123-456789abcdef",
                        "name": "rsa-enc-generated",
                        "providerId": "rsa-enc-generated",
                        "config": {
                            "privateKey": ["MIIEpAIBAAKCAQEA7dG..."],
                            "priority": ["200"],
                            "algorithm": ["RSA-OAEP"]
                        }
                    }
                ]
            }
        })
    }

    // --- get_private_keys tests ---

    #[test]
    fn get_private_keys_extracts_from_valid_json() {
        let json_data = keycloak_realm_fixture();
        let mut keys = HashMap::new();
        get_private_keys(&json_data, &mut keys).unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys["a0908969-93f0-40a2-b56d-f843450c579b"],
            "MIIEowIBAAKCAQEA0Z3..."
        );
        assert_eq!(
            keys["b1234567-89ab-cdef-0123-456789abcdef"],
            "MIIEpAIBAAKCAQEA7dG..."
        );
    }

    #[test]
    fn get_private_keys_skips_entries_without_private_key() {
        let json_data = json!({
            "components": {
                "org.keycloak.keys.KeyProvider": [
                    {
                        "id": "has-key",
                        "config": {
                            "privateKey": ["some-key"],
                            "priority": ["100"]
                        }
                    },
                    {
                        "id": "no-config"
                    },
                    {
                        "id": "empty-config",
                        "config": {
                            "priority": ["100"]
                        }
                    }
                ]
            }
        });
        let mut keys = HashMap::new();
        get_private_keys(&json_data, &mut keys).unwrap();

        assert_eq!(keys.len(), 1);
        assert_eq!(keys["has-key"], "some-key");
        assert!(!keys.contains_key("no-config"));
        assert!(!keys.contains_key("empty-config"));
    }

    #[test]
    fn get_private_keys_errors_on_missing_key_provider() {
        // Missing components entirely
        let json_data = json!({"realm": "test"});
        let mut keys = HashMap::new();
        let result = get_private_keys(&json_data, &mut keys);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("org.keycloak.keys.KeyProvider"));

        // Components present but no KeyProvider
        let json_data = json!({"components": {}});
        let mut keys = HashMap::new();
        let result = get_private_keys(&json_data, &mut keys);
        assert!(result.is_err());
    }

    // --- set_private_keys tests ---

    #[test]
    fn set_private_keys_replaces_with_avp_paths() {
        let mut json_data = keycloak_realm_fixture();
        set_private_keys(&mut json_data, |id| format!("<path:replaced#{id}>")).unwrap();

        let providers = json_data["components"]["org.keycloak.keys.KeyProvider"]
            .as_array()
            .unwrap();

        assert_eq!(
            providers[0]["config"]["privateKey"][0],
            "<path:replaced#a0908969-93f0-40a2-b56d-f843450c579b>"
        );
        assert_eq!(
            providers[1]["config"]["privateKey"][0],
            "<path:replaced#b1234567-89ab-cdef-0123-456789abcdef>"
        );
    }

    #[test]
    fn set_private_keys_preserves_other_config_fields() {
        let mut json_data = keycloak_realm_fixture();
        set_private_keys(&mut json_data, |id| format!("<avp:{id}>")).unwrap();

        let providers = json_data["components"]["org.keycloak.keys.KeyProvider"]
            .as_array()
            .unwrap();

        // First provider: priority and keySize should be untouched
        assert_eq!(providers[0]["config"]["priority"][0], "100");
        assert_eq!(providers[0]["config"]["keySize"][0], "2048");
        assert_eq!(providers[0]["name"], "rsa-generated");

        // Second provider: priority and algorithm should be untouched
        assert_eq!(providers[1]["config"]["priority"][0], "200");
        assert_eq!(providers[1]["config"]["algorithm"][0], "RSA-OAEP");
        assert_eq!(providers[1]["name"], "rsa-enc-generated");

        // Realm-level fields should be untouched
        assert_eq!(json_data["realm"], "my-realm");
        assert_eq!(json_data["enabled"], true);
    }

    // --- roundtrip test ---

    #[test]
    fn roundtrip_extract_then_replace() {
        let mut json_data = keycloak_realm_fixture();

        // Step 1: Extract private keys
        let mut keys = HashMap::new();
        get_private_keys(&json_data, &mut keys).unwrap();
        assert_eq!(keys.len(), 2);

        // Step 2: Replace with AVP paths
        let avp = avp_path_generator("secret", "openshift/argocd", "cluster01");
        set_private_keys(&mut json_data, &avp).unwrap();

        // Step 3: Verify AVP paths are correct
        let providers = json_data["components"]["org.keycloak.keys.KeyProvider"]
            .as_array()
            .unwrap();
        assert_eq!(
            providers[0]["config"]["privateKey"][0],
            "<path:secret/data/openshift/argocd/cluster01#a0908969-93f0-40a2-b56d-f843450c579b>"
        );
        assert_eq!(
            providers[1]["config"]["privateKey"][0],
            "<path:secret/data/openshift/argocd/cluster01#b1234567-89ab-cdef-0123-456789abcdef>"
        );

        // Step 4: Verify extracted keys match original values
        assert_eq!(
            keys["a0908969-93f0-40a2-b56d-f843450c579b"],
            "MIIEowIBAAKCAQEA0Z3..."
        );
        assert_eq!(
            keys["b1234567-89ab-cdef-0123-456789abcdef"],
            "MIIEpAIBAAKCAQEA7dG..."
        );

        // Step 5: Other config fields are untouched
        assert_eq!(providers[0]["config"]["priority"][0], "100");
        assert_eq!(providers[1]["config"]["algorithm"][0], "RSA-OAEP");
    }

    // --- synchronize_keys tests ---

    #[test]
    fn synchronize_keys_filters_to_matching_keys() {
        let mut vault = json!({"key-a": "val-a", "key-b": "val-b", "key-c": "val-c"});
        let file = json!({"key-a": "new-a", "key-b": "new-b"});

        synchronize_keys(&mut vault, &file);

        assert_eq!(vault, json!({"key-a": "val-a", "key-b": "val-b"}));
        assert!(vault.get("key-c").is_none());
    }

    // --- vault update simulation ---

    #[test]
    fn vault_update_sync_compare_merge() {
        // Simulate: vault has keys A, B, C; file has A (changed) and B (unchanged)
        let file_keys = json!({"key-a": "new-value", "key-b": "same-value"});
        let mut vault_keys = json!({"key-a": "old-value", "key-b": "same-value", "key-c": "other"});

        // Step 1: Clone vault and synchronize to only file-relevant keys
        let mut vault_clone = vault_keys.clone();
        synchronize_keys(&mut vault_clone, &file_keys);
        assert_eq!(
            vault_clone,
            json!({"key-a": "old-value", "key-b": "same-value"})
        );

        // Step 2: Compare — should detect changes (key-a differs)
        assert!(!compare_private_keys(&file_keys, &vault_clone));

        // Step 3: Merge file keys into full vault (preserving key-c)
        merge_json(&mut vault_keys, file_keys);
        assert_eq!(
            vault_keys,
            json!({"key-a": "new-value", "key-b": "same-value", "key-c": "other"})
        );
    }
}
