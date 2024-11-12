<img src="https://loxley.se/image_project.webp" alt="Alt Text" width="300" height="300">

# pkcli

## What is pkcli?

It is a tool written in Rust that can help out securing private keys in exported [Keycloak](https://www.keycloak.org/) realms if you are using [ArgoCD](https://github.com/argoproj/argo-cd)
, [AVP](https://github.com/argoproj-labs/argocd-vault-plugin) and [Vault](https://github.com/hashicorp/vault).
* replace `privateKeys` with [argocd-vault-plugin](https://github.com/argoproj-labs/argocd-vault-plugin) inline paths (so its matching paths in Vault)
* convert exported data to a `KeyCloakRealmImport` CR ready for import 
* save the extracted privateKeys to Vault for [AVP](https://github.com/argoproj-labs/argocd-vault-plugin) to use (only this supported for the time being)

## Why?

Because I wanted an excuse to learn a bit of Rust and I had a usecase for it.

And I finally got an excuse to generate a fancy Github picture. :point_up:

## Usage

The following steps are performed if not adding `update-avp` or `update-vault`.

1. Read Keycloak export and parse privateKeys with ArgoCD Vault Plugin paths pointing to a secret in Vault.
The parsed AVP path would look something like this: `<path:secret/data/some/path/cluster#id>`.
2. Write the file as a `KeyCloakRealmImport` Custom Resource in YAML using same name as the export name for easy cluster import.
3. Create/Append/Update secrets as needed in Vault. Vault API path: `/v1/secret/data/some/path/cluster` and the vault field(key) name would be `id`.

Id is the relevant Keycloak config id under `components.org.keycloak.keys.KeyProvider` array.

Examples:

```bash
# Read keycloak data exported with `kc.sh`, parse and write AVP paths and update Vault (the default)
./pkcli -f exported_keycloak_data.json -c <CLUSTER>

# Read exported keycloak data, update `privateKeys` with argocd-vault-plugin paths
./pkcli -f exported_keycloak_data.json -c <CLUSTER> update-avp

# Read exported keycloak data, update Vault with secrets without writing yaml
./pkcli -f exported_keycloak_data.json -c <CLUSTER> update-vault

# Read from stdin and redirect stdout to a file
cat exported_keycloak_data.json | ./pkcli -f- -c <CLUSTER> -k <KEYCLOAK-CR-NAME> > realm.yaml

# Read keycloak data exports from a directory
./pkcli -d exported_keycloak_data -c <CLUSTER>
```

## Todo

* Add arg for output directory
* Add concurrency (yeye, overkill but I want to learn it)
* Authenticate with Vault AppRole
* Support other Secret Managers (on GCP, Azure, AWS etc.)
* Run the actual `kc.sh` [export](https://www.keycloak.org/server/importExport) script in a kubernetes pod and grab the realm data

## License
This project is licensed under the Beerware License. If you like it, feel free to buy me a beer if we ever meet!
