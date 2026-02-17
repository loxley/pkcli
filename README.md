<img src="https://loxley.se/image_project.webp" alt="Alt Text" width="300" height="300">

# pkcli

![CI](https://github.com/loxley/pkcli/actions/workflows/ci.yml/badge.svg)

## What is pkcli?

A CLI tool written in Rust that secures private keys in exported [Keycloak](https://www.keycloak.org/) realm files for GitOps workflows with [ArgoCD](https://github.com/argoproj/argo-cd), [argocd-vault-plugin (AVP)](https://github.com/argoproj-labs/argocd-vault-plugin), and [HashiCorp Vault](https://github.com/hashicorp/vault).

* Replace `privateKey` values with [argocd-vault-plugin](https://github.com/argoproj-labs/argocd-vault-plugin) inline path references pointing to secrets in Vault
* Convert exported realm data to a `KeycloakRealmImport` CR (`k8s.keycloak.org/v2alpha1`) ready for cluster import
* Save extracted private keys to Vault with diff-based updates (only writes when changes are detected)

## Why?

Because I wanted an excuse to learn a bit of Rust and I had a usecase for it.

And I finally got an excuse to generate a fancy Github picture. :point_up:

## Installation

### Pre-built binaries

Download the latest binary from [GitHub Releases](https://github.com/loxley/pkcli/releases).

### Build from source

```bash
cargo build --release
```

The binary will be at `target/release/pkcli`.

## Usage

### Prerequisites

pkcli requires a Vault token for authentication. Provide it via environment variable or the `-t` flag:

```bash
export VAULT_TOKEN=<your-vault-token>
```

### Examples

```bash
# Full workflow: parse keycloak export, replace private keys with AVP paths, update Vault
./pkcli -f exported_keycloak_data.json -c <CLUSTER> -t <VAULT_TOKEN>

# Only replace privateKeys with argocd-vault-plugin paths (writes YAML, no Vault interaction)
./pkcli -f exported_keycloak_data.json -c <CLUSTER> -t <VAULT_TOKEN> update-avp

# Only update Vault with secrets (no YAML output)
./pkcli -f exported_keycloak_data.json -c <CLUSTER> -t <VAULT_TOKEN> update-vault

# Read from stdin and write YAML to stdout
cat exported_keycloak_data.json | ./pkcli -f- -c <CLUSTER> -k <KEYCLOAK-CR-NAME> -t <VAULT_TOKEN> > realm.yaml

# Process all JSON files in a directory
./pkcli -d exported_keycloak_data/ -c <CLUSTER> -t <VAULT_TOKEN>

# Write output YAML to a specific directory
./pkcli -f exported_keycloak_data.json -c <CLUSTER> -t <VAULT_TOKEN> -o /path/to/output/
```

### How it works

When run without a subcommand, pkcli performs the following steps:

1. Reads the Keycloak realm export JSON and extracts `privateKey` values from `components.org.keycloak.keys.KeyProvider` entries.
2. Replaces each private key with an AVP inline path reference: `<path:secret/data/openshift/argocd/<cluster>#<id>>`.
3. Wraps the modified realm data in a `KeycloakRealmImport` CRD and writes it as YAML.
4. Compares extracted keys with what is currently in Vault and only updates if changes are detected.

### CLI Reference

Run `pkcli --help` for all available options:

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--cluster` | `-c` | Cluster name used in Vault path | `cluster01` |
| `--filename` | `-f` | Input file (use `-` for stdin) | |
| `--directory` | `-d` | Process all JSON files in directory | |
| `--output-directory` | `-o` | Output directory for YAML files | `.` |
| `--vault-addr` | `-a` | Vault server address | `http://127.0.0.1:8200` |
| `--vault-token` | `-t` | Vault token (or `VAULT_TOKEN` env var) | |
| `--vault-mount` | `-m` | Vault mount path | `secret` |
| `--vault-path` | `-p` | Override the calculated Vault path | |
| `--keycloak-cr-name` | `-k` | Custom name for the Keycloak CR | |

## Roadmap

* Authenticate with Vault AppRole
* Support other Secret Managers (GCP, Azure, AWS)
* Run the `kc.sh` [export](https://www.keycloak.org/server/importExport) script in a Kubernetes pod and grab the realm data

## License

This project is licensed under the Beerware License. If you like it, feel free to buy me a beer if we ever meet!
