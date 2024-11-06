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

## Todo

* Add arg for output directory
* Add concurrency (yeye, overkill but I want to learn it)
* Authenticate with Vault AppRole
* Support other Secret Managers (on GCP, Azure, AWS etc.)
* Run the actual `kc.sh` [export](https://www.keycloak.org/server/importExport) script in a kubernetes pod and grab the realm data

## License
This project is licensed under the Beerware License. If you like it, feel free to buy me a beer if we ever meet!
