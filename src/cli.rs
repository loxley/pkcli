use clap::builder::{NonEmptyStringValueParser, ValueParser};
use clap::{Arg, Command};
use std::path::PathBuf;

pub fn build_cli() -> Command {
    Command::new("pkcli")
        .version("1.0")
        .about("Parses Keycloak files, extracts private keys, and updates Vault")
        .author("loxley <loxley@loxley@users.noreply.github.com>")
        // Global arguments
        .arg(
            Arg::new("cluster")
                .short('c')
                .long("cluster")
                .value_name("CLUSTER")
                .help("Specifies the cluster")
                .value_parser(NonEmptyStringValueParser::new())
                .default_value("cluster01"),
        )
        .arg(
            Arg::new("filename")
                .short('f')
                .long("filename")
                .value_name("FILE")
                .help("Specifies the filename to be processed (use '-' to read from stdin)")
                .conflicts_with("directory")
                .value_parser(ValueParser::from(parse_file_path)),
        )
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .value_name("DIR")
                .help("Specifies the directory to be processed")
                .conflicts_with("filename")
                .value_parser(ValueParser::from(parse_directory_path)),
        )
        .arg(
            Arg::new("vault_addr")
                .short('a')
                .long("vault-addr")
                .value_name("VAULT_ADDR")
                .help("Specifies the Vault server address")
                .value_parser(NonEmptyStringValueParser::new())
                .env("VAULT_ADDR")
                .default_value("http://127.0.0.1:8200"),
        )
        .arg(
            Arg::new("vault_token")
                .short('t')
                .long("vault-token")
                .value_name("VAULT_TOKEN")
                .help("Specifies the Vault token for authentication")
                .value_parser(NonEmptyStringValueParser::new())
                .env("VAULT_TOKEN")
                .hide_env(true)
                .required(true),
        )
        .arg(
            Arg::new("vault_mount")
                .short('m')
                .long("vault-mount")
                .value_name("VAULT_MOUNT")
                .help("Specifies the Vault mount path")
                .value_parser(NonEmptyStringValueParser::new())
                .default_value("secret"),
        )
        .arg(
            // This can override the calculated path which is 'openshift/argocd/<cluster>'
            Arg::new("vault_path")
                .short('p')
                .long("vault-path")
                .value_name("VAULT_PATH")
                .help("Specifies the Vault secret path (to override calculated path)")
                .value_parser(NonEmptyStringValueParser::new()),
        )
        // Subcommands
        .subcommand(
            Command::new("update-avp").about("Updates private keys with argocd-vault-plugin path"),
        )
        .subcommand(
            Command::new("update-vault").about("Updates Vault with private keys from the file"),
        )
}

/// Validate file path
fn parse_file_path(s: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(s);
    if path.is_file() || path.as_os_str() == "-" {
        Ok(path)
    } else {
        Err(format!("'{}' is not a valid file path", s))
    }
}

/// Validate directory path
fn parse_directory_path(s: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(s);
    if path.is_dir() {
        Ok(path)
    } else {
        Err(format!("'{}' is not a valid directory path", s))
    }
}
