use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    version,
    long_version = env!("RELEASE_NAME"),
    about = "Parses Keycloak files, extracts private keys, and updates Vault",
    author = "loxley <loxley@users.noreply.github.com>"
)]
pub struct Cli {
    /// Specifies the cluster
    #[arg(short, long, default_value = "cluster01")]
    pub cluster: String,

    /// Specifies the filename to be processed (use '-' to read from stdin)
    #[arg(short, long, conflicts_with = "directory", value_parser = parse_file_path)]
    pub filename: Option<PathBuf>,

    /// Specifies the directory to be processed
    #[arg(short, long, conflicts_with = "filename", value_parser = parse_directory_path)]
    pub directory: Option<PathBuf>,

    /// Specifies the output directory (defaults to current directory)
    #[arg(short, long, value_parser = parse_directory_path)]
    pub output_directory: Option<PathBuf>,

    /// Specifies the Vault server address
    #[arg(
        short = 'a',
        long,
        env = "VAULT_ADDR",
        default_value = "http://127.0.0.1:8200"
    )]
    pub vault_addr: String,

    /// Specifies the Vault token for authentication
    #[arg(short = 't', long, env = "VAULT_TOKEN", hide_env = true)]
    pub vault_token: String,

    /// Specifies the Vault mount path
    #[arg(short = 'm', long, default_value = "secret")]
    pub vault_mount: String,

    /// Specifies the Vault secret path (to override calculated path)
    #[arg(short = 'p', long)]
    pub vault_path: Option<String>,

    /// Specifies the Keycloak CR name (use with 'f' option)
    #[arg(short = 'k', long, conflicts_with = "directory", requires = "filename")]
    pub keycloak_cr_name: Option<String>,

    #[command(subcommand)]
    pub command: Option<SubCmd>,
}

#[derive(Debug, Subcommand)]
pub enum SubCmd {
    /// Updates private keys with argocd-vault-plugin path
    UpdateAvp,
    /// Updates Vault with private keys from the file
    UpdateVault,
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
