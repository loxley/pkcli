use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Get package name and version from environment variables set by Cargo
    let package_name = env::var("CARGO_PKG_NAME").unwrap();
    let version = env::var("CARGO_PKG_VERSION").unwrap();

    // Determine the target triple (e.g., x86_64-unknown-linux-gnu)
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    // Extract specific parts of the target triple
    let os = if target.contains("linux") {
        "linux"
    } else if target.contains("windows") {
        "windows"
    } else if target.contains("darwin") {
        "macos"
    } else {
        "unknown_os"
    };

    let arch = if target.starts_with("x86_64") {
        "amd64"
    } else if target.starts_with("aarch64") {
        "arm64"
    } else if target.starts_with("i686") {
        "x86"
    } else {
        "unknown_arch"
    };

    // Create the release name
    let release_name = format!("{}_{}_{}_{}", package_name, version, os, arch);

    // Save the release name to an output file (optional)
    let out_dir = env::var("OUT_DIR").unwrap();
    let release_name_path = Path::new(&out_dir).join("release_name.txt");
    fs::write(&release_name_path, &release_name).expect("Unable to write release name");

    // Print instructions for Cargo
    println!("cargo:rustc-env=RELEASE_NAME={}", release_name);
    println!("cargo:rerun-if-changed=build.rs");
}
