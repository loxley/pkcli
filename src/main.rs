use anyhow::Result;
use clap::Parser;
use pkcli::cli::Cli;
use pkcli::run;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await?;
    Ok(())
}
