mod cli;
use anyhow::Result;
use pkcli::run;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    run(matches).await?;
    Ok(())
}
