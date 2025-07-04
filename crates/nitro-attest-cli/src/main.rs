use clap::{Parser, Subcommand};
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

mod debug;
mod proof;
mod prove;
mod upload;
mod utils;

#[derive(Parser)]
#[command(name = "nitro-attest-cli")]
#[command(version)]
struct NitroAttestCli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Prove(prove::ProveCli),
    #[command(subcommand)]
    Proof(proof::ProofCli),
    Upload(upload::UploadCli),
    #[command(subcommand)]
    Debug(debug::DebugCli),
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let cli = NitroAttestCli::parse();
    match &cli.command {
        Commands::Prove(cli) => cli.run(),
        Commands::Debug(cli) => cli.run(),
        Commands::Upload(cli) => cli.run(),
        Commands::Proof(cli) => cli.run(),
    }
    .unwrap()
}
