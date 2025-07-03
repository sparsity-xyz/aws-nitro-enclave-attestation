use aws_nitro_enclave_attestation_prover::set_prover_dev_mode;
use clap::{Parser, Subcommand};

mod prove;
use prove::*;
use tokio::runtime::Runtime;

mod debug;
use debug::DebugCli;

#[derive(Parser)]
#[command(name = "nitro-attest-cli")]
#[command(version = "0.1.0")]
struct NitroAttestCli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Prove(ProveCli),
    ProveProof(ProveMultiCli),
    Upload(ProverArgs),
    #[command(subcommand)]
    Debug(DebugCli),
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let cli = NitroAttestCli::parse();
    match &cli.command {
        Commands::Prove(cli) => cli.run().unwrap(),
        Commands::ProveProof(cli) => cli.run().unwrap(),
        Commands::Debug(cli) => cli.run().unwrap(),
        Commands::Upload(prover) => {
            set_prover_dev_mode(prover.dev);
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let prover = prover.new_prover().unwrap();
                let result = prover.upload_image().await.unwrap();
                dbg!(result);
            });
        }
    }
}
