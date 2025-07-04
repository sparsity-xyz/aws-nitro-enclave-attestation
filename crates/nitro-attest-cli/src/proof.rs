use std::path::PathBuf;

use anyhow::anyhow;
use aws_nitro_enclave_attestation_prover::{utils::block_on, ProveResult};
use clap::{Args, Subcommand};

use crate::utils::ContractArgs;

#[derive(Subcommand)]
pub enum ProofCli {
    VerifyOnChain(ProofVerifyOnChainCli),
}

impl ProofCli {
    pub fn run(&self) -> anyhow::Result<()> {
        block_on(async {
            match self {
                ProofCli::VerifyOnChain(cli) => cli.run().await,
            }
        })
    }
}

#[derive(Args)]
pub struct ProofVerifyOnChainCli {
    #[clap(long)]
    proof: PathBuf,

    #[clap(flatten)]
    contract: ContractArgs,
}

impl ProofVerifyOnChainCli {
    pub async fn run(&self) -> anyhow::Result<()> {
        let contract = self.contract.stub()?.ok_or_else(|| {
            anyhow!("No contract specified. Use --contract, --rpc-url to specify the contract.")
        })?;

        let result = ProveResult::decode_json(&std::fs::read(&self.proof)?)?;
        if result.onchain_proof.len() == 0 {
            return Err(anyhow::anyhow!(
                "Proof does not contain an on-chain proof, unable to submit."
            ));
        }

        let result = contract.verify_proof(&result).await?;
        dbg!(result);

        Ok(())
    }
}
