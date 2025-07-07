use std::path::PathBuf;

use anyhow::anyhow;
use aws_nitro_enclave_attestation_prover::{
    set_prover_dev_mode, utils::block_on, OnchainProof, ProofType,
};
use clap::{Args, Subcommand};

use crate::utils::{ContractArgs, ProverArgs};

#[derive(Subcommand)]
pub enum ProofCli {
    VerifyOnChain(ProofVerifyOnChainCli),
    GenComposite(ProofGenCompositeCli),
    Aggregate(ProofAggregateCli),
}

impl ProofCli {
    pub fn run(&self) -> anyhow::Result<()> {
        match self {
            ProofCli::VerifyOnChain(cli) => cli.run(),
            ProofCli::Aggregate(cli) => cli.run(),
            ProofCli::GenComposite(cli) => cli.run(),
        }
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
    pub fn run(&self) -> anyhow::Result<()> {
        let contract = self.contract.stub()?.ok_or_else(|| {
            anyhow!("No contract specified. Use --contract, --rpc-url to specify the contract.")
        })?;

        let result = OnchainProof::decode_json(&std::fs::read(&self.proof)?)?;
        if result.onchain_proof.len() == 0 {
            return Err(anyhow::anyhow!(
                "Proof does not contain an on-chain proof, unable to submit."
            ));
        }

        let result = block_on(contract.verify_proof(&result))?;
        dbg!(result);

        Ok(())
    }
}

#[derive(Args)]
pub struct ProofAggregateCli {
    /// The path to the Nitro Attestation Report files
    #[arg(long)]
    proof: Vec<PathBuf>,

    /// The path to store the output
    #[arg(long)]
    out: Option<PathBuf>,

    #[clap(flatten)]
    contract: ContractArgs,

    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProofAggregateCli {
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(self.prover.dev);
        if self.proof.is_empty() {
            return Err(anyhow!(
                "No report files provided. Use --reports to specify the report files."
            ));
        }

        let mut proofs = Vec::with_capacity(self.proof.len());
        for report in &self.proof {
            let proof = OnchainProof::decode_json(&std::fs::read(report)?)?;
            proofs.push(proof.raw_proof);
        }

        let contract = self.contract.stub()?;
        let prover = self.prover.new_prover(contract)?;
        let aggregated_proof = prover.aggregate_proofs(proofs)?;
        let aggregated_proof =
            prover.create_onchain_proof(aggregated_proof, ProofType::Aggregator)?;

        if let Some(out) = &self.out {
            std::fs::write(out, aggregated_proof.encode_json()?)?;
        }
        println!("proof: {:?}", aggregated_proof);

        Ok(())
    }
}

#[derive(Args)]
pub struct ProofGenCompositeCli {
    /// The path to the Nitro Attestation Report files
    #[arg(long)]
    report: PathBuf,

    /// The path to store the output
    #[arg(long)]
    out: Option<PathBuf>,

    #[clap(flatten)]
    contract: ContractArgs,

    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProofGenCompositeCli {
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(self.prover.dev);
        let raw_report = std::fs::read(&self.report)?;

        let contract = self.contract.stub()?;
        let prover = self.prover.new_prover(contract)?;
        let inputs = prover.prepare_verifier_inputs(vec![raw_report])?;
        let composite_proof = prover.gen_multi_composite_proofs(&inputs)?.remove(0);
        let composite_proof = prover.create_onchain_proof(composite_proof, ProofType::Verifier)?;

        if let Some(out) = &self.out {
            std::fs::write(out, composite_proof.encode_json()?)?;
        }
        println!("proof: {:?}", composite_proof);

        Ok(())
    }
}
