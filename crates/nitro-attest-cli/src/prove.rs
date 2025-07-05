use std::path::PathBuf;

use anyhow::anyhow;
use aws_nitro_enclave_attestation_prover::set_prover_dev_mode;
use clap::Args;

use crate::utils::{ContractArgs, ProverArgs};

/// Arguments of the prover CLI.
#[derive(Args)]
pub struct ProveCli {
    /// The path to the Nitro Attestation Report file
    #[arg(long)]
    report: Vec<PathBuf>,

    /// The path to store the output
    #[arg(long)]
    out: Option<PathBuf>,

    #[clap(flatten)]
    prover: ProverArgs,

    #[clap(flatten)]
    contract: ContractArgs,

    /// Submit the proof on-chain
    #[arg(long)]
    submit_onchain: bool,
}

impl ProveCli {
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(self.prover.dev);
        if self.report.len() == 0 {
            return Err(anyhow!(
                "No report files provided. Use --report to specify the report files."
            ));
        }

        let mut raw_reports = Vec::with_capacity(self.report.len());
        for report in &self.report {
            raw_reports.push(std::fs::read(report)?);
        }

        let contract = self.contract.stub()?;
        let prover = self.prover.new_prover(contract)?;
        let result = if raw_reports.len() == 1 {
            prover.prove_attestation_report(raw_reports.remove(0))?
        } else {
            prover.prove_multiple_reports(raw_reports)?
        };

        if let Some(out) = &self.out {
            std::fs::write(out, result.encode_json()?)?;
        } else {
            println!("proof: {:?}", result);
        }

        Ok(())
    }
}
