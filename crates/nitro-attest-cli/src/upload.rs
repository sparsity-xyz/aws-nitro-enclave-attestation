use aws_nitro_enclave_attestation_prover::set_prover_dev_mode;
use clap::Args;

use crate::utils::ProverArgs;

/// Command for uploading ZK programs for remote execution
#[derive(Args)]
pub struct UploadCli {
    #[clap(flatten)]
    prover: ProverArgs,
}

impl UploadCli {
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(false);
        let prover = self.prover.new_prover()?;
        let result = prover.upload_image()?;

        dbg!(result);
        Ok(())
    }
}
