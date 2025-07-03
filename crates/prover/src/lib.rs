mod types;
pub use types::*;
pub mod contract;

use alloy_primitives::Bytes;
use async_trait::async_trait;
use aws_nitro_enclave_attestation_verifier::VerifierInput;

#[cfg(feature = "sp1")]
pub mod sp1;

#[cfg(feature = "risc0")]
pub mod risc0;

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum ZkType {
    RiscZero = 1,
    Succinct = 2,
}

#[derive(Debug, Default)]
pub struct ProverConfig {
    #[cfg(feature = "risc0")]
    pub risc0: bool,
    #[cfg(feature = "sp1")]
    pub sp1: bool,
    pub sp1_private_key: Option<String>,
    pub sp1_rpc_url: Option<String>,
    pub risc0_api_url: Option<String>,
}

pub fn set_prover_dev_mode(dev_mode: bool) {
    #[cfg(feature = "sp1")]
    if dev_mode {
        std::env::set_var("SP1_PROVER", "mock");
    } else {
        std::env::set_var("SP1_PROVER", "network");
    }

    #[cfg(feature = "risc0")]
    if dev_mode {
        std::env::set_var("RISC0_PROVER", "");
        std::env::set_var("RISC0_DEV_MODE", "1");
        std::env::set_var("RISC0_INFO", "1");
    } else {
        std::env::set_var("RISC0_PROVER", "bonsai");
        std::env::set_var("RISC0_DEV_MODE", "0");
    }
}

pub fn new_prover_by_name(zkvm_info: &str, cfg: ProverConfig) -> anyhow::Result<Box<dyn Prover>> {
    #[cfg(feature = "risc0")]
    if zkvm_info.starts_with("risc0/") {
        return Ok(Box::new(risc0::Risc0Prover::new(cfg)));
    }

    #[cfg(feature = "sp1")]
    if zkvm_info.starts_with("sp1/") {
        return Ok(Box::new(sp1::SP1Prover::new(cfg)));
    }

    Err(anyhow::anyhow!("unknown prover: {}", zkvm_info))
}

pub fn new_prover(cfg: ProverConfig) -> anyhow::Result<Box<dyn Prover>> {
    #[cfg(feature = "risc0")]
    if cfg.risc0 {
        #[cfg(feature = "sp1")]
        if cfg.sp1 {
            return Err(anyhow::anyhow!(
                "Error: cannot specify both risc0 and sp1 in the configuration."
            ));
        }
        return Ok(Box::new(risc0::Risc0Prover::new(cfg)));
    }

    #[cfg(feature = "sp1")]
    if cfg.sp1 {
        #[cfg(feature = "risc0")]
        if cfg.risc0 {
            return Err(anyhow::anyhow!(
                "Error: cannot specify both risc0 and sp1 in the configuration."
            ));
        }
        return Ok(Box::new(sp1::SP1Prover::new(cfg)));
    }

    Err(anyhow::anyhow!("Error: no prover specified."))
}

#[async_trait]
pub trait Prover {
    fn zkvm_info(&self) -> String;
    fn program_id(&self) -> ProgramId;
    fn decode_proof(&self, proof: &Proof) -> anyhow::Result<Bytes>;
    async fn upload_image(&self) -> anyhow::Result<ProgramId>;
    fn prove_single(&self, input: &VerifierInput) -> anyhow::Result<ProveResult>;
    fn prove_partial(&self, input: &VerifierInput) -> anyhow::Result<ProveResult>;
    fn prove_aggregated_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<ProveResult>;

    fn prove_multi(&self, input: &[VerifierInput]) -> anyhow::Result<ProveResult> {
        let mut results = Vec::new();
        for item in input {
            let result = self.prove_single(item)?;
            results.push(result.proof);
        }
        Ok(self.prove_aggregated_proofs(results)?)
    }

    fn build_result(&self, proof: Proof) -> anyhow::Result<ProveResult> {
        Ok(ProveResult {
            zkvm: self.zkvm_info(),
            program_id: self.program_id(),
            onchain_proof: self.decode_proof(&proof)?,
            proof,
        })
    }
}
