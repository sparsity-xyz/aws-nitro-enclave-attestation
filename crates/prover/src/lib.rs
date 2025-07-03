mod types;
use std::time::{SystemTime, UNIX_EPOCH};

use contract::NitroEnclaveVerifier;
pub use types::*;
pub mod contract;

use alloy_primitives::Bytes;
use async_trait::async_trait;
use aws_nitro_enclave_attestation_verifier::{
    stub::{VerifierInput, ZkCoProcessorType},
    AttestationReport,
};

#[cfg(feature = "sp1")]
pub mod sp1;

#[cfg(feature = "risc0")]
pub mod risc0;

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

#[async_trait(?Send)]
pub trait Prover {
    fn zkvm_info(&self) -> String;
    fn zk_type(&self) -> ZkCoProcessorType;
    fn program_id(&self) -> ProgramId;
    fn decode_proof(&self, proof: &Proof) -> anyhow::Result<Bytes>;
    async fn upload_image(&self) -> anyhow::Result<ProgramId>;
    fn prove_single(&self, input: &VerifierInput) -> anyhow::Result<ProveResult>;
    fn prove_partial(&self, input: &VerifierInput) -> anyhow::Result<ProveResult>;
    fn prove_aggregated_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<ProveResult>;

    async fn build_inputs(
        &self,
        raw_reports: Vec<Vec<u8>>,
        contract: Option<&NitroEnclaveVerifier>,
    ) -> anyhow::Result<Vec<VerifierInput>> {
        let mut reports = Vec::with_capacity(raw_reports.len());
        // let mut cert_chains = Vec::with_capacity(raw_reports.len());
        let mut cert_digests = Vec::with_capacity(raw_reports.len());
        for raw_report in &raw_reports {
            reports.push(AttestationReport::parse(&raw_report)?);
            let cert_chain = reports.last().unwrap().cert_chain()?;
            cert_digests.push(cert_chain.digest().to_vec());
        }

        let trusted_certs_len;
        match contract {
            Some(stub) => {
                trusted_certs_len = stub.batch_query_cert_cache(cert_digests).await?;
            }
            None => {
                tracing::warn!("Contract information is not provided, which may lead to attestation failures and increased costs. This setup is not recommended for production use.");
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                for report in &reports {
                    let timestamp = report.doc().timestamp / 1000;
                    if timestamp + 3600 < now {
                        tracing::warn!("The attestation report was signed {} seconds ago, which may indicate a verification failure.", now - timestamp);
                    }
                }
                // trusted the root certificate
                trusted_certs_len = vec![1_u8; reports.len()];
            }
        }
        assert!(
            trusted_certs_len.len() == raw_reports.len(),
            "Trusted certs length mismatch"
        );

        let inputs = raw_reports
            .into_iter()
            .zip(trusted_certs_len)
            .map(|(report, trusted_certs_len)| VerifierInput {
                trustedCertsLen: trusted_certs_len,
                attestationReport: report.into(),
            })
            .collect();
        Ok(inputs)
    }

    fn prove_multi(&self, input: &[VerifierInput]) -> anyhow::Result<ProveResult> {
        let mut results = Vec::new();
        for item in input {
            let result = self.prove_partial(item)?;
            results.push(result.proof);
        }
        Ok(self.prove_aggregated_proofs(results)?)
    }

    fn build_result(&self, proof: Proof, proof_type: ProofType) -> anyhow::Result<ProveResult> {
        Ok(ProveResult {
            zktype: self.zk_type(),
            zkvm: self.zkvm_info(),
            program_id: self.program_id(),
            onchain_proof: self.decode_proof(&proof)?,
            proof,
            proof_type,
        })
    }
}
