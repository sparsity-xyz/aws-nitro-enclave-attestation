mod types;
pub mod utils;
use std::time::{SystemTime, UNIX_EPOCH};

use contract::NitroEnclaveVerifier;
pub use types::*;
pub mod contract;

use alloy_primitives::Bytes;
use aws_nitro_enclave_attestation_verifier::{
    stub::{VerifierInput, ZkCoProcessorType},
    AttestationReport,
};
use utils::{block_on, parallels_blocking};

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

pub fn set_prover_dev_mode(_dev_mode: bool) {
    #[cfg(feature = "sp1")]
    if _dev_mode {
        std::env::set_var("SP1_PROVER", "mock");
    } else {
        std::env::set_var("SP1_PROVER", "network");
    }

    #[cfg(feature = "risc0")]
    if _dev_mode {
        std::env::set_var("RISC0_PROVER", "");
        std::env::set_var("RISC0_DEV_MODE", "1");
        std::env::set_var("RISC0_INFO", "1");
    } else {
        std::env::set_var("RISC0_PROVER", "bonsai");
        std::env::set_var("RISC0_DEV_MODE", "0");
    }
}

pub fn new_prover(_cfg: ProverConfig) -> anyhow::Result<Box<dyn Prover>> {
    #[cfg(feature = "risc0")]
    if _cfg.risc0 {
        #[cfg(feature = "sp1")]
        if _cfg.sp1 {
            return Err(anyhow::anyhow!(
                "Error: cannot specify both risc0 and sp1 in the configuration."
            ));
        }
        return Ok(Box::new(risc0::Risc0Prover::new(_cfg)));
    }

    #[cfg(feature = "sp1")]
    if _cfg.sp1 {
        #[cfg(feature = "risc0")]
        if _cfg.risc0 {
            return Err(anyhow::anyhow!(
                "Error: cannot specify both risc0 and sp1 in the configuration."
            ));
        }
        return Ok(Box::new(sp1::SP1Prover::new(_cfg)));
    }

    Err(anyhow::anyhow!("Error: no prover specified."))
}

/// AWS Nitro Enclave attestation prover using zero-knowledge proofs
///
/// This trait provides the core functionality for generating ZKP
pub trait Prover: Send + Sync + 'static {
    /// Get zkVM version and implementation information
    fn get_zkvm_info(&self) -> String;

    /// Get the zero-knowledge coprocessor type (RISC0 or SP1)
    fn get_zk_type(&self) -> ZkCoProcessorType;

    /// Get program identifiers for verifier and aggregator circuits
    fn get_program_id(&self) -> ProgramId;

    /// Encode zkVM proof to blockchain-compatible format
    fn encode_proof_for_onchain(&self, proof: &Proof) -> anyhow::Result<Bytes>;

    /// Upload program images to proving service (Bonsai/SP1 Network)
    fn upload_program_images(&self) -> anyhow::Result<ProgramId>;

    /// Generate a complete proof for a single verifier input
    fn gen_single_proof(&self, input: &VerifierInput) -> anyhow::Result<Proof>;

    /// Generate a partial proof for later aggregation
    fn gen_partial_proof(&self, input: &VerifierInput) -> anyhow::Result<Proof>;

    fn gen_multi_partial_proof(&self, inputs: &[VerifierInput]) -> anyhow::Result<Vec<Proof>> {
        let max_concurrency = std::env::var("PROVE_MAX_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| 8);

        // Generate partial proofs in parallel
        Ok(parallels_blocking(max_concurrency, inputs, move |input| {
            self.gen_partial_proof(input)
        })?)
    }

    /// Aggregate multiple partial proofs into a single compact proof
    fn aggregate_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<Proof>;

    /// Prove a single attestation report
    fn prove_attestation_report(
        &self,
        report_bytes: Vec<u8>,
        contract: Option<&NitroEnclaveVerifier>,
    ) -> anyhow::Result<ProveResult> {
        let inputs = self.prepare_verifier_inputs(vec![report_bytes], contract)?;
        let proof = self.gen_single_proof(&inputs[0])?;
        Ok(self.create_proof_result(proof, ProofType::Verifier)?)
    }

    /// Prove multiple attestation reports with aggregation
    fn prove_multiple_reports(
        &self,
        raw_reports: Vec<Vec<u8>>,
        contract: Option<&NitroEnclaveVerifier>,
    ) -> anyhow::Result<ProveResult> {
        let inputs = self.prepare_verifier_inputs(raw_reports, contract)?;
        let proofs = self.gen_multi_partial_proof(&inputs)?;
        let result = self.aggregate_proofs(proofs)?;
        Ok(self.create_proof_result(result, ProofType::Aggregator)?)
    }

    /// Prepare verifier inputs from raw attestation reports
    ///
    /// This method parses attestation reports, validates certificate chains,
    /// and queries smart contract for trusted certificate information.
    fn prepare_verifier_inputs(
        &self,
        raw_reports: Vec<Vec<u8>>,
        contract: Option<&NitroEnclaveVerifier>,
    ) -> anyhow::Result<Vec<VerifierInput>> {
        let mut parsed_reports = Vec::with_capacity(raw_reports.len());
        let mut cert_digests = Vec::with_capacity(raw_reports.len());

        // Parse attestation reports and extract certificate chain digests
        for raw_report in &raw_reports {
            parsed_reports.push(AttestationReport::parse(&raw_report)?);
            let cert_chain = parsed_reports.last().unwrap().cert_chain()?;
            cert_digests.push(cert_chain.digest().to_vec());
        }

        let trusted_certs_lengths;
        match contract {
            Some(verifier_contract) => {
                // Query smart contract for certificate cache information
                trusted_certs_lengths =
                    block_on(verifier_contract.batch_query_cert_cache(cert_digests))?;
            }
            None => {
                tracing::warn!("Contract not provided, may lead to attestation failures and increased costs. Not recommended for production.");

                // Validate report timestamps when no contract is available
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                for report in &parsed_reports {
                    let report_timestamp = report.doc().timestamp / 1000;
                    if report_timestamp + 3600 < current_time {
                        tracing::warn!(
                            "Report signed {} seconds ago, may indicate verification failure.",
                            current_time - report_timestamp
                        );
                    }
                }
                // Trust root certificate by default
                trusted_certs_lengths = vec![1_u8; parsed_reports.len()];
            }
        }

        assert!(
            trusted_certs_lengths.len() == raw_reports.len(),
            "Trusted certificate lengths count mismatch"
        );

        // Build verifier inputs with trusted certificate information
        let verifier_inputs = raw_reports
            .into_iter()
            .zip(trusted_certs_lengths)
            .map(|(report_bytes, trusted_cert_len)| VerifierInput {
                trustedCertsLen: trusted_cert_len,
                attestationReport: report_bytes.into(),
            })
            .collect();
        Ok(verifier_inputs)
    }

    /// Build a complete proof result with all metadata
    fn create_proof_result(
        &self,
        proof: Proof,
        proof_type: ProofType,
    ) -> anyhow::Result<ProveResult> {
        Ok(ProveResult {
            zktype: self.get_zk_type(),
            zkvm: self.get_zkvm_info(),
            program_id: self.get_program_id(),
            onchain_proof: self.encode_proof_for_onchain(&proof)?,
            proof,
            proof_type,
        })
    }
}
