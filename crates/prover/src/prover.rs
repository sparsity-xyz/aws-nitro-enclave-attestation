use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    program::{Program, RemoteProverConfig},
    utils::{block_on, parallels_blocking},
    NitroEnclaveVerifierContract, OnchainProof, ProgramId, ProofType, RawProof, RawProofType,
};
use alloy_primitives::Bytes;
use anyhow::anyhow;
use aws_nitro_enclave_attestation_verifier::{
    stub::{
        BatchVerifierInput, BatchVerifierJournal, VerifierInput, VerifierJournal, ZkCoProcessorType,
    },
    AttestationReport,
};

#[derive(Debug, Clone)]
pub enum ProverConfig {
    #[cfg(feature = "sp1")]
    Succinct(crate::program_sp1::SP1ProverConfig),
    #[cfg(feature = "risc0")]
    RiscZero(crate::program_risc0::RiscZeroProverConfig),
}

/// AWS Nitro Enclave attestation prover using zero-knowledge proofs
///
/// This trait provides the core functionality for generating ZKP
///
/// # Examples
///
/// ## Basic Single Attestation Proof
///
/// ```rust,no_run
/// use aws_nitro_enclave_attestation_prover::{
///     NitroEnclaveProver, set_prover_dev_mode, ProverConfig
/// };
///
/// fn main() -> anyhow::Result<()> {
///     // turn on simulation
///     set_prover_dev_mode(true);
///     
///     // Configure the prover (RISC0 example)
///     let config = ProverConfig::RiscZero(Default::default());
///     
///     // Create prover instance
///     let prover = NitroEnclaveProver::new(config, None);
///     
///     // Load attestation report
///     let report_bytes = std::fs::read("samples/attestation_1.report")?;
///     
///     // Generate proof
///     let result = prover.prove_attestation_report(report_bytes)?;
///     
///     // Save proof result
///     std::fs::write("proof.json", result.encode_json()?)?;
///     
///     println!("Proof generated successfully!");
///     println!("{}", String::from_utf8_lossy(&result.encode_json()?));
///     
///     Ok(())
/// }
/// ```
///
/// ## Batch Proving with Aggregation
///
/// ```rust,no_run
/// use aws_nitro_enclave_attestation_prover::{
///     NitroEnclaveProver, set_prover_dev_mode, ProverConfig
/// };
///
/// fn prove_multiple_reports() -> anyhow::Result<()> {
///     set_prover_dev_mode(false);
///     
///     let config = ProverConfig::Succinct(Default::default());
///     let prover = NitroEnclaveProver::new(config, None);
///     
///     // Load multiple attestation reports
///     let reports = vec![
///         std::fs::read("samples/attestation_1.report")?,
///         std::fs::read("samples/attestation_2.report")?,
///     ];
///     
///     // Generate aggregated proof for all reports
///     let reports_count = reports.len();
///     let result = prover.prove_multiple_reports(reports)?;
///     
///     println!("Aggregated proof generated for {} reports", reports_count);
///     println!("{}", String::from_utf8_lossy(&result.encode_json()?));
///     
///     Ok(())
/// }
/// ```
///
/// ## Smart Contract Integration
///
/// For optimal gas efficiency, integrate with the Nitro Enclave Verifier contract:
///
/// ```rust,no_run
/// use aws_nitro_enclave_attestation_prover::{
///     NitroEnclaveProver, ProverConfig,
///     NitroEnclaveVerifierContract
/// };
/// use alloy_primitives::Address;
///
/// async fn prove_with_contract() -> anyhow::Result<()> {
///     // Connect to deployed verifier contract
///     let contract_address: Address = "0x1234567890123456789012345678901234567890".parse()?;
///     let rpc_url = "https://1rpc.io/holesky";
///     let verifier = NitroEnclaveVerifierContract::dial(rpc_url, contract_address, None)?;
/// 
///     let config = ProverConfig::RiscZero(Default::default());
///     let prover = NitroEnclaveProver::new(config, Some(verifier));
///     
///     let report_bytes = std::fs::read("samples/attestation_2.report")?;
///     
///     // Prove with contract optimization
///     let result = prover.prove_attestation_report(report_bytes)?;
///     
///     // The result.onchain_proof is ready for contract submission
///     std::fs::write("proof.json", result.encode_json()?)?;
///     
///     println!("Aggregation Proof generated successfully!");
///     println!("{}", String::from_utf8_lossy(&result.encode_json()?));
///     
///     Ok(())
/// }
/// ```
///
pub struct NitroEnclaveProver {
    contract: Option<NitroEnclaveVerifierContract>,
    remote_prover_config: Result<RemoteProverConfig, String>,
    pub verifier: Box<dyn Program<Input = VerifierInput, Output = VerifierJournal>>,
    pub aggregator: Box<dyn Program<Input = BatchVerifierInput, Output = BatchVerifierJournal>>,
}

impl NitroEnclaveProver {
    pub fn new(cfg: ProverConfig, contract: Option<NitroEnclaveVerifierContract>) -> Self {
        match cfg {
            #[cfg(feature = "sp1")]
            ProverConfig::Succinct(cfg) => {
                use crate::program_sp1::{SP1_PROGRAM_AGGREGATOR, SP1_PROGRAM_VERIFIER};
                if let Some(api_url) = &cfg.rpc_url {
                    std::env::set_var("NETWORK_RPC_URL", api_url);
                }
                if let Some(api_key) = &cfg.private_key {
                    std::env::set_var("NETWORK_API_KEY", api_key);
                }
                NitroEnclaveProver {
                    contract,
                    remote_prover_config: cfg.try_into().map_err(|err| format!("{:?}", err)),
                    verifier: Box::new(SP1_PROGRAM_VERIFIER.clone()),
                    aggregator: Box::new(SP1_PROGRAM_AGGREGATOR.clone()),
                }
            }
            #[cfg(feature = "risc0")]
            ProverConfig::RiscZero(cfg) => {
                use crate::program_risc0::{RISC0_PROGRAM_AGGREGATOR, RISC0_PROGRAM_VERIFIER};
                if let Some(api_url) = &cfg.api_url {
                    std::env::set_var("BONSAI_API_URL", api_url);
                }
                if let Some(api_key) = &cfg.api_key {
                    std::env::set_var("BONSAI_API_KEY", api_key);
                }
                NitroEnclaveProver {
                    contract,
                    remote_prover_config: cfg.try_into().map_err(|err| format!("{:?}", err)),
                    verifier: Box::new(RISC0_PROGRAM_VERIFIER.clone()),
                    aggregator: Box::new(RISC0_PROGRAM_AGGREGATOR.clone()),
                }
            }
        }
    }

    /// Get the zero-knowledge coprocessor type (RISC0 or SP1)
    pub fn get_zk_type(&self) -> ZkCoProcessorType {
        self.verifier.zktype()
    }

    /// Get program identifiers for verifier and aggregator circuits
    pub fn get_program_id(&self) -> ProgramId {
        ProgramId {
            verifier_id: self.verifier.program_id(),
            verifier_proof_id: self.verifier.verify_proof_id(),
            aggregator_id: self.aggregator.program_id(),
        }
    }

    /// Encode zkVM proof to blockchain-compatible format
    pub fn encode_proof_for_onchain(&self, proof: &RawProof) -> anyhow::Result<Bytes> {
        self.verifier.onchain_proof(proof)
    }

    /// Upload program images to proving service
    pub fn upload_program_images(&self) -> anyhow::Result<ProgramId> {
        let cfg = match &self.remote_prover_config {
            Ok(cfg) => cfg,
            Err(err) => return Err(anyhow!("{}", err)),
        };
        self.verifier.upload_image(&cfg)?;
        self.aggregator.upload_image(&cfg)?;
        Ok(self.get_program_id())
    }

    pub fn gen_multi_composite_proofs(
        &self,
        inputs: &[VerifierInput],
    ) -> anyhow::Result<Vec<RawProof>> {
        let max_concurrency = std::env::var("PROVE_MAX_CONCURRENCY")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| 8);

        // Generate partial proofs in parallel
        Ok(parallels_blocking(max_concurrency, inputs, |input| {
            self.verifier
                .gen_proof(input, RawProofType::Composite, None)
        })?)
    }

    /// Aggregate multiple partial proofs into a single compact proof
    pub fn aggregate_proofs(&self, proofs: Vec<RawProof>) -> anyhow::Result<RawProof> {
        let mut journals = Vec::with_capacity(proofs.len());
        let mut encoded_proofs = Vec::with_capacity(proofs.len());
        for item in &proofs {
            let decoded = item.decode_journal::<VerifierJournal>()?;
            journals.push(decoded);
            encoded_proofs.push(&item.encoded_proof);
        }

        let batch_input = BatchVerifierInput {
            verifierVk: self.verifier.verify_proof_id(),
            outputs: journals,
        };
        Ok(self.aggregator.gen_proof(
            &batch_input,
            RawProofType::Groth16,
            Some(encoded_proofs.as_slice()),
        )?)
    }

    /// Prove a single attestation report
    pub fn prove_attestation_report(&self, report_bytes: Vec<u8>) -> anyhow::Result<OnchainProof> {
        let inputs = self.prepare_verifier_inputs(vec![report_bytes])?;
        let proof = self
            .verifier
            .gen_proof(&inputs[0], RawProofType::Groth16, None)?;
        Ok(self.create_onchain_proof(proof, ProofType::Verifier)?)
    }

    /// Prove multiple attestation reports with aggregation
    pub fn prove_multiple_reports(
        &self,
        raw_reports: Vec<Vec<u8>>,
    ) -> anyhow::Result<OnchainProof> {
        let inputs = self.prepare_verifier_inputs(raw_reports)?;
        let proofs = self.gen_multi_composite_proofs(&inputs)?;
        let result = self.aggregate_proofs(proofs)?;
        Ok(self.create_onchain_proof(result, ProofType::Aggregator)?)
    }

    /// Prepare verifier inputs from raw attestation reports
    ///
    /// This method parses attestation reports, validates certificate chains,
    /// and queries smart contract for trusted certificate information.
    pub fn prepare_verifier_inputs(
        &self,
        raw_reports: Vec<Vec<u8>>,
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
        match &self.contract {
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
    pub fn create_onchain_proof(
        &self,
        raw_proof: RawProof,
        proof_type: ProofType,
    ) -> anyhow::Result<OnchainProof> {
        Ok(OnchainProof::new_from_program(
            &*self.verifier,
            self.get_program_id(),
            raw_proof,
            proof_type,
        )?)
    }
}
