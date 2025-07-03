use alloy_primitives::{Bytes, B256};
use async_trait::async_trait;
use aws_nitro_enclave_attestation_verifier::{BatchVerifierInput, VerifierInput, VerifierJournal};
use bonsai_sdk::non_blocking::Client;
use risc0_ethereum_contracts::groth16;
use risc0_methods::{
    RISC0_AGGREGATOR_ELF, RISC0_AGGREGATOR_ID, RISC0_VERIFIER_ELF, RISC0_VERIFIER_ID,
};
use risc0_zkvm::{
    default_prover, Digest, ExecutorEnv, InnerReceipt, ProverOpts, VERSION,
};

use crate::{ProgramId, Proof, ProveResult, Prover, ProverConfig};

pub struct Risc0Prover {}

impl Risc0Prover {
    pub fn new(cfg: ProverConfig) -> Self {
        if let Some(api_url) = cfg.risc0_api_url {
            std::env::set_var("BONSAI_API_URL", api_url);
        }
        Risc0Prover {}
    }

    pub fn prove(&self, env: ExecutorEnv, elf: &[u8], opts: &ProverOpts) -> anyhow::Result<Proof> {
        let prover = default_prover();
        let prove_info = prover.prove_with_opts(env, elf, &opts)?;
        let journal: Bytes = prove_info.receipt.journal.bytes.clone().into();
        let claim = prove_info.receipt.inner;
        let proof = Proof::from_proof(&claim, journal)?;
        Ok(proof)
    }
}

#[async_trait]
impl Prover for Risc0Prover {
    fn zkvm_info(&self) -> String {
        format!("risc0/{}", VERSION)
    }

    fn decode_proof(&self, proof: &Proof) -> anyhow::Result<Bytes> {
        let receipt = proof.decode_proof::<InnerReceipt>()?;
        let proof = match receipt {
            InnerReceipt::Groth16(groth16_receipt) => groth16::encode(&groth16_receipt.seal)?,
            _ => vec![],
        };
        Ok(proof.into())
    }

    fn program_id(&self) -> ProgramId {
        let verifier_image_id = Digest::new(RISC0_VERIFIER_ID);
        let aggregator_image_id = Digest::new(RISC0_AGGREGATOR_ID);

        ProgramId {
            verifier_id: B256::from_slice(verifier_image_id.as_bytes()),
            verifier_proof_id: B256::from_slice(verifier_image_id.as_bytes()),
            aggregator_id: B256::from_slice(aggregator_image_id.as_bytes()),
        }
    }

    fn prove_aggregated_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<ProveResult> {
        let mut journals = Vec::with_capacity(proofs.len());
        for item in &proofs {
            let decoded = item.decode_journal::<VerifierJournal>()?;
            journals.push(decoded);
        }

        let batch_input = BatchVerifierInput {
            verifier_vk: B256::from_slice(Digest::new(RISC0_VERIFIER_ID).as_bytes()),
            outputs: journals,
        };

        let mut env = ExecutorEnv::builder();
        for item in &proofs {
            let assumption = item.decode_proof::<InnerReceipt>()?;
            env.add_assumption(assumption);
        }
        let env = env.write_slice(&batch_input.encode()).build()?;
        let opts = ProverOpts::groth16();

        let proof = self.prove(env, RISC0_AGGREGATOR_ELF, &opts)?;
        Ok(self.build_result(proof)?)
    }

    fn prove_single(&self, input: &VerifierInput) -> anyhow::Result<ProveResult> {
        let env = ExecutorEnv::builder()
            .write_slice(&input.encode())
            .build()?;
        let opts = ProverOpts::groth16();
        let proof = self.prove(env, RISC0_VERIFIER_ELF, &opts)?;
        Ok(self.build_result(proof)?)
    }

    async fn upload_image(&self) -> anyhow::Result<ProgramId> {
        let client = Client::from_env(VERSION)?;
        let verifier_image_id = Digest::new(RISC0_VERIFIER_ID);
        let aggregator_image_id = Digest::new(RISC0_AGGREGATOR_ID);
        client
            .upload_img(&verifier_image_id.to_string(), RISC0_VERIFIER_ELF.into())
            .await?;
        client
            .upload_img(
                &aggregator_image_id.to_string(),
                RISC0_AGGREGATOR_ELF.into(),
            )
            .await?;
        Ok(self.program_id())
    }

    fn prove_partial(&self, input: &VerifierInput) -> anyhow::Result<ProveResult> {
        let env = ExecutorEnv::builder()
            .write_slice(&input.encode())
            .build()?;
        let opts = ProverOpts::composite();
        let proof = self.prove(env, RISC0_VERIFIER_ELF, &opts)?;
        Ok(self.build_result(proof)?)
    }
}
