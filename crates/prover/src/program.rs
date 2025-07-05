use alloy_primitives::{Bytes, B256};
use alloy_sol_types::SolValue;
use aws_nitro_enclave_attestation_verifier::stub::ZkCoProcessorType;

use crate::{RawProof, RawProofType};

#[derive(Clone)]
pub struct RemoteProverConfig {
    pub api_url: String,
    pub api_key: String,
}

pub trait Program: Send + Sync {
    type Input: SolValue;
    type Output: SolValue;
    fn version(&self) -> &'static str;
    fn zktype(&self) -> ZkCoProcessorType;
    fn onchain_proof(&self, proof: &RawProof) -> anyhow::Result<Bytes>;
    fn upload_image(&self, cfg: &RemoteProverConfig) -> anyhow::Result<()>;
    fn program_id(&self) -> B256;
    fn verify_proof_id(&self) -> B256;
    fn gen_proof(
        &self,
        input: &Self::Input,
        raw_proof_type: RawProofType,
        encoded_proofs: Option<&[&Bytes]>,
    ) -> anyhow::Result<RawProof>;
}
