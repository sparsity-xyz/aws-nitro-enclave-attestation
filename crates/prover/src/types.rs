use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{SolType, SolValue};
use anyhow::anyhow;
use aws_nitro_enclave_attestation_verifier::stub::ZkCoProcessorType;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProveResult {
    pub zktype: ZkCoProcessorType,
    pub zkvm: String,
    pub program_id: ProgramId,
    pub proof: Proof,
    pub onchain_proof: Bytes,
    pub proof_type: ProofType,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ProofType {
    Verifier,
    Aggregator,
}

impl ProveResult {
    pub fn new(
        zktype: ZkCoProcessorType,
        zkvm: String,
        program_id: ProgramId,
        proof: Proof,
        onchain_proof: Bytes,
        proof_type: ProofType,
    ) -> Self {
        Self {
            zktype,
            zkvm,
            program_id,
            proof,
            onchain_proof,
            proof_type,
        }
    }

    pub fn encode_json(&self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|e| anyhow!("Failed to serialize proof: {}", e))
    }

    pub fn decode_json(data: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(data).map_err(|e| anyhow!("Failed to deserialize proof: {}", e))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProgramId {
    pub verifier_id: B256,
    pub verifier_proof_id: B256,
    pub aggregator_id: B256,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Proof {
    pub encoded_proof: Bytes,
    pub journal: Bytes,
}

impl Proof {
    pub fn from_proof<P>(proof: P, journal: Bytes) -> anyhow::Result<Self>
    where
        P: Serialize,
    {
        let encoded_proof = bincode::serialize(&proof)?.into();
        Ok(Self {
            journal,
            encoded_proof,
        })
    }

    pub fn decode_proof<P>(&self) -> anyhow::Result<P>
    where
        P: Serialize + DeserializeOwned,
    {
        bincode::deserialize(&self.encoded_proof)
            .map_err(|err| anyhow!("Failed to deserialize proof: {}", err))
    }

    pub fn decode_journal<J>(&self) -> anyhow::Result<J>
    where
        J: SolValue + From<<<J as SolValue>::SolType as SolType>::RustType>,
    {
        J::abi_decode(&self.journal).map_err(|err| anyhow!("Failed to decode journal: {}", err))
    }
}
