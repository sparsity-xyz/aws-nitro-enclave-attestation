use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use x509_verifier_rust_crypto::sha256;

alloy_sol_types::sol! {
    #[sol(docs, extra_derives(Debug, Serialize, Deserialize))]
    "../../contracts/src/interfaces/INitroEnclaveVerifier.sol"
}

impl VerifierInput {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        Ok(VerifierInput::abi_decode(buf)
            .map_err(|err| anyhow!("Failed to decode VerifierInput: {}", err))?)
    }
}

impl VerifierJournal {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn digest(&self) -> B256 {
        sha256(&self.encode())
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        Ok(Self::abi_decode(buf)
            .map_err(|err| anyhow!("Failed to decode VerifierJournal: {}", err))?)
    }
}

impl BatchVerifierInput {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        Ok(Self::abi_decode(buf)
            .map_err(|err| anyhow!("Failed to decode BatchVerifierInput: {}", err))?)
    }
}

impl BatchVerifierJournal {
    pub fn encode(&self) -> Vec<u8> {
        self.abi_encode()
    }

    pub fn decode(buf: &[u8]) -> anyhow::Result<Self> {
        Ok(Self::abi_decode(buf)
            .map_err(|err| anyhow!("Failed to decode BatchVerifierJournal: {}", err))?)
    }
}
