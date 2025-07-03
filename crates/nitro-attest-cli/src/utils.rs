use alloy_primitives::Address;
use aws_nitro_enclave_attestation_prover::{
    contract::NitroEnclaveVerifier, new_prover, Prover, ProverConfig,
};
use clap::Args;

#[derive(Args, Clone)]
pub struct ProverArgs {
    /// Use the risc0 zkvm
    #[cfg(feature = "risc0")]
    #[arg(long)]
    pub risc0: bool,

    /// Use the sp1 zkvm
    #[cfg(feature = "sp1")]
    #[arg(long)]
    pub sp1: bool,

    #[arg(long, default_value = "false", env = "DEV_MODE")]
    pub dev: bool,

    #[arg(long, env = "NETWORK_PRIVATE_KEY")]
    pub sp1_private_key: Option<String>,

    #[arg(long, env = "NETWORK_RPC_URL")]
    pub sp1_rpc_url: Option<String>,

    #[arg(long, env = "BONSAI_API_URL", default_value = "https://api.bonsai.xyz")]
    pub risc0_api_url: Option<String>,
}

impl ProverArgs {
    pub fn new_prover(&self) -> anyhow::Result<Box<dyn Prover>> {
        let prover = new_prover(ProverConfig {
            #[cfg(feature = "sp1")]
            sp1: self.sp1,
            #[cfg(feature = "risc0")]
            risc0: self.risc0,
            sp1_private_key: self.sp1_private_key.clone(),
            sp1_rpc_url: self.sp1_rpc_url.clone(),
            risc0_api_url: self.risc0_api_url.clone(),
        })?;
        Ok(prover)
    }
}

#[derive(Args, Clone)]
pub struct ContractArgs {
    /// The address of the Nitro Enclave Verifier contract
    #[arg(long, env = "VERIFIER")]
    pub contract: Option<Address>,

    /// The RPC URL to connect to the Ethereum network
    #[arg(long, env = "RPC_URL", default_value = "http://localhost:8545")]
    pub rpc_url: Option<String>,
}

impl ContractArgs {
    pub fn empty(&self) -> bool {
        self.contract.is_none() || self.rpc_url.is_none()
    }

    pub fn stub(&self) -> anyhow::Result<Option<NitroEnclaveVerifier>> {
        if self.empty() {
            return Ok(None);
        }
        let contract = *self.contract.as_ref().unwrap();
        let rpc_url = self.rpc_url.as_ref().unwrap();
        let verifier = NitroEnclaveVerifier::dial(&rpc_url, contract, None)?;
        Ok(Some(verifier))
    }
}
