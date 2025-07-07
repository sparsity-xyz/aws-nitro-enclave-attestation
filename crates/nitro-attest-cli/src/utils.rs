use alloy_primitives::Address;
use anyhow::anyhow;
use aws_nitro_enclave_attestation_prover::{
    NitroEnclaveProver, NitroEnclaveVerifierContract, ProverConfig,
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

    #[arg(long, env = "BONSAI_API_KEY")]
    pub risc0_api_key: Option<String>,
}

impl ProverArgs {
    pub fn prover_config(&self) -> anyhow::Result<ProverConfig> {
        #[cfg(all(feature = "sp1", feature = "risc0"))]
        if self.sp1 && self.risc0 {
            return Err(anyhow!(
                "Cannot use both --sp1 and --risc0 at the same time."
            ));
        }

        #[cfg(feature = "sp1")]
        if self.sp1 {
            use aws_nitro_enclave_attestation_prover::SP1ProverConfig;
            return Ok(ProverConfig::sp1_with(SP1ProverConfig {
                private_key: self.sp1_private_key.clone(),
                rpc_url: self.sp1_rpc_url.clone(),
            }));
        }

        #[cfg(feature = "risc0")]
        if self.risc0 {
            use aws_nitro_enclave_attestation_prover::RiscZeroProverConfig;
            return Ok(ProverConfig::risc0_with(RiscZeroProverConfig {
                api_url: self.risc0_api_url.clone(),
                api_key: self.risc0_api_key.clone(),
            }));
        }

        return Err(anyhow!("No prover specified. "));
    }

    pub fn new_prover(
        &self,
        contract: Option<NitroEnclaveVerifierContract>,
    ) -> anyhow::Result<NitroEnclaveProver> {
        Ok(NitroEnclaveProver::new(self.prover_config()?, contract))
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

    pub fn stub(&self) -> anyhow::Result<Option<NitroEnclaveVerifierContract>> {
        if self.empty() {
            return Ok(None);
        }
        let contract = *self.contract.as_ref().unwrap();
        let rpc_url = self.rpc_url.as_ref().unwrap();
        let verifier = NitroEnclaveVerifierContract::dial(&rpc_url, contract, None)?;
        Ok(Some(verifier))
    }
}
