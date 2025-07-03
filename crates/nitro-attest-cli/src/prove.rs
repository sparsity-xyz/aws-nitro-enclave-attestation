use std::{alloc::System, path::PathBuf, time::SystemTime};

use alloy_primitives::Address;
use aws_nitro_enclave_attestation_prover::{
    contract::NitroEnclaveVerifier, new_prover, set_prover_dev_mode, ProveResult, Prover,
    ProverConfig,
};
use aws_nitro_enclave_attestation_verifier::{AttestationReport, VerifierInput};
use clap::Args;
use tokio::runtime::Runtime;
use x509_verifier_rust_crypto::Cert;

#[derive(Args)]
pub struct ProveMultiCli {
    #[arg(long)]
    proof: Vec<PathBuf>,

    #[arg(long)]
    out: Option<PathBuf>,

    #[clap(flatten)]
    prover: ProverArgs,
}

impl ProveMultiCli {
    pub fn run(&self) -> anyhow::Result<()> {
        set_prover_dev_mode(self.prover.dev);
        let prover = self.prover.new_prover()?;
        let mut proofs = Vec::new();
        for proof in &self.proof {
            let result = ProveResult::decode_json(&std::fs::read(&proof)?)?;
            proofs.push(result.proof);
        }

        let result = prover.prove_aggregated_proofs(proofs)?;
        if let Some(out) = &self.out {
            std::fs::write(out, result.encode_json()?)?;
        } else {
            println!("proof: {:?}", result);
        }
        Ok(())
    }
}

/// Arguments of the prover CLI.
#[derive(Args)]
pub struct ProveCli {
    /// The path to the Nitro Attestation Report file
    #[arg(long)]
    report: PathBuf,

    #[arg(long)]
    out: Option<PathBuf>,

    #[arg(long)]
    proof: Option<PathBuf>,

    #[arg(long)]
    root: Option<PathBuf>,

    /// Specify the timestamp when it verified
    #[arg(long)]
    timestamp: Option<u64>,

    #[clap(flatten)]
    prover: ProverArgs,

    #[clap(flatten)]
    contract: ContractArgs,
}

#[derive(Args, Clone)]
pub struct ContractArgs {
    /// The address of the Nitro Enclave Verifier contract
    #[arg(long)]
    pub contract: Option<Address>,

    /// The RPC URL to connect to the Ethereum network
    #[arg(long, env = "RPC_URL")]
    pub rpc_url: Option<String>,

    /// The private key to use for signing transactions
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
}

impl ContractArgs {
    pub fn empty(&self) -> bool {
        self.contract.is_none() || self.rpc_url.is_none()
    }

    pub fn sendable(&self) -> bool {
        !self.empty() && self.private_key.is_some()
    }

    pub fn stub(&self) -> anyhow::Result<NitroEnclaveVerifier> {
        if self.empty() {
            return Err(anyhow::anyhow!(
                "Contract address and RPC URL must be provided"
            ));
        }
        let contract = *self.contract.as_ref().unwrap();
        let rpc_url = self.rpc_url.as_ref().unwrap();
        let private_key = self.private_key.as_ref().map(|n| n.as_str());
        let verifier = NitroEnclaveVerifier::dial(&rpc_url, contract, private_key)?;
        Ok(verifier)
    }
}

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

impl ProveCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let attestation_report = std::fs::read(&self.report)?;
        let report = AttestationReport::parse(&attestation_report)?;

        let timestamp = self
            .timestamp
            .unwrap_or_else(|| report.doc().timestamp / 1000 as u64);

        let cert_chain = report.cert_chain()?;
        let certs = cert_chain.digest();
        if let Some(root) = &self.root {
            let root_cert = std::fs::read(root)?;
            let root_cert = Cert::parse_der(&root_cert)?.digest();
            if certs[0] != root_cert {
                return Err(anyhow::anyhow!(
                    "The root certificate is not in the verified certificate chain"
                ));
            }
        }

        let trusted_certs_len;
        if self.contract.empty() {
            log::warn!("provide --contract and --rpc-url allows querying the cert cache, which reduces cycle usage and also performs validity checks");

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if timestamp + 3600 < now {
                log::warn!(
                "The attestation report was signed {} seconds ago, which may indicate a verification failure.",
                now - timestamp
            );
            }
            trusted_certs_len = 1;
        } else {
            let rt = Runtime::new()?;
            trusted_certs_len = rt.block_on(async {
                let v = self.contract.stub()?;
                Ok::<_, anyhow::Error>(v.query_cert_cache(certs).await?)
            })?;
        }

        let input = VerifierInput {
            timestamp,
            trusted_certs_len,
            attestation_report: attestation_report.into(),
        };

        set_prover_dev_mode(self.prover.dev);

        let prover = new_prover(ProverConfig {
            sp1: self.prover.sp1,
            risc0: self.prover.risc0,
            sp1_private_key: self.prover.sp1_private_key.clone(),
            sp1_rpc_url: self.prover.sp1_rpc_url.clone(),
            risc0_api_url: self.prover.risc0_api_url.clone(),
        })?;
        let result = prover.prove_partial(&input)?;

        if let Some(out) = &self.out {
            std::fs::write(out, result.encode_json()?)?;
        } else {
            println!("proof: {:?}", result);
        }
        Ok(())
    }
}
