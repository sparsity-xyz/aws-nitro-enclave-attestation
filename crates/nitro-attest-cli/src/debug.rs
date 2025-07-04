use std::path::PathBuf;

use alloy_primitives::Bytes;
use aws_nitro_enclave_attestation_verifier::{stub::Bytes48, AttestationReport};
use clap::{Args, Subcommand};
use x509_verifier_rust_crypto::x509_parser::time::ASN1Time;

#[derive(Subcommand)]
pub enum DebugCli {
    Doc(DebugDocCli),
}

impl DebugCli {
    pub fn run(&self) -> anyhow::Result<()> {
        match self {
            DebugCli::Doc(cli) => cli.run(),
        }
    }
}

#[derive(Args)]
pub struct DebugDocCli {
    #[clap(long)]
    report: PathBuf,
}

impl DebugDocCli {
    pub fn run(&self) -> anyhow::Result<()> {
        let report = AttestationReport::parse(&std::fs::read(&self.report)?)?;
        let cert_chain = report.cert_chain()?;
        let doc = report.doc();
        tracing::info!("Doc:");
        tracing::info!("\tModule ID: {}", doc.module_id);
        let timestamp = ASN1Time::from_timestamp(doc.timestamp as i64 / 1000)?;
        tracing::info!("\tTimestamp: {}({})", timestamp, timestamp.timestamp());
        tracing::info!("\tDigest: {}", doc.digest);
        if let Some(data) = &doc.public_key {
            tracing::info!("\tPublicKey: {}", Bytes::copy_from_slice(data));
        }
        if let Some(data) = &doc.user_data {
            tracing::info!("\tUserData: {}", Bytes::copy_from_slice(data));
        }
        if let Some(data) = &doc.nonce {
            tracing::info!("\tNonce: {}", Bytes::copy_from_slice(data));
        }
        for (k, v) in &doc.pcrs {
            let v = Bytes48::from(v);
            if v.is_zero() {
                continue;
            }
            tracing::info!("\tPCR[{}]: {}", k, v);
        }
        tracing::info!("Cert Chain:");
        let digest = cert_chain.digest();
        for (idx, cert) in cert_chain.certs.iter().enumerate() {
            tracing::info!("\t[{idx}] Digest: {:?}", digest[idx]);
            let (start, end) = cert.validity();
            tracing::info!(
                "\t    Valid: {start}({}) - {end}({})",
                start.timestamp(),
                end.timestamp()
            );
        }
        Ok(())
    }
}
