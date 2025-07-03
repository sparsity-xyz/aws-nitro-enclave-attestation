use alloy_primitives::{Bytes, B128, B256};
use alloy_sol_types::{sol, SolValue};
use anyhow::anyhow;
use serde_bytes::{ByteArray, ByteBuf};
use x509_verifier_rust_crypto::sha256;

use crate::AttestationReport;

sol! {
    #[derive(Debug)]
    struct VerifierInput {
        uint64 timestamp;
        uint8 trusted_certs_len;
        bytes attestation_report;
    }
    #[derive(Debug)]
    struct VerifierJournal {
        uint64 verify_timestamp;
        bytes32[] certs;
        uint8 trusted_certs_len;
        bytes user_data;
        bytes nonce;
        bytes public_key;
        Pcr[] pcrs;
        string module_id;
        uint64 doc_timestamp;
    }
    #[derive(Debug)]
    struct BatchVerifierInput {
        bytes32 verifier_vk;
        VerifierJournal[] outputs;
    }
    #[derive(Debug)]
    struct BatchVerifierJournal {
        bytes32 verifier_vk;
        VerifierJournal[] outputs;
    }
    #[derive(Debug, Default)]
    struct Bytes48 {
        bytes32 first;
        bytes16 second;
    }
    #[derive(Debug)]
    struct Pcr {
        uint64 index;
        Bytes48 value;
    }
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

fn get_option_bytes(val: &Option<ByteBuf>) -> Bytes {
    val.as_ref().map(|n| n.to_vec()).unwrap_or_default().into()
}

pub fn verify_attestation_report(input: &VerifierInput) -> anyhow::Result<VerifierJournal> {
    // let time_now = SystemTime::UNIX_EPOCH + Duration::from_secs(input.timestamp);

    let report = AttestationReport::parse(&input.attestation_report)?;
    let cert_chain = report.authenticate(input.trusted_certs_len as usize, input.timestamp)?;

    let doc = report.doc();

    let user_data = get_option_bytes(&doc.user_data);
    let nonce = get_option_bytes(&doc.nonce);
    let public_key = get_option_bytes(&doc.public_key);
    let pcrs = doc
        .pcrs
        .iter()
        .filter(|(_, value)| value != &&ByteArray::<48>::default())
        .map(|(index, value)| Pcr {
            index: *index,
            value: Bytes48 {
                first: B256::from_slice(&value[..32]),
                second: B128::from_slice(&value[32..]),
            },
        })
        .collect::<Vec<_>>();

    let output = VerifierJournal {
        verify_timestamp: input.timestamp,
        certs: cert_chain.digest().to_vec(),
        trusted_certs_len: input.trusted_certs_len,
        user_data: user_data.into(),
        nonce: nonce.into(),
        public_key: public_key.into(),
        pcrs,
        module_id: doc.module_id.clone(),
        doc_timestamp: doc.timestamp,
    };

    Ok(output)
}
