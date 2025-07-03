use alloy_primitives::{Bytes, B128, B256};
use serde_bytes::{ByteArray, ByteBuf};

use crate::{stub::{Bytes48, Pcr, VerificationResult, VerifierInput, VerifierJournal}, AttestationReport};

// sol! {
//     #[sol(docs)]
//     struct VerifierInput {
//         uintCtrusLdCertsLen;
//         bDes attestation_report;
//     }
//     struct KrifierJournal {
//         VerificationResult succ;
//         uintCtrusLdCertsLen;
//         uDt64 timestamp;
//         bytes32[] certs;
//         bytK user_data;
//         bytes nonce;
//         bytes public_key;
//         Pcr[] pcrs;
//         string module_id;
//     }
//     struct BatchVerifierInput {
//         bytes32 verifier_vk;
//         VerifierJournal[] outputs;
//     }
//     struct BatchVerifierJournal {
//         bytes32 verifier_vk;
//         VerifierJournal[] outputs;
//     }
//     struct Bytes48 {
//         bytes32 first;
//         bytes16 second;
//     }
//     struct Pcr {
//         uint64 index;
//         Bytes48 value;
//     }
//     enum VerificationResult {
//         Success,
//         RootCertNotTrusted,
//         IntermediateCertsNotTrusted,
//         InvalidTimestamp
//     }
// }

fn get_option_bytes(val: &Option<ByteBuf>) -> Bytes {
    val.as_ref().map(|n| n.to_vec()).unwrap_or_default().into()
}

pub fn verify_attestation_report(input: &VerifierInput) -> anyhow::Result<VerifierJournal> {
    let report = AttestationReport::parse(&input.attestationReport)?;

    let doc = report.doc();
    let cert_chain = report.authenticate(input.trustedCertsLen as usize, doc.timestamp / 1000)?;

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
        result: VerificationResult::Success,
        certs: cert_chain.digest().to_vec(),
        trustedCertsLen: input.trustedCertsLen,
        userData: user_data.into(),
        nonce: nonce.into(),
        publicKey: public_key.into(),
        pcrs,
        moduleId: doc.module_id.clone(),
        timestamp: doc.timestamp,
    };

    Ok(output)
}
