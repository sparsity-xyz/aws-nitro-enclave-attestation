// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// This file contains modified code originally from the AWS Labs aws-nitro-enclaves-cose project:
// https://github.com/awslabs/aws-nitro-enclaves-cose
//
// Modifications have been made to adapt the code for use with x509-verifier-rust-crypto
// instead of the original OpenSSL-based crypto implementation.

use std::collections::BTreeMap;

use anyhow::anyhow;
use serde::ser::SerializeSeq;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde_bytes::ByteBuf;
use serde_cbor::Value as CborValue;
use x509_verifier_rust_crypto::verify_signature;
use x509_verifier_rust_crypto::PubKey;
use x509_verifier_rust_crypto::SigAlgo;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
/// Implementation of header_map, with CborValue keys and CborValue values.
pub struct HeaderMap(
    #[serde(deserialize_with = "::serde_with::rust::maps_duplicate_key_is_error::deserialize")]
    BTreeMap<CborValue, CborValue>,
);

#[repr(i8)]
pub enum SignatureAlgorithm {
    ///  ECDSA w/ SHA-256
    ES256 = -7,
    ///  ECDSA w/ SHA-384
    ES384 = -35,
    /// ECDSA w/ SHA-512
    ES512 = -36,
}

fn sig_algo_val(alg: SigAlgo) -> anyhow::Result<i8> {
    Ok(match alg {
        SigAlgo::EcdsaSHA256 => -7,
        SigAlgo::EcdsaSHA384 => -35,
        alg => return Err(anyhow!("unsupport sigAlgo: {:?}", alg)),
    })
}

#[derive(Debug)]
pub struct CoseSign1 {
    /// protected: empty_or_serialized_map,
    protected: ByteBuf,
    /// unprotected: HeaderMap
    pub unprotected: HeaderMap,
    /// payload: bstr
    /// The spec allows payload to be nil and transported separately, but it's not useful at the
    /// moment, so this is just a ByteBuf for simplicity.
    pub payload: ByteBuf,
    /// signature: bstr
    pub signature: ByteBuf,
}

impl CoseSign1 {
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let cosesign1: serde_cbor::tags::Tagged<Self> = serde_cbor::from_slice(bytes)
            .map_err(|err| anyhow!("deserialization failed: {:?}", err))?;

        match cosesign1.tag {
            None | Some(18) => (),
            Some(tag) => return Err(anyhow!("tag error: {:?}", tag)),
        }
        let protected = cosesign1.value.protected.as_slice();
        let _: HeaderMap = serde_cbor::from_slice(protected)
            .map_err(|err| anyhow!("deserialization failed: {:?}", err))?;
        Ok(cosesign1.value)
    }

    pub fn verify_signature(&self, sig_algo: SigAlgo, issuer_key: PubKey) -> anyhow::Result<bool> {
        let protected: HeaderMap = serde_cbor::from_slice(&self.protected)
            .map_err(|err| anyhow!("deserialization failed: {:?}", err))?;

        if let Some(protected_signature_alg_val) = protected.0.get(&CborValue::Integer(1)) {
            let protected_signature_alg = match protected_signature_alg_val {
                CborValue::Integer(val) => val,
                _ => {
                    return Err(anyhow!(
                        "Protected Header contains invalid Signature Algorithm specification"
                    ))
                }
            };
            if protected_signature_alg != &(sig_algo_val(sig_algo)? as i128) {
                // The key doesn't match the one specified in the HeaderMap, so this fails
                // signature verification immediately.
                return Ok(false);
            }
        } else {
            return Err(anyhow!(
                "Protected Header does not contain a valid Signature Algorithm specification",
            ));
        }

        let sig_structure = SigStructure::new_sign1(&self.protected, &self.payload)?;

        let tbs = sig_structure.as_bytes()?;

        Ok(verify_signature(
            issuer_key,
            sig_algo,
            &self.signature,
            &tbs,
        )?)
    }
}

impl Serialize for CoseSign1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        seq.serialize_element(&self.protected)?;
        seq.serialize_element(&self.unprotected)?;
        seq.serialize_element(&self.payload)?;
        seq.serialize_element(&self.signature)?;
        seq.end()
    }
}

impl<'de> Deserialize<'de> for CoseSign1 {
    fn deserialize<D>(deserializer: D) -> Result<CoseSign1, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{Error, SeqAccess, Visitor};
        use std::fmt;

        struct CoseSign1Visitor;

        impl<'de> Visitor<'de> for CoseSign1Visitor {
            type Value = CoseSign1;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a possibly tagged CoseSign1 structure")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<CoseSign1, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // This is the untagged version
                let protected = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("protected")),
                };

                let unprotected = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("unprotected")),
                };
                let payload = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("payload")),
                };
                let signature = match seq.next_element()? {
                    Some(v) => v,
                    None => return Err(A::Error::missing_field("signature")),
                };

                Ok(CoseSign1 {
                    protected,
                    unprotected,
                    payload,
                    signature,
                })
            }

            fn visit_newtype_struct<D>(self, deserializer: D) -> Result<CoseSign1, D::Error>
            where
                D: Deserializer<'de>,
            {
                // This is the tagged version: we ignore the tag part, and just go into it
                deserializer.deserialize_seq(CoseSign1Visitor)
            }
        }

        deserializer.deserialize_any(CoseSign1Visitor)
    }
}

///  Implementation of the Sig_structure as defined in
///  [RFC8152](https://tools.ietf.org/html/rfc8152#section-4.4).
///
///  In order to create a signature, a well-defined byte stream is needed.
///  The Sig_structure is used to create the canonical form.  This signing
///  and verification process takes in the body information (COSE_Sign or
///  COSE_Sign1), the signer information (COSE_Signature), and the
///  application data (external source).  A Sig_structure is a CBOR array.
///  The fields of the Sig_structure in order are:
///
///  1.  A text string identifying the context of the signature.  The
///      context string is:
///
///         "Signature" for signatures using the COSE_Signature structure.
///
///         "Signature1" for signatures using the COSE_Sign1 structure.
///
///         "CounterSignature" for signatures used as counter signature
///         attributes.
///
///  2.  The protected attributes from the body structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.
///
///  3.  The protected attributes from the signer structure encoded in a
///      bstr type.  If there are no protected attributes, a bstr of
///      length zero is used.  This field is omitted for the COSE_Sign1
///      signature structure.
///
///  4.  The protected attributes from the application encoded in a bstr
///      type.  If this field is not supplied, it defaults to a zero-
///      length binary string.  (See Section 4.3 for application guidance
///      on constructing this field.)
///
///  5.  The payload to be signed encoded in a bstr type.  The payload is
///      placed here independent of how it is transported.
///
///  Note: A struct serializes to a map, while a tuple serializes to an array,
///  which is why this struct is actually a tuple
///  Note: This structure only needs to be serializable, since it's
///  used for generating a signature and not transported anywhere. Both
///  sides need to generate it independently.
#[derive(Debug, Clone, Serialize)]
pub struct SigStructure(
    /// context: "Signature" / "Signature1" / "CounterSignature"
    String,
    /// body_protected : empty_or_serialized_map,
    ByteBuf,
    /// ? sign_protected : empty_or_serialized_map,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    Option<ByteBuf>,
    /// external_aad : bstr,
    #[serde(default)]
    ByteBuf,
    /// payload : bstr
    #[serde(default)]
    ByteBuf,
);

impl SigStructure {
    /// Takes the protected field of the COSE_Sign object and a raw slice of bytes as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1(body_protected: &[u8], payload: &[u8]) -> anyhow::Result<Self> {
        Ok(SigStructure(
            String::from("Signature1"),
            ByteBuf::from(body_protected.to_vec()),
            None,
            ByteBuf::new(),
            ByteBuf::from(payload.to_vec()),
        ))
    }

    /// Takes the protected field of the COSE_Sign object and a CborValue as payload and creates a
    /// SigStructure for one signer from it
    pub fn new_sign1_cbor_value(
        body_protected: &[u8],
        payload: &CborValue,
    ) -> anyhow::Result<Self> {
        let payload = serde_cbor::to_vec(payload)
            .map_err(|err| anyhow!("deserialization failed: {:?}", err))?;
        Ok(Self::new_sign1(body_protected, &payload)?)
    }

    /// Serializes the SigStructure to . We don't care about deserialization, since
    /// both sides are supposed to compute the SigStructure and compare.
    pub fn as_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_cbor::to_vec(self).map_err(|err| anyhow!("serialization failed: {:?}", err))?)
    }
}
