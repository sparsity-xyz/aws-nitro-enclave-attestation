//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// ZK-Coprocessor imports:

enum ZkCoProcessorType {
    Unknown,
    RiscZero,
    Succinct
}

/**
 * @title ZK Co-Processor Configuration Object
 * @param programIdentifier - This is the identifier of the ZK Program, required for
 * verification
 * @param zkVerifier - Points to the address of the ZK Verifier contract. Ideally
 * this should be pointing to a universal verifier, that may support multiple proof types and/or versions.
 */
struct ZkCoProcessorConfig {
    bytes32 verifierId;
    bytes32 verifierProofId;
    bytes32 aggregatorId;
    address zkVerifier;
}

struct VerifierInput {
    uint64 timestamp;
    uint8 trusted_certs_len;
    bytes attestation_report;
}

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

struct BatchVerifierInput {
    bytes32 verifier_vk;
    VerifierJournal[] outputs;
}

struct BatchVerifierJournal {
    bytes32 verifier_vk;
    VerifierJournal[] outputs;
}

struct Bytes48 {
    bytes32 first;
    bytes16 second;
}

struct Pcr {
    uint64 index;
    Bytes48 value;
}

interface INitroEnclaveVerifier {

}