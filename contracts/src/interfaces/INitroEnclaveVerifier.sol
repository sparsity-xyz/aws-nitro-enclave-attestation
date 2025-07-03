//SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.0;

enum ZkCoProcessorType {
    Unknown,
    RiscZero,
    Succinct
}

struct ZkCoProcessorConfig {
    bytes32 verifierId;
    bytes32 verifierProofId;
    bytes32 aggregatorId;
    address zkVerifier;
}

struct VerifierInput {
    uint8 trustedCertsLen;
    bytes attestationReport;
}

struct VerifierJournal {
    VerificationResult result;
    uint8 trustedCertsLen;
    uint64 timestamp;
    bytes32[] certs;
    bytes userData;
    bytes nonce;
    bytes publicKey;
    Pcr[] pcrs;
    string moduleId;
}

struct BatchVerifierInput {
    bytes32 verifierVk;
    VerifierJournal[] outputs;
}

struct BatchVerifierJournal {
    bytes32 verifierVk;
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

enum VerificationResult {
    Success,
    RootCertNotTrusted,
    IntermediateCertsNotTrusted,
    InvalidTimestamp
}

interface INitroEnclaveVerifier {
    error Unknown_Zk_Coprocessor();

    function maxTimeDiff() external view returns (uint64);
    function rootCert() external view returns (bytes32);

    function revokeCert(bytes32 _certHash) external;
    function checkTrustedIntermediateCerts(bytes32[][] calldata _report_certs) external view returns (uint8[] memory);
    function setRootCert(bytes32 _rootCert) external;
    function setZkConfiguration(ZkCoProcessorType _zkCoProcessor, ZkCoProcessorConfig memory _config) external;
    function batchVerify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal[] memory);
    function verify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal memory);
}
