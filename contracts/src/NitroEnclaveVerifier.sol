//SPDX-License-Identifier: Apache2.0
pragma solidity ^0.8.0;

import {Ownable} from "@solady/auth/Ownable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IRiscZeroVerifier} from "@risc0-ethereum/IRiscZeroVerifier.sol";
import {
    INitroEnclaveVerifier,
    ZkCoProcessorType,
    ZkCoProcessorConfig,
    VerifierJournal,
    BatchVerifierJournal,
    VerificationResult
} from "./interfaces/INitroEnclaveVerifier.sol";
import {console} from "forge-std/console.sol";

contract NitroEnclaveVerifier is Ownable, INitroEnclaveVerifier {
    mapping(ZkCoProcessorType => ZkCoProcessorConfig) zkConfig;
    // should not save the root cert
    mapping(bytes32 trustedCertHash => bool) public trustedIntermediateCerts;
    uint64 public maxTimeDiff;
    bytes32 public rootCert;

    constructor(uint64 _maxTimeDiff, bytes32[] memory initializeTrustedCerts) {
        maxTimeDiff = _maxTimeDiff;
        for (uint256 i = 0; i < initializeTrustedCerts.length; i++) {
            trustedIntermediateCerts[initializeTrustedCerts[i]] = true;
        }
        _initializeOwner(msg.sender);
    }

    function revokeCert(bytes32 _certHash) external onlyOwner {
        if (!trustedIntermediateCerts[_certHash]) {
            revert("Certificate not found in trusted certs");
        }
        delete trustedIntermediateCerts[_certHash];
    }

    function checkTrustedIntermediateCerts(bytes32[][] calldata _report_certs) public view returns (uint8[] memory) {
        uint8[] memory results = new uint8[](_report_certs.length);
        bytes32 rootCertHash = rootCert;
        for (uint256 i = 0; i < _report_certs.length; i++) {
            bytes32[] calldata certs = _report_certs[i];
            uint8 trustedCertLen = 1;
            if (certs[0] != rootCertHash) {
                revert("First certificate must be the root certificate");
            }
            for (uint256 j = 1; j < certs.length; j++) {
                if (!trustedIntermediateCerts[certs[j]]) {
                    break;
                }
                trustedCertLen += 1;
            }
            results[i] = trustedCertLen;
        }
        return results;
    }

    function setRootCert(bytes32 _rootCert) external onlyOwner {
        rootCert = _rootCert;
    }

    /**
     * @notice Sets the ZK Configuration for the given ZK Co-Processor
     */
    function setZkConfiguration(ZkCoProcessorType _zkCoProcessor, ZkCoProcessorConfig memory _config)
        external
        onlyOwner
    {
        zkConfig[_zkCoProcessor] = _config;
    }

    function _cacheNewCert(VerifierJournal memory journal) internal {
        for (uint256 i = journal.trustedCertsLen; i < journal.certs.length; i++) {
            bytes32 certHash = journal.certs[i];
            trustedIntermediateCerts[certHash] = true;
        }
    }

    function _verifyJournal(VerifierJournal memory journal) internal returns (VerifierJournal memory) {
        if (journal.result != VerificationResult.Success) {
            return journal;
        }
        if (journal.trustedCertsLen == 0) {
            journal.result = VerificationResult.RootCertNotTrusted;
            return journal;
        }
        // check every trusted certificate to make sure none of one is revoked
        for (uint256 i = 0; i < journal.trustedCertsLen; i++) {
            bytes32 certHash = journal.certs[i];
            if (i == 0) {
                if (certHash != rootCert) {
                    journal.result = VerificationResult.RootCertNotTrusted;
                    return journal;
                }
                continue;
            }
            if (!trustedIntermediateCerts[certHash]) {
                journal.result = VerificationResult.IntermediateCertsNotTrusted;
                return journal;
            }
        }
        uint64 timestamp = journal.timestamp / 1000;
        if (timestamp + maxTimeDiff < block.timestamp || timestamp > block.timestamp) {
            journal.result = VerificationResult.InvalidTimestamp;
            return journal;
        }
        _cacheNewCert(journal);
        return journal;
    }

    function batchVerify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal[] memory)
    {
        bytes32 programId = zkConfig[zkCoprocessor].aggregatorId;
        bytes32 verifierProofId = zkConfig[zkCoprocessor].verifierProofId;
        _verifyZk(zkCoprocessor, programId, output, proofBytes);
        BatchVerifierJournal memory batchJournal = abi.decode(output, (BatchVerifierJournal));
        if (batchJournal.verifierVk != verifierProofId) {
            revert("Verifier VK does not match the expected verifier proof ID");
        }
        for (uint256 i = 0; i < batchJournal.outputs.length; i++) {
            batchJournal.outputs[i] = _verifyJournal(batchJournal.outputs[i]);
        }

        return batchJournal.outputs;
    }

    function _verifyZk(
        ZkCoProcessorType zkCoprocessor,
        bytes32 programId,
        bytes calldata output,
        bytes calldata proofBytes
    ) internal view {
        address zkVerifier = zkConfig[zkCoprocessor].zkVerifier;
        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkVerifier).verify(proofBytes, programId, sha256(output));
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkVerifier).verifyProof(programId, output, proofBytes);
        } else {
            revert Unknown_Zk_Coprocessor();
        }
    }

    function verify(bytes calldata output, ZkCoProcessorType zkCoprocessor, bytes calldata proofBytes)
        external
        returns (VerifierJournal memory)
    {
        bytes32 programId = zkConfig[zkCoprocessor].verifierId;
        _verifyZk(zkCoprocessor, programId, output, proofBytes);
        VerifierJournal memory journal = abi.decode(output, (VerifierJournal));
        journal = _verifyJournal(journal);
        return journal;
    }
}
