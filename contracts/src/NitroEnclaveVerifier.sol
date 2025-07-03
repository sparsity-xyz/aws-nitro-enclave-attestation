//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Ownable} from "@solady/auth/Ownable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IRiscZeroVerifier} from "@risc0-ethereum/IRiscZeroVerifier.sol";
import {INitroEnclaveVerifier, ZkCoProcessorType, ZkCoProcessorConfig, VerifierJournal, BatchVerifierJournal} from "./interfaces/INitroEnclaveVerifier.sol";
import {console} from "forge-std/console.sol";

contract NitroEnclaveVerifier is Ownable, INitroEnclaveVerifier {
    mapping(ZkCoProcessorType => ZkCoProcessorConfig) zkConfig;
    // should not save the root cert
    mapping(bytes32 trustedCertHash => bool) public trustedIntermediateCerts;
    uint64 maxTimeDiff;
    bytes32 public rootCert;

    constructor(uint64 _maxTimeDiff) {
        maxTimeDiff = _maxTimeDiff;
        _initializeOwner(msg.sender);
    }

    error Unknown_Zk_Coprocessor();

    function revokeCert(bytes32 _certHash)
        external
        onlyOwner
    {
        if (!trustedIntermediateCerts[_certHash]) {
            revert("Certificate not found in trusted certs");
        }
        delete trustedIntermediateCerts[_certHash];
    }

    function setRootCert(bytes32 _rootCert)
        external
        onlyOwner
    {
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
        for (uint256 i = journal.trusted_certs_len; i < journal.certs.length; i++) {
            bytes32 certHash = journal.certs[i];
            trustedIntermediateCerts[certHash] = true;
        }
    }

    function _verifyJournal(VerifierJournal memory journal)
        internal
    {
        if (journal.trusted_certs_len == 0) {
            revert("At least trusted the root certs");
        }
        // check every trusted certificate to make sure none of one is revoked
        for (uint256 i = 0; i < journal.trusted_certs_len; i++) {
            bytes32 certHash = journal.certs[i];
            if (i == 0) {
                if (certHash != rootCert) {
                    revert("Last trusted certificate must be the root certificate");
                }
                continue;
            }
            if (!trustedIntermediateCerts[certHash]) {
                revert("Untrusted certificate");
            }
        }
        _cacheNewCert(journal);
        if (journal.verify_timestamp + maxTimeDiff < block.timestamp || journal.verify_timestamp > block.timestamp) {
            revert("invalid verify timestamp");
        }
        if (journal.doc_timestamp / 1000 + maxTimeDiff < block.timestamp || journal.doc_timestamp / 1000 > block.timestamp) {
            console.log(journal.doc_timestamp / 1000);
            revert("invalid doc timestamp");
        }
    }

    function batchVerify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    )
        external
        returns (VerifierJournal[] memory)
    {
        bytes32 programId = zkConfig[zkCoprocessor].aggregatorId;
        bytes32 verifierProofId = zkConfig[zkCoprocessor].verifierProofId;
        _verifyZk(zkCoprocessor, programId, output, proofBytes);
        BatchVerifierJournal memory batchJournal = abi.decode(output, (BatchVerifierJournal));
        for (uint256 i = 0; i < batchJournal.outputs.length; i++) {
            _verifyJournal(batchJournal.outputs[i]);
        }
        if (batchJournal.verifier_vk != verifierProofId) {
            revert("Verifier VK does not match the expected verifier proof ID");
        }
        return batchJournal.outputs;
    }

    function _verifyZk(ZkCoProcessorType zkCoprocessor, bytes32 programId, bytes calldata output, bytes calldata proofBytes) internal view {
        address zkVerifier = zkConfig[zkCoprocessor].zkVerifier;
        if (zkCoprocessor == ZkCoProcessorType.RiscZero) {
            IRiscZeroVerifier(zkVerifier).verify(
                proofBytes,
                programId,
                sha256(output)
            );
        } else if (zkCoprocessor == ZkCoProcessorType.Succinct) {
            ISP1Verifier(zkVerifier).verifyProof(programId, output, proofBytes);
        } else {
            revert Unknown_Zk_Coprocessor();
        }
    }

    function verify(
        bytes calldata output,
        ZkCoProcessorType zkCoprocessor,
        bytes calldata proofBytes
    )
        external
        returns (VerifierJournal memory)
    {
        bytes32 programId = zkConfig[zkCoprocessor].verifierId;
        _verifyZk(zkCoprocessor, programId, output, proofBytes);
        VerifierJournal memory journal = abi.decode(output, (VerifierJournal));
        _verifyJournal(journal);
        return journal;
    }
}