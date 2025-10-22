#!/bin/bash

set -euo pipefail

function _cli() {
    target/debug/nitro-attest-cli "$@"
}

function _script() {
    cd contracts
    unset VERIFIER
    forge script ./script/NitroEnclaveVerifier.s.sol --broadcast --rpc-url $RPC_URL --private-key $PRIVATE_KEY --sig "$@"
    cd ../
}

function getDeployment() {
    echo $(cat contracts/deployments/$1.json | jq -r .$2)
}

function getProgram() {
    echo $(cat samples/$1_program_id.json | jq -r .program_id.$2)
}

function _printAddr() {
    echo "| $1 | $2    | $(getDeployment $2 VERIFIER)  | $(getDeployment $2 SP1_VERIFIER) | $(getDeployment $2 RISC0_VERIFIER) |"
}

function _summary() {
    echo "| Network | ChainID  | NitroEnclaveVerifier                       | SP1Verifier                                | RiscZeroGroth16Verifier                    |"
    echo "| ------- | -------- | ------------------------------------------ | ------------------------------------------ | ------------------------------------------ |"
    _printAddr "Holesky" "17000"
    _printAddr "Sepolia" "11155111"

    echo
    echo "| ZkType | Verifier ID | Verifier Proof ID | Aggregator ID |"
    echo "| ------ | ----------- | ----------------- | ------------- |"
    echo "| Risc0  | $(getProgram risc0 verifier_id) | $(getProgram risc0 verifier_proof_id) | $(getProgram risc0 aggregator_id) |"
    echo "| SP1    | $(getProgram sp1 verifier_id) | $(getProgram sp1 verifier_proof_id) | $(getProgram sp1 aggregator_id) |"
}

#echo "Holesky: $HOLESKY_RPC_URL"
#echo "Sepolia: $SEPOLIA_RPC_URL"

#cargo build
#_cli upload --sp1 --out samples/sp1_program_id.json
#_cli upload --risc0 --out samples/risc0_program_id.json

#RPC_URL=$HOLESKY_RPC_URL _script 'deployAll(string,string,string)' ../samples/aws_root.der ../samples/sp1_program_id.json ../samples/risc0_program_id.json
#RPC_URL=$SEPOLIA_RPC_URL _script 'deployAll(string,string,string)' ../samples/aws_root.der ../samples/sp1_program_id.json ../samples/risc0_program_id.json

_summary