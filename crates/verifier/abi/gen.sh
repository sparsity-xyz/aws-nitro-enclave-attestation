#!/bin/bash
cd $(dirname $0)

cat ../../../contracts/out/NitroEnclaveVerifier.sol/NitroEnclaveVerifier.json | jq .abi >> NitroEnclaveVerifier.rs
