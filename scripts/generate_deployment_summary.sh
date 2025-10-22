#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"
DEPLOYMENTS_DIR="$CONTRACTS_DIR/deployments"
CONFIG_FILE="$CONTRACTS_DIR/deploy-config.json"

cd "$CONTRACTS_DIR"

if [ ! -d "$DEPLOYMENTS_DIR" ]; then
    echo "Error: deployments directory not found"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq command not found. Please install jq:"
    echo "https://stedolan.github.io/jq/download/"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: deploy-config.json not found"
    exit 1
fi

echo "# Deployment Addresses"
echo ""
echo "This document contains all NitroEnclaveVerifier contract deployment addresses across different chains."
echo ""
echo "Last updated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
echo ""

echo "## Mainnet Deployments"
echo ""
echo "| Network | Chain ID | NitroEnclaveVerifier | SP1 Verifier | RISC0 Verifier |"
echo "|---------|----------|---------------------|--------------|----------------|"

for file in "$DEPLOYMENTS_DIR"/*.json; do
    if [ -f "$file" ]; then
        chain_id=$(basename "$file" .json)
        
        is_testnet=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .value.testnet // false' "$CONFIG_FILE")
        
        if [ "$is_testnet" == "false" ]; then
            chain_name=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .key' "$CONFIG_FILE")
            explorer=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .value.explorer' "$CONFIG_FILE")
            
            if [ -z "$chain_name" ] || [ "$chain_name" == "null" ]; then
                chain_name="Chain $chain_id"
            fi
            
            verifier=$(jq -r '.VERIFIER // "N/A"' "$file")
            sp1_verifier=$(jq -r '.SP1_VERIFIER // "N/A"' "$file")
            risc0_verifier=$(jq -r '.RISC0_VERIFIER // "N/A"' "$file")
            
            verifier_link="N/A"
            sp1_link="N/A"
            risc0_link="N/A"
            
            if [ "$verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                verifier_link="[\`${verifier}\`](${explorer}/address/${verifier})"
            elif [ "$verifier" != "N/A" ]; then
                verifier_link="\`${verifier}\`"
            fi
            
            if [ "$sp1_verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                sp1_link="[\`${sp1_verifier}\`](${explorer}/address/${sp1_verifier})"
            elif [ "$sp1_verifier" != "N/A" ]; then
                sp1_link="\`${sp1_verifier}\`"
            fi
            
            if [ "$risc0_verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                risc0_link="[\`${risc0_verifier}\`](${explorer}/address/${risc0_verifier})"
            elif [ "$risc0_verifier" != "N/A" ]; then
                risc0_link="\`${risc0_verifier}\`"
            fi
            
            echo "| $chain_name | $chain_id | $verifier_link | $sp1_link | $risc0_link |"
        fi
    fi
done

echo ""
echo "## Testnet Deployments"
echo ""
echo "| Network | Chain ID | NitroEnclaveVerifier | SP1 Verifier | RISC0 Verifier |"
echo "|---------|----------|---------------------|--------------|----------------|"

for file in "$DEPLOYMENTS_DIR"/*.json; do
    if [ -f "$file" ]; then
        chain_id=$(basename "$file" .json)
        
        is_testnet=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .value.testnet // false' "$CONFIG_FILE")
        
        if [ "$is_testnet" == "true" ]; then
            chain_name=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .key' "$CONFIG_FILE")
            explorer=$(jq -r --arg cid "$chain_id" '.chains | to_entries[] | select(.value.chainId == ($cid | tonumber)) | .value.explorer' "$CONFIG_FILE")
            
            if [ -z "$chain_name" ] || [ "$chain_name" == "null" ]; then
                chain_name="Chain $chain_id"
            fi
            
            verifier=$(jq -r '.VERIFIER // "N/A"' "$file")
            sp1_verifier=$(jq -r '.SP1_VERIFIER // "N/A"' "$file")
            risc0_verifier=$(jq -r '.RISC0_VERIFIER // "N/A"' "$file")
            
            verifier_link="N/A"
            sp1_link="N/A"
            risc0_link="N/A"
            
            if [ "$verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                verifier_link="[\`${verifier}\`](${explorer}/address/${verifier})"
            elif [ "$verifier" != "N/A" ]; then
                verifier_link="\`${verifier}\`"
            fi
            
            if [ "$sp1_verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                sp1_link="[\`${sp1_verifier}\`](${explorer}/address/${sp1_verifier})"
            elif [ "$sp1_verifier" != "N/A" ]; then
                sp1_link="\`${sp1_verifier}\`"
            fi
            
            if [ "$risc0_verifier" != "N/A" ] && [ -n "$explorer" ] && [ "$explorer" != "null" ]; then
                risc0_link="[\`${risc0_verifier}\`](${explorer}/address/${risc0_verifier})"
            elif [ "$risc0_verifier" != "N/A" ]; then
                risc0_link="\`${risc0_verifier}\`"
            fi
            
            echo "| $chain_name | $chain_id | $verifier_link | $sp1_link | $risc0_link |"
        fi
    fi
done

echo ""
echo "## Notes"
echo ""
echo "- All addresses are checksummed Ethereum addresses"
echo "- SP1 and RISC0 verifiers may use official deployments from their respective projects"
echo "- Click on addresses to view contracts on block explorers"
