#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/contracts"

cd "$CONTRACTS_DIR"

print_usage() {
    cat << EOF
Multi-Chain Deployment Tool for NitroEnclaveVerifier

Usage: $0 [OPTIONS]

Options:
    -c, --chain CHAIN_NAME          Deploy to a specific chain (e.g., sepolia, base, arbitrum)
    -m, --multiple CHAIN1,CHAIN2    Deploy to multiple specific chains (comma-separated)
    -a, --all                       Deploy to all chains in deploy-config.json
    -l, --list                      List all available chains
    -d, --dry-run                   Simulate deployment without broadcasting transactions
    -h, --help                      Show this help message

Environment Variables:
    PRIVATE_KEY                     Private key for deployment (required)
    ETHERSCAN_API_KEY              API key for contract verification (optional)

Examples:
    # Deploy to Sepolia testnet
    $0 --chain sepolia

    # Deploy to multiple chains
    $0 --multiple sepolia,base-sepolia,arbitrum-sepolia

    # Deploy to all configured chains
    $0 --all

    # List available chains
    $0 --list

    # Dry run deployment
    $0 --chain sepolia --dry-run

EOF
}

list_chains() {
    echo "Available chains in deploy-config.json:"
    echo "========================================"
    
    if [ ! -f "deploy-config.json" ]; then
        echo "Error: deploy-config.json not found"
        exit 1
    fi
    
    chains=$(jq -r '.chains | keys[]' deploy-config.json)
    
    for chain in $chains; do
        chain_id=$(jq -r ".chains.${chain}.chainId" deploy-config.json)
        rpc=$(jq -r ".chains.${chain}.rpc" deploy-config.json)
        echo "  - $chain (Chain ID: $chain_id)"
        echo "    RPC: $rpc"
    done
    
    echo ""
}

check_requirements() {
    if [ -z "$PRIVATE_KEY" ]; then
        echo "Error: PRIVATE_KEY environment variable is not set"
        echo "Please set it with: export PRIVATE_KEY=your_private_key"
        exit 1
    fi
    
    if ! command -v forge &> /dev/null; then
        echo "Error: forge command not found. Please install Foundry:"
        echo "https://getfoundry.sh/"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        echo "Error: jq command not found. Please install jq:"
        echo "https://stedolan.github.io/jq/download/"
        exit 1
    fi
    
    if [ ! -f "deploy-config.json" ]; then
        echo "Error: deploy-config.json not found in $CONTRACTS_DIR"
        exit 1
    fi
}

deploy_to_chain() {
    local chain_name=$1
    local dry_run=$2
    
    echo "=========================================="
    echo "Deploying to: $chain_name"
    echo "=========================================="
    
    local cmd="forge script script/MultiChainDeploy.s.sol:MultiChainDeployScript \
        --sig 'deployToChain(string)' \
        '$chain_name'"
    
    if [ "$dry_run" != "true" ]; then
        cmd="$cmd --broadcast --private-key $PRIVATE_KEY"
        
        if [ -n "$ETHERSCAN_API_KEY" ]; then
            cmd="$cmd --verify --etherscan-api-key $ETHERSCAN_API_KEY"
        fi
    fi
    
    eval $cmd
    
    if [ $? -eq 0 ]; then
        echo "✅ Successfully deployed to $chain_name"
    else
        echo "❌ Failed to deploy to $chain_name"
        return 1
    fi
}

deploy_to_multiple_chains() {
    local chains=$1
    local dry_run=$2
    
    IFS=',' read -ra CHAIN_ARRAY <<< "$chains"
    
    for chain in "${CHAIN_ARRAY[@]}"; do
        chain=$(echo "$chain" | xargs)
        deploy_to_chain "$chain" "$dry_run"
        echo ""
    done
}

deploy_to_all_chains() {
    local dry_run=$1
    
    echo "=========================================="
    echo "Deploying to ALL chains"
    echo "=========================================="
    echo ""
    
    local cmd="forge script script/MultiChainDeploy.s.sol:MultiChainDeployScript \
        --sig 'deployAll()'"
    
    if [ "$dry_run" != "true" ]; then
        cmd="$cmd --broadcast --private-key $PRIVATE_KEY"
        
        if [ -n "$ETHERSCAN_API_KEY" ]; then
            cmd="$cmd --verify --etherscan-api-key $ETHERSCAN_API_KEY"
        fi
    fi
    
    eval $cmd
}

CHAIN_NAME=""
MULTIPLE_CHAINS=""
DEPLOY_ALL=false
DRY_RUN=false
LIST_CHAINS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--chain)
            CHAIN_NAME="$2"
            shift 2
            ;;
        -m|--multiple)
            MULTIPLE_CHAINS="$2"
            shift 2
            ;;
        -a|--all)
            DEPLOY_ALL=true
            shift
            ;;
        -l|--list)
            LIST_CHAINS=true
            shift
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

if [ "$LIST_CHAINS" = true ]; then
    list_chains
    exit 0
fi

if [ -z "$CHAIN_NAME" ] && [ -z "$MULTIPLE_CHAINS" ] && [ "$DEPLOY_ALL" = false ]; then
    echo "Error: No deployment target specified"
    echo ""
    print_usage
    exit 1
fi

check_requirements

if [ "$DRY_RUN" = true ]; then
    echo "🔍 DRY RUN MODE - No transactions will be broadcasted"
    echo ""
fi

if [ -n "$CHAIN_NAME" ]; then
    deploy_to_chain "$CHAIN_NAME" "$DRY_RUN"
elif [ -n "$MULTIPLE_CHAINS" ]; then
    deploy_to_multiple_chains "$MULTIPLE_CHAINS" "$DRY_RUN"
elif [ "$DEPLOY_ALL" = true ]; then
    deploy_to_all_chains "$DRY_RUN"
fi

echo ""
echo "=========================================="
echo "Deployment process completed!"
echo "=========================================="
