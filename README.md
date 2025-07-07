<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# AWS Nitro Enclave Attestation SDK
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A comprehensive SDK for AWS Nitro Enclave attestation verification that generates zero-knowledge proofs for on-chain verification with batch processing capabilities.

## Features

* **Zero-Knowledge Proof Generation**
  * Creates on-chain verifiable zero-knowledge proofs (ZKPs) for attestation reports
  * Supports both single and batch attestation verification
* **Multi-Backend Support**
  * Compatible with both Risc0 and Succinct proving systems, providing a unified user experience
  * Optimized performance profiles for different use cases
* **Batch Verification**
  * Supports attestation report batch verification to significantly reduce on-chain verification costs
* **Smart Contract Integration**
  * Includes on-chain verification contracts for seamless blockchain integration
  * Gas-optimized verification with certificate revocation support
* **Comprehensive CLI Tool**
  * Comprehensive CLI tool for proof generation, verification, and debugging

## Using the Prover SDK

The AWS Nitro Enclave Attestation Prover provides a comprehensive SDK for generating zero-knowledge proofs of attestation report validity. This SDK supports both RISC0 and SP1 proving systems and can be integrated into your Rust applications.

### Installation

Add the prover to your `Cargo.toml`:

```toml
[dependencies]
aws-nitro-enclave-attestation-prover = { git = "https://github.com/automata-network/aws-nitro-enclave-attestation" }
```

### Examples

<details>
<summary>Basic Single Attestation Proof</summary>

```rust
use aws_nitro_enclave_attestation_prover::{NitroEnclaveProver, ProverConfig};

fn main() -> anyhow::Result<()> {
    // Configure the prover (RISC0 example)
    let config = ProverConfig::risc0();
    
    // Create prover instance
    let prover = NitroEnclaveProver::new(config, None);
    
    // Load attestation report
    let report_bytes = std::fs::read("samples/attestation_1.report")?;
    
    // Generate proof
    let result = prover.prove_attestation_report(report_bytes)?;
    
    // Save proof result
    std::fs::write("proof.json", result.encode_json()?)?;
    
    println!("Proof generated successfully!");
    println!("{}", String::from_utf8_lossy(&result.encode_json()?));
    
    Ok(())
}
```

</details>

<details>
<summary>Batch Proving with Aggregation</summary>

```rust
use aws_nitro_enclave_attestation_prover::{NitroEnclaveProver, ProverConfig};

fn prove_multiple_reports() -> anyhow::Result<()> {
    let config = ProverConfig::sp1();
    let prover = NitroEnclaveProver::new(config, None);
    
    // Load multiple attestation reports
    let reports = vec![
        std::fs::read("samples/attestation_1.report")?,
        std::fs::read("samples/attestation_2.report")?,
    ];
    
    // Generate aggregated proof for all reports
    let reports_count = reports.len();
    let result = prover.prove_multiple_reports(reports)?;
    
    println!("Aggregated proof generated for {} reports", reports_count);
    println!("{}", String::from_utf8_lossy(&result.encode_json()?));
    
    Ok(())
}
```
</details>

<details>
<summary>Smart Contract Integration</summary>

For optimal gas efficiency, integrate with the Nitro Enclave Verifier contract:

```rust
use aws_nitro_enclave_attestation_prover::{
    NitroEnclaveProver, ProverConfig,
    NitroEnclaveVerifierContract
};
use alloy_primitives::Address;

async fn prove_with_contract() -> anyhow::Result<()> {
    // Connect to deployed verifier contract
    let contract_address: Address = "0x1234567890123456789012345678901234567890".parse()?;
    let rpc_url = "https://1rpc.io/holesky";
    let verifier = NitroEnclaveVerifierContract::dial(rpc_url, contract_address, None)?;
    let config = ProverConfig::risc0();
    let prover = NitroEnclaveProver::new(config, Some(verifier));
    
    let report_bytes = std::fs::read("samples/attestation_2.report")?;
    
    // Prove with contract optimization
    let result = prover.prove_attestation_report(report_bytes)?;
    
    // The result.onchain_proof is ready for contract submission
    std::fs::write("proof.json", result.encode_json()?)?;
    
    println!("Aggregation Proof generated successfully!");
    println!("{}", String::from_utf8_lossy(&result.encode_json()?));
    let result = prover.verify_on_chain(&result)?;
    println!("onchain verfication result: {:?}", result);
    
    Ok(())
}
```
</details>

## Getting Started with CLI Tools

### Prerequisites

Ensure you have the following installed:
- [Rust](https://rustup.rs/) (latest stable version)
- [Foundry](https://getfoundry.sh/) for smart contract development

### Generate Zero-Knowledge Proofs

Generate proofs for single or multiple attestation reports:

```bash
$ export VERIFIER=$(NitroEnclaveVerifier address) RPC_URL=http://localhost:8545

# Generate proof using SP1 backend
$ cargo run prove --sp1 --report samples/attestation_1.report --out proof.json

# Generate proof using RISC0 backend  
$ cargo run prove --risc0 --report samples/attestation_1.report --out proof.json

# Batch verification with multiple reports
$ cargo run prove --sp1 --report samples/attestation_1.report --report samples/attestation_2.report --out aggregated_proof.json

# Verify proof on-chain
$ cargo run proof verify-on-chain --proof aggregated_proof.json
```

### Inspect Attestation Reports

Examine the contents of attestation reports for debugging and verification:

```bash
$ cargo run debug doc --report samples/attestation_1.report
```

**Example Output:**
```
Doc:
    Module ID: i-07fd4cc4df935eab0-enc01915a74e6ed4aa6
    Timestamp: Aug 16 09:11:49 2024 +00:00(1723799509)
    Digest: SHA384
    PublicKey: 0x5075626c69634b657928343032626137353561336335346339653737643937656233663035663562383232373732326666383631653465633537623137356634636263656135613463343534643437613863316637386466343931373533623931346231313738333335636334326435653332666337323864393932613064333337333662633137336529
    UserData: 0x4175746f6d617461204d50432044656d6f
    Nonce: 0x31323334
    PCR[3]: 0xb0c424e9f3727f78f370d4332f3e6e2bb02a288d9bc3c4697102d70744de0b064366fbb3190402deeb4d144e4ab17d4f
    PCR[4]: 0xdcd9866c46ee2878f5fd80f955c12a8c11de276346846579d0d077933757988144c96dc4c5fb708c20c04a4ee34639ab
Cert Chain:
    [0] Digest: 0x641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
        Valid: Oct 28 13:28:05 2019 +00:00(1572269285) - Oct 28 14:28:05 2049 +00:00(2519044085)
    [1] Digest: 0x348cc5b001ba75f7d3733ef512463194fea6781954fd416455699d4deb361acf
        Valid: Aug 15 03:20:59 2024 +00:00(1723692059) - Sep  4 04:20:59 2024 +00:00(1725423659)
    [2] Digest: 0x3792fe9068de61899676dfb2f31bf64a72439cf4883d3216629d3404b727c58d
        Valid: Aug 16 00:33:37 2024 +00:00(1723768417) - Aug 21 13:33:37 2024 +00:00(1724247217)
    [3] Digest: 0xb3b18683c518f2c462cd0252034e6a4758c42907add1880bd29a5e0a79aed71b
        Valid: Aug 16 09:11:11 2024 +00:00(1723799471) - Aug 17 09:11:11 2024 +00:00(1723885871)
    [4] Digest: 0x30941d6b61e8cd57b80a6da3705ec072adaa8acb514fbfd9b54ce3393a257e4f
        Valid: Aug 16 09:11:46 2024 +00:00(1723799506) - Aug 16 12:11:49 2024 +00:00(1723810309)
```

## Getting Started with On-Chain Verification

The NitroEnclaveVerifier smart contract provides efficient on-chain verification of zero-knowledge proofs generated by the SDK. It supports both single and batch verification modes with advanced certificate caching optimization.

### Contract Deployment

Deploy the verifier contract to your target network:

```bash
$ cd contracts

# Deploy the NitroEnclaveVerifier
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'deployVerifier()'

# Deploy the SP1Verifier
# If you want to use the official pre-deployed contract, please refer to https://github.com/succinctlabs/sp1-contracts/blob/main/contracts/deployments/
# and export SP1_VERIFIER=$sp1VerifierAddr
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'deploySP1Verifier()'

# Deploy the Risc0Verifier
# If you want to use the official pre-deployed contract, please refer to https://github.com/risc0/risc0-ethereum/blob/main/contracts/deployment.toml
# and export RISC0_VERIFIER=$risc0VerifierAddr
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'deployRisc0Verifier()'
```

The contract deployment information will be saved in the deployments folder.

### Contract Configuration

Configure the verifier contract with appropriate settings:

```bash
# set the root cert (required)
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'setRootCert(string)' ../samples/aws_root.der

# set the zk verifier
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'setZkVerifier(string)' ../samples/proof_sp1_aggregator_1.json # sp1
$ forge script script/NitroEnclaveVerifier.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --sig 'setZkVerifier(string)' ../samples/proof_risc0_aggregator_1.json # risc0
```

## Generating Attestation Reports

This repository does not include the attestation report generation functionality. Please refer to the following resources:

* [aws-nitro-enclaves-sdk-c](https://github.com/aws/aws-nitro-enclaves-sdk-c)
* [Cryptographic attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)

## Development

### Building Smart Contracts

We use [Foundry](https://getfoundry.sh/) for smart contract development. If you don't have it installed, please follow the [installation guide](https://getfoundry.sh/introduction/installation).

```bash
# Initialize and update submodules
$ git submodule update --init --recursive

# Navigate to contracts directory and build
$ cd contracts
$ forge build
```

### Project Structure

```
├── samples/               # Sample attestation reports and proofs
├── contracts/              # Smart contracts for on-chain verification
│   ├── src/
│   │   ├── NitroEnclaveVerifier.sol     # Main verifier contract
│   │   └── interfaces/
│   │       └── INitroEnclaveVerifier.sol # Contract interface
│   ├── script/             # Deployment scripts
│   ├── test/               # Contract tests
│   └── lib/                # Contract dependencies
└── crates/                 # Rust workspace crates
     ├── nitro-attest-cli/  # CLI application
     ├── prover/            # Proof generation logic
     ├── verifier/          # Verification utilities
     ├── risc0-methods/     # RISC0-specific methods
     └── sp1-methods/       # SP1-specific methods
```

## Performance Benchmarks

This section provides comprehensive performance metrics for both RISC0 and SP1 proving systems, demonstrating the efficiency gains from certificate caching and batch verification.

> [!NOTE]
> Proving a single Nitro Enclave attestation report requires approximately 300M cycles, primarily due to the need to verify certificate chains and document correctness through 6 P384 signature verifications, which constitute the majority of the computational overhead. To reduce ZKP proving costs, we have implemented caching at the contract level, which can reduce P384 signature verifications for a single report to as few as 1 verification. This caching system ensures security while supporting revocation operations - when a certificate is revoked, all related leaf certificate caches are invalidated. The caching system only optimizes certificate chain relationship verification; individual certificate validation (such as time validity) is still performed. The specific optimization results are shown below.

### Proving Cycles by Cached Certificate Count

The following table shows how certificate caching reduces computational overhead. When more certificates are cached (trusted certs prefix length), fewer certificates need to be verified in the ZK circuit, resulting in lower cycle counts:

#### RISC0

| Cached Certificates | Proving Cycles | Cycles Improvement |
| ------------------- | -------------- | ------------------ |
| 0 (cache disabled)  | 390,594,560    | Baseline           |
| 1                   | 326,107,136    | 16.5% reduction    |
| 2                   | 261,095,424    | 33.2% reduction    |
| 3                   | 196,083,712    | 49.8% reduction    |
| 4                   | 131,072,000    | 66.4% reduction    |
| 5                   | 66,060,288     | 83.1% reduction    |

#### SP1 (Succinct)
| Cached Certificates | Proving Cycles | Cycles Improvement |
| ------------------- | -------------- | ------------------ |
| 0 (cache disabled)  | 285,573,454    | Baseline           |
| 1                   | 238,129,471    | 16.6% reduction    |
| 2                   | 190,785,832    | 33.2% reduction    |
| 3                   | 143,767,478    | 49.7% reduction    |
| 4                   | 96,838,778     | 66.1% reduction    |
| 5                   | 49,534,287     | 82.6% reduction    |

### Proving Cycles for Proof Aggregation

The following table shows the additional cycles used for aggregation.

#### Risc0
| Aggregated Reports | Proving Cycles | Proving Cycles per Report | Cycles Improvement |
| ------------------ | -------------- | ------------------------- | ------------------ |
| 1                  | 131,072        | 131,072                   | Baseline           |
| 2                  | 131,072        | 65,536                    | 50.0% reduction    |
| 5                  | 262,144        | 52,428.8                  | 60.0% reduction    |
| 10                 | 524,288        | 52,428.8                  | 60.0% reduction    |
| 100                | 3,407,872      | 34,078.7                  | 74.0% reduction    |

#### Succinct
| Aggregated Reports | Proving Cycles | Proving Cycles per Report | Cycles Improvement |
| ------------------ | -------------- | ------------------------- | ------------------ |
| 1                  | 1,368,769      | 1,368,769                 | Baseline           |
| 2                  | 1,738,923      | 869,461                   | 36.5% reduction    |
| 5                  | 2,884,700      | 576,940                   | 57.8% reduction    |
| 10                 | 4,830,986      | 483,098                   | 64.7% reduction    |
| 100                | 34,680,156     | 346,801                   | 74.7% reduction    |

### On-Chain Verification Gas Costs

Gas costs for verifying attestation proofs on Ethereum mainnet (as of block 21,000,000):

#### Single Attestation Verification

| Backend | Verification Gas |
| ------- | ---------------- |
| RISC0   | 257,741          |
| SP1     | 220,333          |

#### Batch Verification Gas Costs

Batch verification provides significant gas savings compared to individual verifications:

| Attestations | RISC0 Total Gas | SP1 Total Gas |
| ------------ | --------------- | ------------- |
| 1            | 259,482         | 234,098       |
| 2            | 260,376         | 235,218       |
| 5            | 306,731         | 282,276       |
| 10           | 384,552         | 361,372       |

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For questions and support, please open an issue in the GitHub repository.
