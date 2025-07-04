<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# AWS Nitro Enclave Attestation CLI
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

The CLI (Command Line Interface) tool for the AWS nitro enclave attestation verification.

## Functionality

* Generates the on-chain verifiable ZKP for the attestation report.
* Supports both Risc0 and Succinct and provides unifid user expirence.
* Supports attestation report batch verification to reduce the on-chain verification cost.
* On-chain verification contract.

## Getting Started


### Build Contracts
```
$ git submodule update --init --recursive
$ cd contracts
$ forge build
```

### Generate ZKP
```
$ cargo run prove [--sp1 or --risc0] --report samples/attestation_1.report --report samples/attestation_2.report --out aggregated_proof.json

# Verify Proof on-chain
$ cargo run proof verify-on-chain --proof aggregated_proof.json
```

### Inspect Attestation Report

```
$ cargo run debug doc --report samples/attestation_1.report
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

## Benchmark
