# Nova SP1 v6 deployment

Nova's deployed SP1 v5 client is rejected by the Succinct Prover Network with
`unsupported prover version sp1-v5.0.0`. This branch merges upstream Automata
release v0.1.2 (`65c4a4233029ea3bbe16110a80731fcfd47cf300`) into the Nova fork,
then pins the host SDK/build dependencies to SP1 6.10.0 and adds local verification
of each generated SP1 proof before exporting it to the registration worker.

The merge includes upstream's other changes; only the SP1 CLI feature is enabled
in the Nova deployment build. The RISC0/Pico paths are not part of this deployment's
acceptance tests. Nova's previous fork-specific changes were release packaging.

## Build

On Ubuntu 24.04 x86_64, install Rust 1.91.1 and the native build dependencies
`build-essential pkg-config libssl-dev clang cmake protobuf-compiler`. Then:

```sh
bash scripts/build-nova-sp1.sh
```

The script uses Cargo's locked dependencies, two compile jobs by default, and the
committed upstream guest ELFs. It does not install or activate a production worker.
Host release debug information and LTO are disabled to keep builds manageable on
the 8-GiB replacement server. These host flags do not rebuild the guest ELFs or
change their measurements. The release workflow uses the same script on Ubuntu
24.04 instead of building every prover backend with unpinned toolchains.

The guest ELFs are byte-identical to the pinned upstream release:

| Guest program | SHA-256 |
|---|---|
| SP1 verifier | `5e0f43c66a46442c20d094fe3afa1a6519811e0e808da868831a9cca71593413` |
| SP1 aggregator | `2d78f8db9a232e073e6048d8c59b70c982dd0e8577beb2f6b41c7965dfce8274` |

For intentional Docker guest rebuilds, the build script pins the original SP1
`v6.1.0` compiler image and guest lockfiles. Upgrading the host SDK must not silently
select a different guest compiler. This migration checked the upstream ELF bytes;
it does not claim that a new independent Docker reproduction has already completed.

## Worker compatibility and activation

The worker's existing invocation remains:

```sh
SP1_PROVER=network nitro-attest-cli prove --sp1 --report attestation.report --out proof.json
```

Provide `NETWORK_PRIVATE_KEY` through a protected environment file or the existing
worker's Secrets Manager integration. Never pass the key in a command-line argument.
The worker consumes `onchain_proof` and `raw_proof.journal` from the JSON output.

**Do not switch binaries without matching the on-chain configuration.** Nova's
Nitro verifier currently stores v5 program IDs and points at a v5 SP1 verifier.
New program IDs and a v6 verifier are required. A real generated proof must pass
the deployed SP1 verifier and Nova's full journal checks before activation.

Nova's current Nitro verifier uses an older four-field `ZkCoProcessorConfig` ABI.
Upstream's new contract client expects a newer three-field ABI and version lookup
method. Consequently, do not use the new CLI's `--contract` option against Nova's
legacy verifier. The existing worker does not use that option. The migration's
separate read-only verifier handles the legacy ABI explicitly; a general CLI
legacy-contract adapter is outside this migration.

The isolated migration tests and owner-transaction handoff are maintained in
[Nova console migration](https://github.com/sparsity-xyz/nova-crack/tree/main/ops/console-v2) (https://github.com/sparsity-xyz/nova-crack/tree/main/ops/console-v2).
Those records identify the tested binary, proof, deployment addresses and remaining
activation steps. A successful build by itself is not end-to-end acceptance.
