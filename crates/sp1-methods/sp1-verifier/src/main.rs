#![no_main]
sp1_zkvm::entrypoint!(main);

use aws_nitro_enclave_attestation_verifier::{verify_attestation_report, VerifierInput};

pub fn main() {
    let input = VerifierInput::decode(&sp1_zkvm::io::read_vec()).unwrap();

    let output = verify_attestation_report(&input).unwrap();

    sp1_zkvm::io::commit_slice(&output.encode());
}
