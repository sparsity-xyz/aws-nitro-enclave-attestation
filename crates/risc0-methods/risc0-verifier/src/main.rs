use aws_nitro_enclave_attestation_verifier::{stub::VerifierInput, verify_attestation_report};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let input = {
        let mut input_bytes = Vec::<u8>::new();
        env::stdin().read_to_end(&mut input_bytes).unwrap();
        VerifierInput::decode(&mut input_bytes).unwrap()
    };

    let output = verify_attestation_report(&input).unwrap();

    env::commit_slice(&output.encode());
}
