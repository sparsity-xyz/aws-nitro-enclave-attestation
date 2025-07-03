use aws_nitro_enclave_attestation_verifier::stub::{BatchVerifierInput, BatchVerifierJournal};
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let input = {
        let mut input = Vec::<u8>::new();
        env::stdin().read_to_end(&mut input).unwrap();
        BatchVerifierInput::decode(&input).expect("Failed to decode BatchVerifierInput")
    };

    for output in &input.outputs {
        env::verify(input.verifierVk.0.clone(), &output.encode()).unwrap();
    }

    let journal = BatchVerifierJournal {
        verifierVk: input.verifierVk,
        outputs: input.outputs,
    };

    // write public output to the journal
    env::commit_slice(&journal.encode());
}
