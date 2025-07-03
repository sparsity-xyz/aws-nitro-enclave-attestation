use alloy_primitives::{hex::FromHex, Bytes, B256};
use anyhow::anyhow;
use async_trait::async_trait;
use aws_nitro_enclave_attestation_verifier::{BatchVerifierInput, VerifierInput, VerifierJournal};
use sp1_methods::{SP1_AGGREGATOR_ELF, SP1_VERIFIER_ELF};
use sp1_sdk::{
    network::builder::NetworkProverBuilder, EnvProver, HashableKey, Prover as Sp1ProverTrait,
    SP1Proof, SP1Stdin,
};

use crate::{types::Proof, ProgramId, ProveResult, Prover, ProverConfig};

pub struct SP1Prover {
    cfg: ProverConfig,
    client: EnvProver,
}

impl SP1Prover {
    pub fn new(cfg: ProverConfig) -> Self {
        let client = EnvProver::new();
        SP1Prover { client, cfg }
    }

    fn prove(&self, elf: &[u8], aggregated: bool, stdin: SP1Stdin) -> anyhow::Result<Proof> {
        let (pk, _) = self.client.setup(elf);

        // Generate the proof
        let prover = self.client.prove(&pk, &stdin);
        let prover = if aggregated {
            prover.compressed()
        } else {
            prover.groth16()
        };
        let proof = prover.run()?;

        Ok(Proof::from_proof(
            &proof.proof,
            proof.public_values.to_vec().into(),
        )?)
    }
}

#[async_trait]
impl Prover for SP1Prover {
    fn zkvm_info(&self) -> String {
        format!("sp1/{}", sp1_sdk::SP1_CIRCUIT_VERSION)
    }

    fn decode_proof(&self, proof: &Proof) -> anyhow::Result<Bytes> {
        let sp1_proof = proof.decode_proof::<SP1Proof>()?;
        Ok(match sp1_proof {
            SP1Proof::Groth16(groth16_proof) => {
                if groth16_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&groth16_proof.encoded_proof)?;
                let proof: Bytes = [
                    groth16_proof.groth16_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into();
                proof
            }
            SP1Proof::Plonk(plonk_proof) => {
                if plonk_proof.encoded_proof.is_empty() {
                    return Ok(Bytes::new());
                }
                let proof_bytes = Bytes::from_hex(&plonk_proof.encoded_proof)?;
                let proof: Bytes = [
                    plonk_proof.plonk_vkey_hash[..4].to_vec(),
                    proof_bytes.to_vec(),
                ]
                .concat()
                .into();
                proof
            }
            SP1Proof::Compressed(_) | SP1Proof::Core(_) => Bytes::new(),
        })
    }

    fn program_id(&self) -> ProgramId {
        let (_, verifier_vk) = self.client.setup(SP1_VERIFIER_ELF);
        let (_, aggregator_vk) = self.client.setup(SP1_AGGREGATOR_ELF);
        ProgramId {
            verifier_id: verifier_vk.bytes32_raw().into(),
            verifier_proof_id: B256::new(unsafe { std::mem::transmute(verifier_vk.hash_u32()) }),
            aggregator_id: aggregator_vk.bytes32_raw().into(),
        }
    }

    fn prove_aggregated_proofs(&self, proofs: Vec<Proof>) -> anyhow::Result<ProveResult> {
        let mut journals = Vec::with_capacity(proofs.len());
        for item in &proofs {
            let decoded = item.decode_journal::<VerifierJournal>()?;
            journals.push(decoded);
        }

        let (_, verifier_vk) = self.client.setup(SP1_VERIFIER_ELF);
        let verifier_vk_digest = B256::new(unsafe { std::mem::transmute(verifier_vk.hash_u32()) });

        let batch_input = BatchVerifierInput {
            verifier_vk: verifier_vk_digest,
            outputs: journals,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(batch_input.encode());
        for item in &proofs {
            let proof = item.decode_proof::<SP1Proof>()?;
            let SP1Proof::Compressed(proof) = proof else {
                return Err(anyhow!("Expected a compressed SP1 proof"));
            };
            stdin.write_proof(*proof, verifier_vk.vk.clone());
        }

        let proof = self.prove(SP1_AGGREGATOR_ELF, false, stdin)?;

        Ok(self.build_result(proof)?)
    }

    fn prove_partial(&self, input: &VerifierInput) -> anyhow::Result<ProveResult> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.encode());
        Ok(self.build_result(self.prove(SP1_VERIFIER_ELF, true, stdin)?)?)
    }

    fn prove_single(&self, input: &VerifierInput) -> anyhow::Result<ProveResult> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input.encode());
        Ok(self.build_result(self.prove(SP1_VERIFIER_ELF, false, stdin)?)?)
    }

    async fn upload_image(&self) -> anyhow::Result<ProgramId> {
        let mut builder = NetworkProverBuilder::default();
        if let Some(key) = &self.cfg.sp1_private_key {
            builder = builder.private_key(&key);
        }
        if let Some(rpc_url) = &self.cfg.sp1_rpc_url {
            builder = builder.rpc_url(&rpc_url);
        }
        let prover = builder.build();
        let (_, verifier_vk) = prover.setup(SP1_VERIFIER_ELF);
        prover
            .register_program(&verifier_vk, SP1_VERIFIER_ELF)
            .await?;
        let (_, aggregator_vk) = prover.setup(SP1_AGGREGATOR_ELF);
        prover
            .register_program(&aggregator_vk, SP1_AGGREGATOR_ELF)
            .await?;
        Ok(self.program_id())
    }
}
