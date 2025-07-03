use std::sync::Arc;

use alloy_network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::{PendingTransactionBuilder, Provider, ProviderBuilder};
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use anyhow::anyhow;

use crate::ZkType;

pub struct NitroEnclaveVerifier {
    contract: Address,
    client: Arc<Box<dyn Provider>>,
}

impl NitroEnclaveVerifier {
    pub fn dial(
        endpoint: &str,
        contract: Address,
        private_key: Option<&str>,
    ) -> anyhow::Result<Self> {
        let url = endpoint.try_into()?;

        let provider: Box<dyn Provider> = match private_key {
            Some(pk) => {
                let signer = pk.parse::<PrivateKeySigner>()?;
                let wallet = EthereumWallet::new(signer);
                let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);
                Box::new(provider)
            }
            None => {
                let provider = ProviderBuilder::new().connect_http(url);
                Box::new(provider)
            }
        };

        Ok(Self {
            contract,
            client: Arc::new(provider),
        })
    }

    pub async fn call<T: SolCall>(&self, call: &T) -> anyhow::Result<T::Return> {
        let tx = TransactionRequest::default()
            .with_call(call)
            .to(self.contract);
        let result = self.client.call(tx).await?;
        let result = T::abi_decode_returns(&result)?;
        Ok(result)
    }

    pub async fn transact<T: SolCall>(
        &self,
        call: &T,
    ) -> anyhow::Result<PendingTransactionBuilder<Ethereum>> {
        let tx = TransactionRequest::default()
            .with_call(call)
            .to(self.contract);
        let result = self.client.send_transaction(tx).await?;
        Ok(result)
    }

    pub async fn verify(
        &self,
        zk: ZkType,
        proof: Bytes,
        journal: Bytes,
    ) -> anyhow::Result<PendingTransactionBuilder<Ethereum>> {
        use aws_nitro_enclave_attestation_verifier::stub::*;
        let call = verifyCall {
            output: journal,
            zkCoprocessor: (zk as u8).into(),
            proofBytes: proof,
        };
        let result = self.transact(&call).await?;
        Ok(result)
    }

    pub async fn batch_verify(
        &self,
        zk: ZkType,
        proof: Bytes,
        journal: Bytes,
    ) -> anyhow::Result<PendingTransactionBuilder<Ethereum>> {
        use aws_nitro_enclave_attestation_verifier::stub::*;
        let call = batchVerifyCall {
            output: journal,
            zkCoprocessor: (zk as u8).into(),
            proofBytes: proof,
        };
        let result = self.transact(&call).await?;
        Ok(result)
    }

    pub async fn root_cert(&self) -> anyhow::Result<B256> {
        use aws_nitro_enclave_attestation_verifier::stub::*;
        Ok(self.call(&rootCertCall {}).await?)
    }

    pub async fn query_cert_cache(&self, certs: &[B256]) -> anyhow::Result<u8> {
        use aws_nitro_enclave_attestation_verifier::stub::*;
        if certs.len() > 8 {
            return Err(anyhow!("Too many certificates provided, maximum is 8"));
        }
        if certs.len() == 0 {
            return Ok(0);
        }

        let root_cert = self.root_cert().await?;
        if root_cert != certs[0] {
            return Err(anyhow!(
                "Root certificate does not match the first provided certificate"
            ));
        }

        let mut trusted_len = 1;

        let calls = certs
            .iter()
            .skip(1)
            .map(|cert| trustedIntermediateCertsCall {
                trustedCertHash: *cert,
            })
            .collect::<Vec<_>>();
        for call in calls {
            let trusted = self.call(&call).await?;
            if trusted {
                trusted_len += 1;
            } else {
                break;
            }
        }
        Ok(trusted_len)
    }
}
