// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A lightweight Sui network handle that connects to an already-running node
//! (e.g. devnet, testnet). Unlike [`crate::SuiNetworkHandle`], this does NOT
//! spawn or manage the Sui process.

use anyhow::Context;
use anyhow::Result;
use std::collections::BTreeMap;
use std::path::Path;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Argument;
use sui_sdk_types::GasPayment;
use sui_sdk_types::Input;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::StructTag;
use sui_sdk_types::Transaction;
use sui_sdk_types::TransactionExpiration;
use sui_sdk_types::TransactionKind;
use sui_sdk_types::TransferObjects;
use sui_sdk_types::bcs::ToBcs;
use tracing::info;

use crate::hashi_network::SuiNetworkInfo;
use crate::sui_network::keypair_from_base64;

pub struct ExternalSuiNetwork {
    rpc_url: String,
    client: Client,
    operator_key: Ed25519PrivateKey,
    validator_keys: BTreeMap<Address, Ed25519PrivateKey>,
}

impl ExternalSuiNetwork {
    /// Connect to an already-running Sui network, generate validator keys, and fund them.
    ///
    /// # Arguments
    /// - `rpc_url`: Sui RPC URL (e.g. `https://fullnode.devnet.sui.io:443`)
    /// - `operator_key`: Ed25519 key with sufficient SUI balance for funding validators
    /// - `num_validators`: Number of validator keypairs to generate and fund
    pub async fn new(
        rpc_url: &str,
        operator_key: Ed25519PrivateKey,
        num_validators: usize,
    ) -> Result<Self> {
        let mut client = Client::new(rpc_url)?;

        crate::sui_network::wait_for_ready(&mut client)
            .await
            .with_context(|| {
                format!(
                    "Failed to connect to Sui network at {}. Ensure the node is reachable.",
                    rpc_url
                )
            })?;

        let operator_addr = operator_key.public_key().derive_address();
        info!(
            "Connected to external Sui network at {}, operator: {}",
            rpc_url, operator_addr
        );

        // Generate fresh Ed25519 keypairs for hashi validator identities
        let mut validator_keys = BTreeMap::new();
        for _ in 0..num_validators {
            let seed: [u8; 32] = rand::random();
            let key = Ed25519PrivateKey::new(seed);
            let addr = key.public_key().derive_address();
            validator_keys.insert(addr, key);
        }

        let mut network = Self {
            rpc_url: rpc_url.to_string(),
            client,
            operator_key,
            validator_keys,
        };

        // Fund validator accounts from operator.
        // External networks have limited funds, so use 5 SUI per validator
        // (enough for registration + gas during operations).
        let fund_requests: Vec<(Address, u64)> = network
            .validator_keys
            .keys()
            .map(|addr| (*addr, 5 * 1_000_000_000))
            .collect();
        network.fund(&fund_requests).await?;

        Ok(network)
    }

    /// Load an Ed25519 private key from a Sui keystore file by address.
    ///
    /// The keystore file is a JSON array of base64-encoded keys, each prefixed
    /// with a scheme byte (as written by `sui keytool import`).
    pub fn load_key_from_keystore(
        keystore_path: &Path,
        target_address: &Address,
    ) -> Result<Ed25519PrivateKey> {
        let contents = std::fs::read_to_string(keystore_path)
            .with_context(|| format!("Failed to read keystore at {}", keystore_path.display()))?;
        let keys: Vec<String> = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse keystore at {}", keystore_path.display()))?;

        for b64_key in &keys {
            if let Ok(key) = keypair_from_base64(b64_key) {
                let addr = key.public_key().derive_address();
                if addr == *target_address {
                    return Ok(key);
                }
            }
        }

        anyhow::bail!(
            "No Ed25519 key found for address {} in keystore at {}",
            target_address,
            keystore_path.display()
        )
    }

    /// Fund Sui addresses from the operator account.
    pub async fn fund(&mut self, requests: &[(Address, u64)]) -> Result<()> {
        let sender = self.operator_key.public_key().derive_address();
        let price = self.client.get_reference_gas_price().await?;

        let gas_objects = self
            .client
            .select_coins(
                &sender,
                &StructTag::sui().into(),
                requests.iter().map(|r| r.1).sum(),
                &[],
            )
            .await?;

        let (inputs, transfers): (Vec<Input>, Vec<sui_sdk_types::Command>) = requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                (
                    Input::Pure(request.0.to_bcs().unwrap()),
                    sui_sdk_types::Command::TransferObjects(TransferObjects {
                        objects: vec![Argument::NestedResult(0, i as u16)],
                        address: Argument::Input(i as u16),
                    }),
                )
            })
            .unzip();

        let (input_amounts, argument_amounts) = requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                (
                    Input::Pure(request.1.to_bcs().unwrap()),
                    Argument::Input((i + inputs.len()) as u16),
                )
            })
            .unzip();

        let pt = ProgrammableTransaction {
            inputs: [inputs, input_amounts].concat(),
            commands: [
                vec![sui_sdk_types::Command::SplitCoins(
                    sui_sdk_types::SplitCoins {
                        coin: Argument::Gas,
                        amounts: argument_amounts,
                    },
                )],
                transfers,
            ]
            .concat(),
        };

        let gas_payment_objects = gas_objects
            .iter()
            .map(|o| -> anyhow::Result<_> { Ok((&o.object_reference()).try_into()?) })
            .collect::<Result<Vec<_>>>()?;

        let transaction = Transaction {
            kind: TransactionKind::ProgrammableTransaction(pt),
            sender,
            gas_payment: GasPayment {
                objects: gas_payment_objects,
                owner: sender,
                price,
                budget: 1_000_000_000,
            },
            expiration: TransactionExpiration::None,
        };

        let signature = self.operator_key.sign_transaction(&transaction)?;

        let response = self
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                std::time::Duration::from_secs(10),
            )
            .await?
            .into_inner();

        anyhow::ensure!(
            response.transaction().effects().status().success(),
            "fund failed"
        );

        info!("Funded {} validator accounts from operator", requests.len());
        Ok(())
    }

    /// Write a minimal `client.yaml` + keystore so `sui move build` can resolve
    /// framework dependencies. Call this before publishing.
    pub fn write_sui_config(&self, sui_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(sui_dir)?;

        // Write a minimal keystore (empty array is valid)
        let keystore_path = sui_dir.join("sui.keystore");
        std::fs::write(&keystore_path, "[]")?;

        // Write client.yaml pointing to our RPC
        let client_yaml = format!(
            "---\nkeystore:\n  File: {keystore}\nenvs:\n  - alias: external\n    rpc: \"{rpc}\"\n    ws: ~\nactive_env: external\nactive_address: \"{addr}\"\n",
            keystore = keystore_path.display(),
            rpc = self.rpc_url,
            addr = self.operator_key.public_key().derive_address(),
        );
        std::fs::write(sui_dir.join("client.yaml"), client_yaml)?;

        Ok(())
    }
}

impl SuiNetworkInfo for ExternalSuiNetwork {
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn client(&self) -> Client {
        self.client.clone()
    }

    fn validator_keys(&self) -> &BTreeMap<Address, Ed25519PrivateKey> {
        &self.validator_keys
    }

    fn funding_key(&self) -> &Ed25519PrivateKey {
        &self.operator_key
    }
}
