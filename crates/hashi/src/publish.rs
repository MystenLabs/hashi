// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Build, publish, and launch the Hashi Move package.
//!
//! Provides a reusable [`build_package`] + [`publish_package`] +
//! [`finish_publish`] workflow that can be called from both the CLI and
//! integration tests. [`finish_publish`] is deferred to launch time: it is
//! the switch that unlocks genesis.

use std::path::Path;
use std::process::Command;
use std::str::FromStr;

use anyhow::Result;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_transaction_builder::Function;
use sui_transaction_builder::ObjectInput;
use sui_transaction_builder::TransactionBuilder;

use crate::btc_monitor::config::BlockHash;
use crate::btc_monitor::config::network_from_chain_id;
use crate::config::HashiIds;
use bitcoin::hashes::Hash as _;

/// Well-known Sui CoinRegistry shared object address (0xc).
const COIN_REGISTRY_OBJECT_ID: Address = Address::from_static("0xc");

/// Parameters for building a Move package.
pub struct BuildParams<'a> {
    /// Path to the `sui` CLI binary.
    pub sui_binary: &'a Path,
    /// Path to the Move package directory.
    pub package_path: &'a Path,
    /// Optional path to a `sui client.yaml` for dependency resolution.
    pub client_config: Option<&'a Path>,
    /// Network environment for the build (`"testnet"`, `"mainnet"`, etc.).
    pub environment: Option<&'a str>,
}

/// JSON output produced by `sui move build --dump-bytecode-as-base64`.
#[derive(serde::Deserialize)]
struct MoveBuildOutput {
    modules: Vec<String>,
    dependencies: Vec<Address>,
    digest: Vec<u8>,
}

/// Build a Move package and return the compiled [`sui_sdk_types::Publish`] payload.
///
/// Shells out to `sui move build --dump-bytecode-as-base64`, parses the JSON
/// output, and decodes the base64-encoded module bytecodes.
pub fn build_package(params: &BuildParams<'_>) -> Result<sui_sdk_types::Publish> {
    let mut cmd = Command::new(params.sui_binary);
    cmd.arg("move");

    if let Some(config) = params.client_config {
        cmd.arg("--client.config").arg(config);
    }

    cmd.arg("-p").arg(params.package_path).arg("build");

    if let Some(env) = params.environment {
        cmd.args(["-e", env]);
    }

    // --no-tree-shaking: avoid the RPC call newer sui CLI makes during
    // --dump-bytecode-as-base64; required for offline builds (CI, e2e).
    cmd.arg("--dump-bytecode-as-base64")
        .arg("--no-tree-shaking");

    let output = cmd.output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "sui move build failed
stdout: {}
stderr: {}",
            output.stdout.escape_ascii(),
            output.stderr.escape_ascii()
        ));
    }

    let build_output: MoveBuildOutput = serde_json::from_slice(&output.stdout)?;
    let modules = build_output
        .modules
        .into_iter()
        .map(|b64| <base64ct::Base64 as base64ct::Encoding>::decode_vec(&b64))
        .collect::<Result<Vec<_>, _>>()?;
    let _digest = sui_sdk_types::Digest::from_bytes(build_output.digest)?;

    Ok(sui_sdk_types::Publish {
        modules,
        dependencies: build_output.dependencies,
    })
}

/// Guardian configuration for post-publish initialization. Required —
/// every deposit address is a 2-of-2 (mpc, guardian) taproot leaf, so a
/// guardian-less deploy can't produce spendable deposits.
pub struct GuardianConfig {
    pub url: String,
    /// X-only BTC pubkey of the enclave (32 bytes).
    pub btc_public_key: Vec<u8>,
}

/// Optional Bitcoin config overrides applied during `finish_publish`. Any
/// `None` field falls back to the Move package's `init_defaults` value.
#[derive(Default)]
pub struct BitcoinConfigOverrides {
    pub confirmation_threshold: Option<u64>,
    pub deposit_time_delay_ms: Option<u64>,
}

/// Result of [`publish_package`].
pub struct PublishOutput {
    pub ids: HashiIds,
    /// `UpgradeCap` object id, left in the publisher's wallet until
    /// [`finish_publish`] (the launch switch) is sent.
    pub upgrade_cap_id: Address,
}

/// Publish the compiled package. The `UpgradeCap` is transferred to the
/// sender, where it stays through the validator-registration window;
/// genesis is unlocked later by handing it in via [`finish_publish`].
pub async fn publish_package(
    client: &mut Client,
    signer: &Ed25519PrivateKey,
    publish: sui_sdk_types::Publish,
) -> Result<PublishOutput> {
    let sender = signer.public_key().derive_address();

    // ── Transaction: Publish ────────────────────────────────────────────
    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);

    let upgrade_cap = builder.publish(publish.modules, publish.dependencies);
    let sender_arg = builder.pure(&sender);
    builder.transfer_objects(vec![upgrade_cap], sender_arg);

    let transaction = builder.build(client).await?;
    let signature = signer.sign_transaction(&transaction)?;

    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(30),
        )
        .await?
        .into_inner();

    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "publish transaction failed"
    );

    // Extract IDs from effects ────────────────────────────────────────────

    let package_id = response
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == "package")
        .ok_or_else(|| anyhow::anyhow!("package not found in publish effects"))?
        .object_id()
        .parse::<Address>()?;

    let hashi_type = StructTag::new(
        package_id,
        Identifier::from_static("hashi"),
        Identifier::from_static("Hashi"),
        vec![],
    )
    .to_string();

    let hashi_object_id = response
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == hashi_type)
        .ok_or_else(|| anyhow::anyhow!("Hashi shared object not found in publish effects"))?
        .object_id()
        .parse::<Address>()?;

    let upgrade_cap_type = StructTag::from_str("0x2::package::UpgradeCap")?.to_string();
    let upgrade_cap_id = response
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == upgrade_cap_type)
        .ok_or_else(|| anyhow::anyhow!("UpgradeCap not found in publish effects"))?
        .object_id()
        .parse::<Address>()?;

    Ok(PublishOutput {
        ids: HashiIds {
            package_id,
            hashi_object_id,
        },
        upgrade_cap_id,
    })
}

/// Build the unsigned `hashi::finish_publish` transaction (the launch
/// switch). Exposed separately from [`finish_publish`] for offline /
/// multisig signing.
pub async fn build_finish_publish_tx(
    client: &mut Client,
    sender: Address,
    ids: &HashiIds,
    upgrade_cap_id: Address,
    bitcoin_chain_id: &str,
    guardian: &GuardianConfig,
    bitcoin_overrides: &BitcoinConfigOverrides,
) -> Result<sui_sdk_types::Transaction> {
    // Validate and convert bitcoin_chain_id to a Move-compatible address.
    anyhow::ensure!(
        network_from_chain_id(bitcoin_chain_id).is_some(),
        "unrecognized bitcoin chain id: {bitcoin_chain_id}"
    );
    let block_hash = BlockHash::from_str(bitcoin_chain_id)?;
    let bitcoin_chain_id_addr = Address::new(*block_hash.as_byte_array());

    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);

    let hashi_arg = builder.object(
        ObjectInput::new(ids.hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let upgrade_cap_arg = builder.object(ObjectInput::new(upgrade_cap_id).as_owned());
    let bitcoin_chain_id_arg = builder.pure(&bitcoin_chain_id_addr);
    let guardian_url_arg = builder.pure(&guardian.url.as_str());
    let guardian_btc_public_key_arg = builder.pure(&guardian.btc_public_key.as_slice());
    let confirmation_threshold_arg = builder.pure(&bitcoin_overrides.confirmation_threshold);
    let deposit_time_delay_ms_arg = builder.pure(&bitcoin_overrides.deposit_time_delay_ms);
    let coin_registry_arg = builder.object(
        ObjectInput::new(COIN_REGISTRY_OBJECT_ID)
            .as_shared()
            .with_mutable(true),
    );

    builder.move_call(
        Function::new(
            ids.package_id,
            Identifier::from_static("hashi"),
            Identifier::from_static("finish_publish"),
        ),
        vec![
            hashi_arg,
            upgrade_cap_arg,
            bitcoin_chain_id_arg,
            guardian_url_arg,
            guardian_btc_public_key_arg,
            confirmation_threshold_arg,
            deposit_time_delay_ms_arg,
            coin_registry_arg,
        ],
    );

    Ok(builder.build(client).await?)
}

/// Send `hashi::finish_publish` — the launch switch. Finalizes the deploy
/// parameters (chain id, guardian, overrides) and hands the `UpgradeCap`
/// into on-chain custody, which unlocks the genesis `start_reconfig`;
/// validator nodes then form the initial committee from whoever is
/// registered, so only call this once all expected validators have fully
/// registered.
pub async fn finish_publish(
    client: &mut Client,
    signer: &Ed25519PrivateKey,
    ids: &HashiIds,
    upgrade_cap_id: Address,
    bitcoin_chain_id: &str,
    guardian: &GuardianConfig,
    bitcoin_overrides: &BitcoinConfigOverrides,
) -> Result<()> {
    let sender = signer.public_key().derive_address();
    let transaction = build_finish_publish_tx(
        client,
        sender,
        ids,
        upgrade_cap_id,
        bitcoin_chain_id,
        guardian,
        bitcoin_overrides,
    )
    .await?;
    let signature = signer.sign_transaction(&transaction)?;

    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(30),
        )
        .await?
        .into_inner();

    anyhow::ensure!(
        response.transaction().effects().status().success(),
        "launch transaction failed (finish_publish)"
    );

    Ok(())
}
