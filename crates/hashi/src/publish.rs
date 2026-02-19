//! Build and publish the Hashi Move package.
//!
//! Provides a reusable [`build_package`] + [`publish_and_init`] workflow that can be called
//! from both the CLI and integration tests.

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

use crate::config::HashiIds;

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

    cmd.arg("--dump-bytecode-as-base64");

    let output = cmd.output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "sui move build failed\nstdout: {}\nstderr: {}",
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

/// Publish the compiled package and run post-publish initialization.
///
/// Executes two transactions:
///
/// 1. **Publish** – publishes the modules, transfers the `UpgradeCap` to the sender.
/// 2. **Init** – calls `hashi::register_btc` and `hashi::register_upgrade_cap`.
///
/// Returns the [`HashiIds`] (package ID + Hashi shared-object ID) on success.
pub async fn publish_and_init(
    client: &mut Client,
    signer: &Ed25519PrivateKey,
    publish: sui_sdk_types::Publish,
) -> Result<HashiIds> {
    let sender = signer.public_key().derive_address();

    // ── Transaction 1: Publish ──────────────────────────────────────────
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

    println!("package: {package_id}");

    // ── Transaction 2: Init (register BTC + upgrade cap) ────────────────
    let mut builder = TransactionBuilder::new();
    builder.set_sender(sender);

    let hashi_arg = builder.object(
        ObjectInput::new(hashi_object_id)
            .as_shared()
            .with_mutable(true),
    );
    let coin_registry_arg = builder.object(
        ObjectInput::new(COIN_REGISTRY_OBJECT_ID)
            .as_shared()
            .with_mutable(true),
    );
    let upgrade_cap_arg = builder.object(ObjectInput::new(upgrade_cap_id).as_owned());

    builder.move_call(
        Function::new(
            package_id,
            Identifier::from_static("hashi"),
            Identifier::from_static("register_btc"),
        ),
        vec![hashi_arg, coin_registry_arg],
    );
    builder.move_call(
        Function::new(
            package_id,
            Identifier::from_static("hashi"),
            Identifier::from_static("register_upgrade_cap"),
        ),
        vec![hashi_arg, upgrade_cap_arg],
    );

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
        "init transaction failed (register_btc / register_upgrade_cap)"
    );

    Ok(HashiIds {
        package_id,
        hashi_object_id,
    })
}
