use anyhow::Result;
use hashi::config::HashiIds;
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Digest;

use crate::sui_network::sui_binary;

#[derive(serde::Deserialize)]
struct MoveBuildOutput {
    modules: Vec<String>,
    dependencies: Vec<Address>,
    digest: Vec<u8>,
}

pub async fn publish(
    dir: &Path,
    client: &mut Client,
    private_key: &Ed25519PrivateKey,
) -> Result<HashiIds> {
    let publish_command = build_package(dir)?;
    let ids = publish_transaction(client, private_key, publish_command).await?;

    Ok(ids)
}

fn build_package(dir: &Path) -> Result<sui_sdk_types::Publish> {
    let client_config = dir.join("sui/client.yaml");
    let hashi_package = dir.join("packages/hashi");

    let mut cmd = Command::new(sui_binary());
    cmd.arg("move")
        .arg("--client.config")
        .arg(client_config)
        .arg("-p")
        .arg(hashi_package)
        .arg("build")
        .args(["-e", "testnet"])
        .arg("--dump-bytecode-as-base64");
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "stdout: {}\n\n stderr: {}",
            output.stdout.escape_ascii(),
            output.stderr.escape_ascii()
        ));
    }

    let move_build_output: MoveBuildOutput = serde_json::from_slice(&output.stdout)?;
    let modules = move_build_output
        .modules
        .into_iter()
        .map(|b64| <base64ct::Base64 as base64ct::Encoding>::decode_vec(&b64))
        .collect::<Result<Vec<_>, _>>()?;
    let _digest = Digest::from_bytes(move_build_output.digest)?;

    Ok(sui_sdk_types::Publish {
        modules,
        dependencies: move_build_output.dependencies,
    })
}

async fn publish_transaction(
    client: &mut Client,
    private_key: &Ed25519PrivateKey,
    publish: sui_sdk_types::Publish,
) -> Result<HashiIds> {
    use sui_sdk_types::bcs::ToBcs;
    use sui_sdk_types::*;

    let sender = private_key.public_key().derive_address();
    let price = client.get_reference_gas_price().await?;
    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;
    let gas_object = (&gas_objects[0].object_reference()).try_into()?;

    let pt = ProgrammableTransaction {
        inputs: vec![Input::Pure(sender.to_bcs()?)],
        commands: vec![
            Command::Publish(publish),
            Command::TransferObjects(TransferObjects {
                objects: vec![Argument::Result(0)],
                address: Argument::Input(0),
            }),
        ],
    };

    let publish_transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: vec![gas_object],
            owner: sender,
            price,
            budget: 1_000_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = private_key.sign_transaction(&publish_transaction)?;

    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(publish_transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(10),
        )
        .await?
        .into_inner();

    assert!(
        response.transaction().effects().status().success(),
        "publish failed"
    );

    let upgrade_cap = {
        let upgrade_cap_type = StructTag::from_str("0x2::package::UpgradeCap")?.to_string();
        let upgrade_cap = response
            .transaction()
            .effects()
            .changed_objects()
            .iter()
            .find(|o| o.object_type() == upgrade_cap_type)
            .unwrap();
        ObjectReference::new(
            upgrade_cap.object_id().parse()?,
            upgrade_cap.output_version(),
            upgrade_cap.output_digest().parse()?,
        )
    };

    let package_id = response
        .transaction()
        .effects()
        .changed_objects()
        .iter()
        .find(|o| o.object_type() == "package")
        .unwrap()
        .object_id()
        .parse::<Address>()?;

    let hashi = {
        let hashi_type = StructTag::new(
            package_id,
            Identifier::from_static("hashi"),
            Identifier::from_static("Hashi"),
            vec![],
        )
        .to_string();
        let hashi = response
            .transaction()
            .effects()
            .changed_objects()
            .iter()
            .find(|o| o.object_type() == hashi_type)
            .unwrap();
        ObjectReference::new(
            hashi.object_id().parse()?,
            hashi.output_version(),
            hashi.output_digest().parse()?,
        )
    };

    println!("package: {package_id}");

    let coin_registry = {
        let resp = client
            .ledger_client()
            .get_object(
                GetObjectRequest::new(&Address::from_static("0xc"))
                    .with_read_mask(FieldMask::from_paths(["object_id", "owner"])),
            )
            .await?
            .into_inner();

        Input::Shared(SharedInput::new(
            Address::from_static("0xc"),
            resp.object().owner().version(),
            true,
        ))
    };

    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;
    let gas_object = (&gas_objects[0].object_reference()).try_into()?;

    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Shared(SharedInput::new(*hashi.object_id(), hashi.version(), true)),
            coin_registry,
            Input::ImmutableOrOwned(upgrade_cap),
        ],
        commands: vec![
            Command::MoveCall(MoveCall {
                package: package_id,
                module: Identifier::from_static("hashi"),
                function: Identifier::from_static("register_btc"),
                type_arguments: vec![],
                arguments: vec![Argument::Input(0), Argument::Input(1)],
            }),
            Command::MoveCall(MoveCall {
                package: package_id,
                module: Identifier::from_static("hashi"),
                function: Identifier::from_static("register_upgrade_cap"),
                type_arguments: vec![],
                arguments: vec![Argument::Input(0), Argument::Input(2)],
            }),
        ],
    };

    let init_transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: vec![gas_object],
            owner: sender,
            price,
            budget: 1_000_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = private_key.sign_transaction(&init_transaction)?;

    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(init_transaction.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(10),
        )
        .await?
        .into_inner();

    assert!(
        response.transaction().effects().status().success(),
        "registering upgrade cap and Coin<BTC> failed"
    );

    Ok(HashiIds {
        package_id,
        hashi_object_id: *hashi.object_id(),
    })
}
