// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi::config::HashiIds;
use std::path::Path;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;

use crate::sui_network::sui_binary;

pub async fn publish(
    dir: &Path,
    client: &mut Client,
    private_key: &Ed25519PrivateKey,
) -> Result<HashiIds> {
    let params = hashi::publish::BuildParams {
        sui_binary: sui_binary(),
        package_path: &dir.join("packages/hashi"),
        client_config: Some(&dir.join("sui/client.yaml")),
        environment: Some("testnet"),
    };
    let compiled = hashi::publish::build_package(&params)?;
    let bitcoin_chain_id = hashi::constants::BITCOIN_REGTEST_CHAIN_ID;
    hashi::publish::publish_and_init(client, private_key, compiled, bitcoin_chain_id).await
}
