// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hashi::publish::PublishOutput;
use std::path::Path;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;

use crate::sui_network::sui_binary;

pub const DEFAULT_MOVE_PACKAGE_DIR: &str = "hashi";

pub const FROZEN_V1_MOVE_PACKAGE_DIR: &str = "hashi-v1";

pub async fn publish(
    dir: &Path,
    package_dir: &str,
    client: &mut Client,
    private_key: &Ed25519PrivateKey,
) -> Result<PublishOutput> {
    let params = hashi::publish::BuildParams {
        sui_binary: sui_binary(),
        package_path: &dir.join("packages").join(package_dir),
        client_config: Some(&dir.join("sui/client.yaml")),
        environment: Some("testnet"),
    };
    let compiled = hashi::publish::build_package(&params)?;
    hashi::publish::publish_package(client, &private_key.clone().into(), compiled).await
}
