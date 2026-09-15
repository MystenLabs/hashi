// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! hashi-monitor's Bitcoin JSON-RPC client against a local regtest bitcoind.

use std::collections::BTreeMap;

use anyhow::Result;
use base64ct::Base64;
use base64ct::Encoding as _;
use bitcoin::Amount;
use bitcoin::Txid;
use bitcoin::hashes::Hash as _;
use e2e_tests::BitcoinNodeBuilder;
use e2e_tests::bitcoin_node::RPC_PASSWORD;
use e2e_tests::bitcoin_node::RPC_USER;
use e2e_tests::test_helpers::init_test_logging;
use hashi_monitor::config::BtcConfig;
use hashi_monitor::config::Config;
use hashi_monitor::config::NextEventDelays;
use hashi_monitor::config::SuiConfig;
use hashi_monitor::domain::WithdrawalEventType;
use hashi_monitor::rpc::btc::BtcRpcClient;
use hashi_monitor::rpc::btc::MIN_CONFIRMATIONS;
use hashi_types::guardian::UnresolvedS3Config;
use tempfile::TempDir;

fn test_config(rpc_url: String) -> Config {
    Config {
        next_event_delays: NextEventDelays::new(vec![
            (WithdrawalEventType::E1HashiApproved, 100),
            (WithdrawalEventType::E2GuardianApproved, 200),
        ])
        .expect("valid next event delays"),
        clock_skew: 10,
        withdrawal_predecessor_lookback: 60 * 60,
        guardian_s3: UnresolvedS3Config {
            bucket_info: hashi_types::guardian::S3BucketInfo {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
            },
            access_key: Some("access-key".to_string()),
            secret_key: Some("secret-key".to_string()),
            retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
        },
        pcr_allowlist: hashi_types::guardian::PcrAllowlist::new(
            hashi_types::guardian::BuildPcrs::new("", vec![]),
            vec![],
        )
        .expect("valid PCR allowlist"),
        sui: SuiConfig {
            rpc_url: "http://sui".to_string(),
            package_id: format!("0x{}", "11".repeat(32)),
        },
        btc: BtcConfig {
            rpc_url,
            http_headers: BTreeMap::from([(
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    Base64::encode_string(format!("{RPC_USER}:{RPC_PASSWORD}").as_bytes())
                ),
            )]),
        },
    }
}

#[tokio::test]
async fn lookup_btc_confirmation_with_local_regtest() -> Result<()> {
    init_test_logging();

    let temp_dir = TempDir::new()?;
    let node = BitcoinNodeBuilder::new()
        .dir(temp_dir.path())
        .build()
        .await?;
    let cfg = test_config(node.rpc_url().to_string());
    let btc_rpc_client = BtcRpcClient::new(&cfg)?;
    btc_rpc_client.ensure_synced()?;

    let unknown_txid = Txid::from_slice(&[7u8; 32])?;
    let unknown = btc_rpc_client.lookup_confirmation(unknown_txid)?;
    assert!(
        unknown.is_none(),
        "expected unknown tx lookup to return none"
    );

    let destination = node.get_new_address()?;
    let txid = node.send_to_address(&destination, Amount::from_sat(50_000))?;

    let unconfirmed = btc_rpc_client.lookup_confirmation(txid)?;
    assert!(unconfirmed.is_none(), "expected unconfirmed transaction");

    node.generate_blocks(1)?;
    btc_rpc_client.clear_confirmation_cache();

    let insufficiently_confirmed = btc_rpc_client.lookup_confirmation(txid)?;
    assert!(
        insufficiently_confirmed.is_none(),
        "expected one-confirmation transaction to remain pending"
    );

    node.generate_blocks(MIN_CONFIRMATIONS - 1)?;
    btc_rpc_client.clear_confirmation_cache();

    let confirmed = btc_rpc_client.lookup_confirmation(txid)?;
    assert!(confirmed.is_some(), "expected confirmed transaction");

    Ok(())
}
