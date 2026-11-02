// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The Sui chain / Bitcoin chain pairing rule (SEC-510, audit D-13): Bitcoin
//! mainnet if and only if Sui mainnet. Enforced by the launch transaction
//! builder before any network I/O, and by the node from its local config at
//! startup.
//!
//! The node also refuses Hashi ids from another chain: the pinned mainnet ids
//! if and only if Sui mainnet.

use std::time::Duration;

use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config;
use hashi::config::HashiIds;
use hashi::constants::BITCOIN_MAINNET_CHAIN_ID;
use hashi::constants::BITCOIN_REGTEST_CHAIN_ID;
use hashi::constants::BITCOIN_SIGNET_CHAIN_ID;
use hashi::constants::BITCOIN_TESTNET4_CHAIN_ID;
use hashi::constants::HASHI_MAINNET_OBJECT_ID;
use hashi::constants::HASHI_MAINNET_PACKAGE_ID;
use hashi::constants::SUI_MAINNET_CHAIN_ID;
use hashi::constants::SUI_TESTNET_CHAIN_ID;
use hashi::constants::check_hashi_ids_for_sui_chain;
use hashi::constants::check_sui_bitcoin_chain_pairing;
use hashi::publish::BitcoinConfigOverrides;
use hashi::publish::GuardianConfig;
use hashi::publish::build_finish_publish_tx;
use sui_sdk_types::Address;

/// Stands in for a localnet or devnet genesis digest.
const SUI_LOCALNET_CHAIN_ID: &str = "8ipsdC3P9bE1oVsr9cpzFRBcV1ZmvPzMwqFwEiwLCbfw";

const NON_MAINNET_BITCOIN: [&str; 3] = [
    BITCOIN_SIGNET_CHAIN_ID,
    BITCOIN_TESTNET4_CHAIN_ID,
    BITCOIN_REGTEST_CHAIN_ID,
];
const NON_MAINNET_SUI: [&str; 2] = [SUI_TESTNET_CHAIN_ID, SUI_LOCALNET_CHAIN_ID];

/// Stand in for the ids of a deployment on another chain.
const OTHER_PACKAGE_ID: Address = Address::from_static("0x1");
const OTHER_OBJECT_ID: Address = Address::from_static("0x2");

const MAINNET_IDS: HashiIds = HashiIds {
    package_id: HASHI_MAINNET_PACKAGE_ID,
    hashi_object_id: HASHI_MAINNET_OBJECT_ID,
};
const OTHER_IDS: HashiIds = HashiIds {
    package_id: OTHER_PACKAGE_ID,
    hashi_object_id: OTHER_OBJECT_ID,
};

#[test]
fn bitcoin_mainnet_pairs_with_sui_mainnet_only() {
    check_sui_bitcoin_chain_pairing(SUI_MAINNET_CHAIN_ID, BITCOIN_MAINNET_CHAIN_ID).unwrap();
    for sui in NON_MAINNET_SUI {
        let err = check_sui_bitcoin_chain_pairing(sui, BITCOIN_MAINNET_CHAIN_ID).unwrap_err();
        assert!(
            err.to_string()
                .contains("Bitcoin mainnet is allowed on Sui mainnet only"),
            "{sui}: {err}"
        );
    }
}

#[test]
fn sui_mainnet_requires_bitcoin_mainnet() {
    for btc in NON_MAINNET_BITCOIN {
        let err = check_sui_bitcoin_chain_pairing(SUI_MAINNET_CHAIN_ID, btc).unwrap_err();
        assert!(
            err.to_string().contains("Sui mainnet requires"),
            "{btc}: {err}"
        );
    }
}

#[test]
fn non_mainnet_sui_pairs_with_any_non_mainnet_bitcoin_chain() {
    for sui in NON_MAINNET_SUI {
        for btc in NON_MAINNET_BITCOIN {
            check_sui_bitcoin_chain_pairing(sui, btc).unwrap();
        }
    }
}

/// The Bitcoin side is decided by the network the hash resolves to, as every
/// consumer of the id does, so letter case cannot dodge the rule.
#[test]
fn an_uppercase_mainnet_hash_is_still_bitcoin_mainnet() {
    let upper = BITCOIN_MAINNET_CHAIN_ID.to_uppercase();
    let err = check_sui_bitcoin_chain_pairing(SUI_TESTNET_CHAIN_ID, &upper).unwrap_err();
    assert!(
        err.to_string()
            .contains("Bitcoin mainnet is allowed on Sui mainnet only"),
        "{err}"
    );
    check_sui_bitcoin_chain_pairing(SUI_MAINNET_CHAIN_ID, &upper).unwrap();
}

#[test]
fn an_unrecognised_bitcoin_chain_id_fails_closed() {
    for sui in [SUI_MAINNET_CHAIN_ID, SUI_TESTNET_CHAIN_ID] {
        let err = check_sui_bitcoin_chain_pairing(sui, "not-a-genesis-hash").unwrap_err();
        assert!(
            err.to_string().contains("unrecognized bitcoin chain id"),
            "{sui}: {err}"
        );
    }
}

#[test]
fn an_empty_sui_chain_id_fails_closed() {
    for btc in [BITCOIN_MAINNET_CHAIN_ID, BITCOIN_SIGNET_CHAIN_ID] {
        let err = check_sui_bitcoin_chain_pairing("", btc).unwrap_err();
        assert!(err.to_string().contains("empty"), "{btc}: {err}");
    }
}

#[test]
fn sui_mainnet_accepts_the_pinned_ids() {
    check_hashi_ids_for_sui_chain(SUI_MAINNET_CHAIN_ID, MAINNET_IDS).unwrap();
}

#[test]
fn sui_mainnet_refuses_any_other_package_id() {
    for package_id in [OTHER_PACKAGE_ID, Address::ZERO] {
        let ids = HashiIds {
            package_id,
            hashi_object_id: HASHI_MAINNET_OBJECT_ID,
        };
        let err = check_hashi_ids_for_sui_chain(SUI_MAINNET_CHAIN_ID, ids).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("refusing package-id {package_id}")),
            "{err}"
        );
    }
}

#[test]
fn sui_mainnet_refuses_any_other_hashi_object_id() {
    for hashi_object_id in [OTHER_OBJECT_ID, Address::ZERO] {
        let ids = HashiIds {
            package_id: HASHI_MAINNET_PACKAGE_ID,
            hashi_object_id,
        };
        let err = check_hashi_ids_for_sui_chain(SUI_MAINNET_CHAIN_ID, ids).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("refusing hashi-object-id {hashi_object_id}")),
            "{err}"
        );
    }
}

/// Either pinned id alone marks a config as mainnet.
#[test]
fn other_sui_chains_refuse_either_pinned_id() {
    let package_only = HashiIds {
        package_id: HASHI_MAINNET_PACKAGE_ID,
        hashi_object_id: OTHER_OBJECT_ID,
    };
    let object_only = HashiIds {
        package_id: OTHER_PACKAGE_ID,
        hashi_object_id: HASHI_MAINNET_OBJECT_ID,
    };
    for sui in NON_MAINNET_SUI {
        for ids in [MAINNET_IDS, package_only, object_only] {
            let err = check_hashi_ids_for_sui_chain(sui, ids).unwrap_err();
            assert!(
                err.to_string().contains("allowed on Sui mainnet only"),
                "{sui}: {err}"
            );
        }
    }
}

#[test]
fn other_sui_chains_accept_their_own_ids() {
    for sui in NON_MAINNET_SUI {
        check_hashi_ids_for_sui_chain(sui, OTHER_IDS).unwrap();
    }
}

/// The builder's only RPC is the final `build`, so a lazily connected client
/// to a closed port is never used when the pairing is refused.
async fn try_build_launch_tx(bitcoin_chain_id: &str, sui_chain_id: &str) -> anyhow::Result<()> {
    let mut client = sui_rpc::Client::new("http://127.0.0.1:1")?;
    let ids = HashiIds {
        package_id: Address::ZERO,
        hashi_object_id: Address::ZERO,
    };
    let guardian = GuardianConfig {
        url: "http://guardian.invalid".to_owned(),
        node_url: "http://node.guardian.invalid".to_owned(),
        btc_public_key: vec![0; 32],
    };
    build_finish_publish_tx(
        &mut client,
        Address::ZERO,
        &ids,
        Address::ZERO,
        bitcoin_chain_id,
        sui_chain_id,
        &guardian,
        &BitcoinConfigOverrides::default(),
    )
    .await
    .map(|_| ())
}

#[tokio::test]
async fn launch_tx_refuses_signet_bitcoin_on_sui_mainnet() {
    let err = try_build_launch_tx(BITCOIN_SIGNET_CHAIN_ID, SUI_MAINNET_CHAIN_ID)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("Sui mainnet requires"), "{err}");
}

#[tokio::test]
async fn launch_tx_refuses_mainnet_bitcoin_on_sui_testnet() {
    let err = try_build_launch_tx(BITCOIN_MAINNET_CHAIN_ID, SUI_TESTNET_CHAIN_ID)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Bitcoin mainnet is allowed on Sui mainnet only"),
        "{err}"
    );
}

#[tokio::test]
async fn launch_tx_still_refuses_an_unknown_bitcoin_chain_first() {
    let err = try_build_launch_tx("not-a-genesis-hash", SUI_MAINNET_CHAIN_ID)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("unrecognized bitcoin chain id"),
        "{err}"
    );
}

/// A permitted pair gets past the check and on to the network: the only
/// error left is the closed port.
#[tokio::test]
async fn launch_tx_with_a_permitted_pair_reaches_the_network() {
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        try_build_launch_tx(BITCOIN_REGTEST_CHAIN_ID, SUI_LOCALNET_CHAIN_ID),
    )
    .await
    .expect("a closed loopback port refuses immediately");
    let err = result.unwrap_err().to_string();
    assert!(
        !err.contains("refusing") && !err.contains("requires"),
        "pairing check fired on a permitted pair: {err}"
    );
}

fn node_with(
    sui_chain_id: Option<&str>,
    bitcoin_chain_id: Option<&str>,
) -> (std::sync::Arc<Hashi>, tempfile::TempDir) {
    node_with_ids(sui_chain_id, bitcoin_chain_id, None)
}

/// The Sui RPC is a closed port, so `Hashi::start` can only get as far as
/// its first network call.
fn node_with_ids(
    sui_chain_id: Option<&str>,
    bitcoin_chain_id: Option<&str>,
    hashi_ids: Option<HashiIds>,
) -> (std::sync::Arc<Hashi>, tempfile::TempDir) {
    let tmpdir = tempfile::tempdir().unwrap();
    let mut config = Config::new_for_testing();
    config.db = Some(tmpdir.path().into());
    config.sui_chain_id = sui_chain_id.map(str::to_owned);
    config.bitcoin_chain_id = bitcoin_chain_id.map(str::to_owned);
    config.hashi_ids = hashi_ids;
    config.sui_rpc = Some("http://127.0.0.1:1".to_owned());
    let hashi = Hashi::new_with_registry(
        ServerVersion::new("test", "test"),
        None,
        config,
        &prometheus::Registry::new(),
    )
    .unwrap();
    (hashi, tmpdir)
}

#[test]
fn node_refuses_signet_bitcoin_on_sui_mainnet() {
    let (hashi, _dir) = node_with(Some(SUI_MAINNET_CHAIN_ID), Some(BITCOIN_SIGNET_CHAIN_ID));
    let err = hashi.verify_chain_pairing().unwrap_err();
    assert!(err.to_string().contains("Sui mainnet requires"), "{err}");
}

#[test]
fn node_refuses_mainnet_bitcoin_on_sui_testnet() {
    let (hashi, _dir) = node_with(Some(SUI_TESTNET_CHAIN_ID), Some(BITCOIN_MAINNET_CHAIN_ID));
    let err = hashi.verify_chain_pairing().unwrap_err();
    assert!(
        err.to_string()
            .contains("Bitcoin mainnet is allowed on Sui mainnet only"),
        "{err}"
    );
}

/// Both config keys default to mainnet, so a Sui testnet config that omits
/// `bitcoin_chain_id` presents as testnet plus Bitcoin mainnet and is refused
/// at boot instead of later against bitcoind.
#[test]
fn node_on_sui_testnet_must_set_a_non_mainnet_bitcoin_chain_id() {
    let (hashi, _dir) = node_with(Some(SUI_TESTNET_CHAIN_ID), None);
    let err = hashi.verify_chain_pairing().unwrap_err();
    assert!(
        err.to_string().contains("defaults to mainnet when unset"),
        "{err}"
    );
}

#[test]
fn node_accepts_the_deployed_pairs() {
    for (sui, btc) in [
        (None, None),
        (Some(SUI_MAINNET_CHAIN_ID), Some(BITCOIN_MAINNET_CHAIN_ID)),
        (Some(SUI_TESTNET_CHAIN_ID), Some(BITCOIN_SIGNET_CHAIN_ID)),
        (Some(SUI_LOCALNET_CHAIN_ID), Some(BITCOIN_REGTEST_CHAIN_ID)),
    ] {
        let (hashi, _dir) = node_with(sui, btc);
        hashi.verify_chain_pairing().unwrap();
    }
}

#[test]
fn node_on_sui_mainnet_refuses_other_ids() {
    let (hashi, _dir) = node_with_ids(None, None, Some(OTHER_IDS));
    let err = hashi.verify_hashi_ids().unwrap_err();
    assert!(err.to_string().contains("on Sui mainnet"), "{err}");
}

/// `hashi-ids` defaults to mainnet, so a Sui testnet config that omits it
/// presents as testnet plus the mainnet ids and is refused at boot.
#[test]
fn node_on_sui_testnet_must_set_hashi_ids() {
    let (hashi, _dir) = node_with(Some(SUI_TESTNET_CHAIN_ID), Some(BITCOIN_SIGNET_CHAIN_ID));
    let err = hashi.verify_hashi_ids().unwrap_err();
    assert!(
        err.to_string().contains("default to mainnet when unset"),
        "{err}"
    );
}

#[test]
fn node_accepts_the_ids_of_its_chain() {
    for (sui, btc, ids) in [
        (None, None, None),
        (
            Some(SUI_MAINNET_CHAIN_ID),
            Some(BITCOIN_MAINNET_CHAIN_ID),
            Some(MAINNET_IDS),
        ),
        (
            Some(SUI_TESTNET_CHAIN_ID),
            Some(BITCOIN_SIGNET_CHAIN_ID),
            Some(OTHER_IDS),
        ),
        (
            Some(SUI_LOCALNET_CHAIN_ID),
            Some(BITCOIN_REGTEST_CHAIN_ID),
            Some(OTHER_IDS),
        ),
    ] {
        let (hashi, _dir) = node_with_ids(sui, btc, ids);
        hashi.verify_hashi_ids().unwrap();
    }
}

/// Run `Hashi::start`, which must fail: nothing in these tests serves the RPC.
async fn start_error(hashi: std::sync::Arc<Hashi>) -> String {
    let start = tokio::time::timeout(Duration::from_secs(30), hashi.start());
    let Err(err) = start
        .await
        .expect("a closed loopback port refuses immediately")
    else {
        panic!("start succeeded without a Sui RPC");
    };
    err.to_string()
}

/// Every way a config can mix mainnet with another network stops `start`
/// before its first network call.
#[tokio::test]
async fn start_refuses_a_partly_mainnet_config() {
    for (sui, btc, ids, expected) in [
        (
            None,
            Some(BITCOIN_SIGNET_CHAIN_ID),
            None,
            "Sui mainnet requires",
        ),
        (None, None, Some(OTHER_IDS), "refusing package-id"),
        (
            Some(SUI_TESTNET_CHAIN_ID),
            None,
            Some(OTHER_IDS),
            "Bitcoin mainnet is allowed on Sui mainnet only",
        ),
        (
            Some(SUI_TESTNET_CHAIN_ID),
            Some(BITCOIN_SIGNET_CHAIN_ID),
            None,
            "default to mainnet when unset",
        ),
        (
            Some(SUI_TESTNET_CHAIN_ID),
            Some(BITCOIN_SIGNET_CHAIN_ID),
            Some(MAINNET_IDS),
            "allowed on Sui mainnet only",
        ),
    ] {
        let (hashi, _dir) = node_with_ids(sui, btc, ids);
        let err = start_error(hashi).await;
        assert!(err.contains(expected), "{sui:?}/{btc:?}: {err}");
    }
}

/// A consistent config gets past the checks and on to the network: the only
/// error left is the closed port.
#[tokio::test]
async fn start_with_a_consistent_config_reaches_the_network() {
    for (sui, btc, ids) in [
        (None, None, None),
        (
            Some(SUI_MAINNET_CHAIN_ID),
            Some(BITCOIN_MAINNET_CHAIN_ID),
            Some(MAINNET_IDS),
        ),
        (
            Some(SUI_TESTNET_CHAIN_ID),
            Some(BITCOIN_SIGNET_CHAIN_ID),
            Some(OTHER_IDS),
        ),
    ] {
        let (hashi, _dir) = node_with_ids(sui, btc, ids);
        let err = start_error(hashi).await;
        assert!(
            !err.contains("refusing"),
            "a check fired on a consistent config, {sui:?}/{btc:?}: {err}"
        );
    }
}

/// `hashi register` signs against the configured ids, so it refuses what the
/// node refuses. The Sui RPC is never contacted.
#[tokio::test]
async fn register_refuses_other_ids_on_sui_mainnet() {
    let tmpdir = tempfile::tempdir().unwrap();
    let config_path = tmpdir.path().join("config.toml");
    let mut config = Config::new_for_testing();
    config.hashi_ids = Some(OTHER_IDS);
    config.save(&config_path).unwrap();

    let err = hashi::cli::run_register(hashi::cli::RegisterOpts {
        config: config_path,
        sui_rpc_url: Some("http://127.0.0.1:1".to_owned()),
        operator_address: None,
        serialize_unsigned: false,
        dry_run: true,
        verbose: false,
        yes: true,
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("refusing package-id"), "{err}");
}
