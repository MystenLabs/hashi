// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Container-side twin of `e2e_tests::TestNetworksBuilder::build`: the same
//! boot order, but each step drives a separate container instead of an
//! in-process handle.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use hashi_types::move_types::ConfigValue;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

use crate::env::CommonArgs;
use crate::env::Deployment;
use crate::env::EnvFile;
use crate::env::POLL_INTERVAL;

/// Coinbase outputs mature after 100 blocks; one more leaves the wallet a
/// spendable 50 BTC.
const INITIAL_BLOCKS: u64 = 101;
const VALIDATOR_FUNDING_MIST: u64 = 1_000_000 * 1_000_000_000;
const HASHI_GRPC_PORT: u16 = 8443;
const HASHI_METRICS_PORT: u16 = 9184;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(600);
const GENESIS_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(clap::Args)]
pub struct Args {
    /// `sui move build --dump-bytecode-as-base64` output for the hashi package,
    /// produced when the image was built (there is no network at runtime).
    #[arg(
        long,
        env = "HASHI_PACKAGE_JSON",
        default_value = "/opt/hashi-antithesis/hashi-package.json"
    )]
    package_json: PathBuf,

    /// `host:port` the hashi nodes' Kyoto light clients sync from.
    #[arg(long, env = "BTC_P2P_ADDR", default_value = "bitcoind:18444")]
    btc_p2p: String,

    /// `test_weight_divisor` for every node; shrinks MPC work as in the e2e tests.
    #[arg(long, env = "HASHI_TEST_WEIGHT_DIVISOR", default_value_t = 100)]
    test_weight_divisor: u16,

    #[arg(
        long,
        env = "HASHI_WITHDRAWAL_BATCHING_DELAY_MS",
        default_value_t = 5_000
    )]
    withdrawal_batching_delay_ms: u64,

    /// Pause between handing out node configs. Kyoto clients that start their
    /// initial filter-header sync against the single regtest peer at the same
    /// time trip its ban logic (see `HashiNetworkBuilder::build`).
    #[arg(long, env = "HASHI_NODE_START_STAGGER_SECS", default_value_t = 2)]
    node_start_stagger_secs: u64,
}

pub async fn run(common: &CommonArgs, args: Args) -> Result<()> {
    let shared = common.shared();
    if shared.bootstrap_done_path().exists() {
        tracing::info!("bootstrap already completed; nothing to do");
        return Ok(());
    }

    let env = EnvFile::load(&common.env_file)?;
    let funded_key = env.funded_key()?;
    let validators = env
        .validators
        .iter()
        .map(|v| Ok((v.hashi_host.clone(), v.key()?)))
        .collect::<Result<Vec<_>>>()?;

    bootstrap_bitcoin(common).await?;

    let mut client = sui_rpc::Client::new(&common.sui_rpc)?;
    let sui_chain_id = crate::env::wait_for_sui(&mut client).await?;
    tracing::info!(sui_chain_id, "sui is up");

    e2e_tests::sui_network::upgrade_sui_system_state(&mut client, &funded_key).await?;
    let funding = validators
        .iter()
        .map(|(_, key)| (address_of(key), VALIDATOR_FUNDING_MIST))
        .collect::<Vec<_>>();
    e2e_tests::sui_network::fund(&mut client, &funded_key, &funding).await?;
    tracing::info!("funded {} validator accounts", funding.len());

    let compiled = hashi::publish::parse_build_output(
        &std::fs::read(&args.package_json)
            .with_context(|| format!("failed to read {}", args.package_json.display()))?,
    )?;
    let published =
        hashi::publish::publish_package(&mut client, &funded_key.clone().into(), compiled).await?;
    let deployment = Deployment {
        package_id: published.ids.package_id,
        hashi_object_id: published.ids.hashi_object_id,
        sui_chain_id,
    };
    shared.write_deployment(&deployment)?;
    tracing::info!(
        package_id = %deployment.package_id,
        hashi_object_id = %deployment.hashi_object_id,
        "published hashi"
    );

    let mut node_configs = Vec::with_capacity(validators.len());
    for (i, (hashi_host, key)) in validators.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(args.node_start_stagger_secs)).await;
        }
        let config = node_config(common, &args, &deployment, hashi_host, key)?;
        let path = shared.node_config_path(hashi_host);
        let tmp = path.with_extension("tmp");
        config.save(&tmp)?;
        std::fs::rename(&tmp, &path)?;
        tracing::info!("wrote {}", path.display());
        node_configs.push(config);
    }

    let (onchain, _onchain_service) = crate::env::onchain_view(&common.sui_rpc, &deployment).await;

    let expected = validators
        .iter()
        .map(|(_, key)| address_of(key))
        .collect::<Vec<_>>();
    wait_until(REGISTRATION_TIMEOUT, "hashi validators to register", || {
        all_registered(&onchain, &expected)
    })
    .await?;

    let guardian = hashi::publish::GuardianConfig {
        url: common.guardian_url.clone(),
        btc_public_key: env
            .guardian_btc_keypair()?
            .x_only_public_key()
            .0
            .serialize()
            .to_vec(),
    };
    hashi::publish::finish_publish(
        &mut client,
        &funded_key.clone().into(),
        &deployment.hashi_ids(),
        published.upgrade_cap_id,
        hashi::constants::BITCOIN_REGTEST_CHAIN_ID,
        &guardian,
        &hashi::publish::BitcoinConfigOverrides {
            deposit_time_delay_ms: Some(0),
            ..Default::default()
        },
    )
    .await?;
    tracing::info!("sent finish_publish; waiting for genesis DKG");

    wait_until(GENESIS_TIMEOUT, "the genesis committee", || {
        crate::env::committee_ready(&onchain)
    })
    .await?;

    // Mirrors TestNetworksBuilder's defaults, minus the deposit delay that
    // finish_publish already set.
    let mut executors = node_configs
        .iter()
        .map(|config| hashi::sui_tx_executor::SuiTxExecutor::from_config(config, &onchain))
        .collect::<Result<Vec<_>>>()?;
    e2e_tests::submit_onchain_config_overrides(
        &mut client,
        deployment.hashi_ids(),
        &onchain,
        &mut executors,
        &[(
            "mpc_nonce_accumulation_window_ms".to_string(),
            ConfigValue::U64(0),
        )],
    )
    .await?;
    tracing::info!("applied on-chain config overrides");

    wait_for_guardian_activated(&common.guardian_url).await;

    std::fs::write(shared.bootstrap_done_path(), b"")?;
    antithesis_sdk::lifecycle::setup_complete(&serde_json::json!({
        "package_id": deployment.package_id.to_string(),
        "hashi_object_id": deployment.hashi_object_id.to_string(),
    }));
    tracing::info!("bootstrap complete");
    Ok(())
}

async fn bootstrap_bitcoin(common: &CommonArgs) -> Result<()> {
    crate::env::retry("bitcoind wallet", || async {
        crate::env::ensure_wallet(common)
    })
    .await;
    let wallet = common.btc_wallet()?;
    let height = wallet.get_block_count()?.0;
    if height < INITIAL_BLOCKS {
        let address = wallet.new_address()?;
        wallet.generate_to_address((INITIAL_BLOCKS - height) as usize, &address)?;
    }
    tracing::info!("bitcoind is up with a funded wallet");
    Ok(())
}

fn node_config(
    common: &CommonArgs,
    args: &Args,
    deployment: &Deployment,
    hashi_host: &str,
    key: &Ed25519PrivateKey,
) -> Result<hashi::config::Config> {
    // Starts from the test config for its fresh TLS key and mock backup cert.
    let mut config = hashi::config::Config::new_for_testing();
    config.listen_address = Some(([0, 0, 0, 0], HASHI_GRPC_PORT).into());
    config.endpoint_url = Some(format!("https://{hashi_host}:{HASHI_GRPC_PORT}"));
    config.metrics_http_address = Some(([0, 0, 0, 0], HASHI_METRICS_PORT).into());
    config.hashi_ids = Some(deployment.hashi_ids());
    config.validator_address = Some(address_of(key));
    config.operator_private_key = Some(key.to_pem()?);
    config.sui_rpc = Some(common.sui_rpc.clone());
    config.sui_chain_id = Some(deployment.sui_chain_id.clone());
    config.bitcoin_rpc = Some(common.btc_rpc.clone());
    config.bitcoin_rpc_auth = Some(hashi::btc_monitor::config::BtcRpcAuth::UserPass(
        common.btc_rpc_user.clone(),
        common.btc_rpc_password.clone(),
    ));
    config.bitcoin_trusted_peers = Some(vec![args.btc_p2p.clone()]);
    config.bitcoin_chain_id = Some(hashi::constants::BITCOIN_REGTEST_CHAIN_ID.to_string());
    config.test_weight_divisor = Some(args.test_weight_divisor);
    config.withdrawal_batching_delay_ms = Some(args.withdrawal_batching_delay_ms);
    config.db = Some("/opt/hashi/data/db".into());
    config.backup_dir = "/opt/hashi/data/backups".into();
    Ok(config)
}

fn address_of(key: &Ed25519PrivateKey) -> Address {
    key.public_key().derive_address()
}

fn all_registered(onchain: &hashi::onchain::OnchainState, expected: &[Address]) -> bool {
    let state = onchain.state();
    let members = state.hashi().committees.members();
    expected.iter().all(|address| {
        members
            .get(address)
            .is_some_and(|m| m.next_epoch_encryption_public_key().is_some())
    })
}

async fn wait_until(timeout: Duration, what: &str, mut ready: impl FnMut() -> bool) -> Result<()> {
    tracing::info!("waiting for {what}");
    tokio::time::timeout(timeout, async {
        while !ready() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {timeout:?} waiting for {what}"))
}

async fn wait_for_guardian_activated(url: &str) {
    use hashi_types::proto::WithdrawStage;
    use hashi_types::proto::guardian_info_data::Lifecycle;

    let client = hashi::grpc::guardian_client::GuardianClient::new(url)
        .expect("guardian url is a valid endpoint");
    crate::env::retry("guardian activation", || async {
        let info = client.get_guardian_info().await?;
        let lifecycle = info
            .signed_info
            .and_then(|signed| signed.data)
            .and_then(|data| data.lifecycle);
        anyhow::ensure!(
            lifecycle == Some(Lifecycle::Withdraw(WithdrawStage::Activated as i32)),
            "guardian lifecycle is {lifecycle:?}"
        );
        Ok(())
    })
    .await;
    tracing::info!("guardian is activated");
}
