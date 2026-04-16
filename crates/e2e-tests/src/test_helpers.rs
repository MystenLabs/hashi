// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used by e2e test modules.
//!
//! Test modules across this crate (`e2e_flow`, `upgrade_tests`, ...) all need
//! the same boilerplate to drive a localnet: init tracing, look up an hBTC
//! balance, wait for a `DepositConfirmedEvent`, deposit-and-wait, etc. Define
//! them here once and import from each test module.

use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Amount;
use bitcoin::Txid;
use futures::StreamExt;
use hashi::sui_tx_executor::SuiTxExecutor;
use hashi_types::move_types::DepositConfirmedEvent;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::GetBalanceRequest;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_sdk_types::Address;
use sui_sdk_types::StructTag;
use sui_sdk_types::bcs::FromBcs;
use tracing::debug;
use tracing::info;

use crate::BitcoinNodeHandle;
use crate::TestNetworks;

pub fn init_test_logging() {
    tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .try_init()
        .ok();
}

pub fn txid_to_address(txid: &Txid) -> Address {
    hashi_types::bitcoin_txid::BitcoinTxid::from(*txid).into()
}

pub async fn get_hbtc_balance(
    sui_client: &mut sui_rpc::Client,
    package_id: Address,
    owner: Address,
) -> Result<u64> {
    let btc_type = format!("{package_id}::btc::BTC");
    let btc_struct_tag: StructTag = btc_type.parse()?;
    let request = GetBalanceRequest::default()
        .with_owner(owner.to_string())
        .with_coin_type(btc_struct_tag.to_string());

    let response = sui_client
        .state_client()
        .get_balance(request)
        .await?
        .into_inner();

    let balance = response.balance().balance_opt().unwrap_or(0);
    debug!("hBTC balance for {owner}: {balance} sats");
    Ok(balance)
}

pub async fn wait_for_deposit_confirmation(
    sui_client: &mut sui_rpc::Client,
    request_id: Address,
    timeout: Duration,
) -> Result<()> {
    info!("Waiting for deposit confirmation for request_id: {request_id}");

    let start = std::time::Instant::now();
    let read_mask = FieldMask::from_paths([Checkpoint::path_builder()
        .transactions()
        .events()
        .events()
        .contents()
        .finish()]);
    let mut subscription = sui_client
        .subscription_client()
        .subscribe_checkpoints(SubscribeCheckpointsRequest::default().with_read_mask(read_mask))
        .await?
        .into_inner();

    while let Some(item) = subscription.next().await {
        if start.elapsed() > timeout {
            return Err(anyhow!(
                "Timeout waiting for deposit confirmation after {timeout:?}"
            ));
        }

        let checkpoint = match item {
            Ok(cp) => cp,
            Err(e) => {
                debug!("Error in checkpoint stream: {e}");
                continue;
            }
        };

        for txn in checkpoint.checkpoint().transactions() {
            for event in txn.events().events() {
                if event.contents().name().contains("DepositConfirmedEvent")
                    && let Ok(evt) = DepositConfirmedEvent::from_bcs(event.contents().value())
                    && evt.request_id == request_id
                {
                    info!("Deposit confirmed for request_id: {request_id}");
                    return Ok(());
                }
            }
        }
    }

    Err(anyhow!("Checkpoint subscription ended unexpectedly"))
}

pub fn lookup_vout(
    networks: &TestNetworks,
    txid: Txid,
    address: bitcoin::Address,
    amount: u64,
) -> Result<usize> {
    let tx = networks
        .bitcoin_node
        .rpc_client()
        .get_raw_transaction(txid)
        .and_then(|r| r.transaction().map_err(Into::into))?;
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == Amount::from_sat(amount)
                && output.script_pubkey == address.script_pubkey()
        })
        .ok_or_else(|| anyhow!("Could not find output with amount {amount} and deposit address"))?;
    debug!("Found deposit in tx output {vout}");
    Ok(vout)
}

/// Deposit BTC and wait for the validators to auto-confirm it via the full
/// observe → sign → confirm path. Returns the hBTC recipient address.
pub async fn create_deposit_and_wait(
    networks: &mut TestNetworks,
    amount_sats: u64,
) -> Result<Address> {
    let user_key = networks.sui_network.user_keys.first().unwrap();
    let hbtc_recipient = user_key.public_key().derive_address();
    let hashi = networks.hashi_network.nodes()[0].hashi().clone();
    // Use the on-chain MPC key rather than the local key-ready channel.
    // The on-chain key is set during end_reconfig and is guaranteed
    // available once HashiNetworkBuilder::build() returns.
    let deposit_address =
        hashi.get_deposit_address(&hashi.get_onchain_mpc_pubkey()?, Some(&hbtc_recipient))?;

    info!("Sending Bitcoin to deposit address...");
    let txid = networks
        .bitcoin_node
        .send_to_address(&deposit_address, Amount::from_sat(amount_sats))?;
    info!("Transaction sent: {txid}");

    info!("Mining blocks for confirmation...");
    let blocks_to_mine = 10;
    networks.bitcoin_node.generate_blocks(blocks_to_mine)?;
    info!("{blocks_to_mine} blocks mined");

    info!("Creating deposit request on Sui...");
    let vout = lookup_vout(networks, txid, deposit_address, amount_sats)?;
    let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
        .with_signer(user_key.clone());
    let request_id = executor
        .execute_create_deposit_request(
            txid_to_address(&txid),
            vout as u32,
            amount_sats,
            Some(hbtc_recipient),
        )
        .await?;
    info!("Deposit request created: {request_id}");

    // Mine blocks in the background so the leader's BTC-block-driven
    // deposit processing loop fires.
    let _miner = BackgroundMiner::start(&networks.bitcoin_node);
    wait_for_deposit_confirmation(
        &mut networks.sui_network.client,
        request_id,
        Duration::from_secs(300),
    )
    .await?;
    info!("Deposit confirmed on Sui");

    Ok(hbtc_recipient)
}

/// Mines one block per second on Bitcoin regtest until stopped.
/// Stops automatically when dropped.
pub struct BackgroundMiner {
    stop_flag: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl BackgroundMiner {
    pub fn start(bitcoin_node: &BitcoinNodeHandle) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_clone = stop_flag.clone();
        let rpc_url = bitcoin_node.rpc_url().to_string();
        let handle = std::thread::spawn(move || {
            let rpc = corepc_client::client_sync::v29::Client::new_with_auth(
                &rpc_url,
                corepc_client::client_sync::Auth::UserPass(
                    crate::bitcoin_node::RPC_USER.to_string(),
                    crate::bitcoin_node::RPC_PASSWORD.to_string(),
                ),
            )
            .expect("failed to create mining RPC client");
            let addr = rpc.new_address().expect("failed to get mining address");
            while !stop_clone.load(Ordering::Relaxed) {
                let _ = rpc.generate_to_address(1, &addr);
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        Self {
            stop_flag,
            handle: Some(handle),
        }
    }
}

impl Drop for BackgroundMiner {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
