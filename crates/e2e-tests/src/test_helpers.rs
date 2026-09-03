// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared helpers used by e2e test modules.
//!
//! Test modules across this crate (`e2e_flow`, `upgrade_tests`, ...) all need
//! the same boilerplate to drive a localnet: init tracing, look up an hBTC
//! balance, wait for a `DepositConfirmed`, deposit-and-wait, etc. Define
//! them here once and import from each test module.

use anyhow::Result;
use anyhow::anyhow;
use bitcoin::Amount;
use bitcoin::Txid;
use futures::StreamExt;
use hashi::onchain::TobCertLayout;
use hashi::sui_tx_executor::SuiTxExecutor;
use hashi_types::bitcoin::BitcoinAddress;
use hashi_types::move_types::DepositConfirmed;
use hashi_types::move_types::ProtocolType;
use hashi_types::move_types::StampedDealerSubmissionV1;
use hashi_types::move_types::WithdrawalConfirmed;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::Checkpoint;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::GetBalanceRequest;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsRequest;
use sui_rpc::proto::sui::rpc::v2::SubscribeCheckpointsResponse;
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
                if event.contents().name().contains("DepositConfirmed")
                    && let Ok(evt) = DepositConfirmed::from_bcs(event.contents().value())
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
    address: BitcoinAddress,
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
    // `get_deposit_address` internally reads the on-chain MPC key, which is
    // populated atomically during `end_reconfig` and is guaranteed
    // available once `HashiNetworkBuilder::build()` returns.
    let deposit_address = hashi.get_deposit_address(Some(&hbtc_recipient))?;

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
        .with_signer(user_key.clone().into());
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

/// Extract the witness program (the bytes after the segwit version +
/// push-length prefix) from a P2WPKH (`0x00 0x14 …20`) or P2TR
/// (`0x51 0x20 …32`) address. This is the destination form the withdrawal
/// entry function expects.
pub fn extract_witness_program(address: &BitcoinAddress) -> Result<Vec<u8>> {
    let script = address.script_pubkey();
    let bytes = script.as_bytes();
    match bytes {
        [0x00, 0x14, rest @ ..] if rest.len() == 20 => Ok(rest.to_vec()),
        [0x51, 0x20, rest @ ..] if rest.len() == 32 => Ok(rest.to_vec()),
        _ => Err(anyhow!(
            "Unsupported script pubkey for withdrawal: {script}"
        )),
    }
}

/// A live checkpoint subscription to be consumed by
/// [`WithdrawalConfirmations::wait_for`].
///
/// Two-phase on purpose: open the subscription with
/// [`subscribe_withdrawal_confirmations`] BEFORE kicking off whatever
/// produces the confirmation (the background miner), so an early event
/// cannot land in the gap before the stream exists and be missed.
pub struct WithdrawalConfirmations {
    subscription: tonic::Streaming<SubscribeCheckpointsResponse>,
}

/// Open a checkpoint subscription for awaiting `WithdrawalConfirmed` events.
pub async fn subscribe_withdrawal_confirmations(
    sui_client: &mut sui_rpc::Client,
) -> Result<WithdrawalConfirmations> {
    let subscription_read_mask = FieldMask::from_paths([Checkpoint::path_builder()
        .transactions()
        .events()
        .events()
        .contents()
        .finish()]);
    let subscription = sui_client
        .subscription_client()
        .subscribe_checkpoints(
            SubscribeCheckpointsRequest::default().with_read_mask(subscription_read_mask),
        )
        .await?
        .into_inner();
    Ok(WithdrawalConfirmations { subscription })
}

impl WithdrawalConfirmations {
    /// Return the `WithdrawalConfirmed` event covering `request_id`, or error
    /// on timeout. Confirmation is the terminal on-chain milestone of a
    /// withdrawal: it fires only after the committee has generated
    /// presignatures, threshold-signed the BTC transaction, the guardian
    /// co-signed, and the leader observed the mined tx — so waiting on it
    /// exercises the whole signing path. Confirmations for other requests are
    /// skipped, so concurrent withdrawals cannot satisfy the wait.
    pub async fn wait_for(
        mut self,
        request_id: Address,
        timeout: Duration,
    ) -> Result<WithdrawalConfirmed> {
        info!("Waiting for confirmation of withdrawal request {request_id}...");

        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Deadline the stream read itself: a stalled subscription must
            // fail the wait, not hang it.
            let item = tokio::time::timeout_at(deadline, self.subscription.next())
                .await
                .map_err(|_| {
                    anyhow!("Timeout waiting for withdrawal confirmation after {timeout:?}")
                })?
                .ok_or_else(|| anyhow!("Checkpoint subscription ended unexpectedly"))?;

            let checkpoint = match item {
                Ok(checkpoint) => checkpoint,
                Err(e) => {
                    debug!("Error in checkpoint stream: {}", e);
                    continue;
                }
            };

            debug!(
                "Received checkpoint {}, checking for WithdrawalConfirmed...",
                checkpoint.cursor()
            );

            for txn in checkpoint.checkpoint().transactions() {
                for event in txn.events().events() {
                    if !event.contents().name().contains("WithdrawalConfirmed") {
                        continue;
                    }
                    match WithdrawalConfirmed::from_bcs(event.contents().value()) {
                        Ok(event_data) if event_data.request_ids.contains(&request_id) => {
                            info!(
                                withdrawal_txn_id = %event_data.withdrawal_txn_id,
                                txid = %event_data.txid,
                                "Withdrawal confirmed!"
                            );
                            return Ok(event_data);
                        }
                        Ok(event_data) => {
                            debug!(
                                withdrawal_txn_id = %event_data.withdrawal_txn_id,
                                "WithdrawalConfirmed for other requests, still waiting"
                            );
                        }
                        Err(e) => {
                            debug!("Failed to parse WithdrawalConfirmed: {}", e);
                        }
                    }
                }
            }
        }
    }
}

/// Request a withdrawal of `amount_sats` to a fresh regtest address and wait
/// for it to be confirmed on Sui, returning the `WithdrawalConfirmed` event.
///
/// Mirrors [`create_deposit_and_wait`] for the withdrawal side: it drives the
/// full presignature-generation + threshold-signing path, mining Bitcoin blocks
/// in the background so the signed transaction confirms and the leader reports
/// `WithdrawalConfirmed`.
pub async fn create_withdrawal_and_wait(
    networks: &mut TestNetworks,
    amount_sats: u64,
) -> Result<WithdrawalConfirmed> {
    let hashi = networks.hashi_network.nodes()[0].hashi().clone();
    let user_key = networks.sui_network.user_keys.first().unwrap();
    let btc_destination = networks.bitcoin_node.get_new_address()?;
    let destination_bytes = extract_witness_program(&btc_destination)?;
    info!("Requesting withdrawal of {amount_sats} sats to {btc_destination}");

    // Subscribe before creating the request or mining, so the confirmation
    // cannot land before the stream exists.
    let confirmations =
        subscribe_withdrawal_confirmations(&mut networks.sui_network.client).await?;

    let mut executor = SuiTxExecutor::from_config(&hashi.config, hashi.onchain_state())?
        .with_signer(user_key.clone().into());
    let withdrawal_request_id = executor
        .execute_create_withdrawal_request(amount_sats, destination_bytes)
        .await?;
    info!("Withdrawal request created: {withdrawal_request_id}");

    // Mine in the background so the signed BTC transaction confirms and the
    // leader's block-driven loop reports the withdrawal on Sui.
    let _miner = BackgroundMiner::start(&networks.bitcoin_node);
    let confirmed = confirmations
        .wait_for(withdrawal_request_id, Duration::from_secs(300))
        .await?;
    info!("Withdrawal confirmed on Sui");

    Ok(confirmed)
}

/// Wait until every node's object mirror shows the spent withdrawal
/// inputs cleaned up: at least one `spent_utxos` tombstone exists and no
/// `utxo_records` entry is still marked spent.
///
/// The cleanup transaction (`cleanup_spent_utxos`) emits no event, so
/// this passing proves both halves of the eventless-write path: the
/// leader's GC decided on the cleanup from its mirror, and every node's
/// mirror applied the resulting Field deletions from the object stream
/// alone — no rescrape exists to paper over a miss.
pub async fn wait_for_spent_utxo_cleanup(networks: &TestNetworks, timeout: Duration) -> Result<()> {
    info!("Waiting for the spent-UTXO cleanup to reach every node's mirror...");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let laggard =
            networks
                .hashi_network
                .nodes()
                .iter()
                .enumerate()
                .find_map(|(index, node)| {
                    let state = node.hashi().onchain_state();
                    let pending = state
                        .utxo_records()
                        .values()
                        .filter(|record| record.spent_epoch.is_some())
                        .count();
                    let tombstones = state.spent_utxos_entries().len();
                    (pending > 0 || tombstones == 0).then_some((index, pending, tombstones))
                });
        let Some((index, pending, tombstones)) = laggard else {
            info!("Every node's mirror shows the spent UTXOs cleaned up");
            return Ok(());
        };
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "Timeout after {timeout:?} waiting for the spent-UTXO cleanup: node {index}'s \
                 mirror still shows {pending} spent record(s) and {tombstones} tombstone(s)"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait until every node's object mirror shows the deferred withdrawal
/// archival completed: no withdrawal transaction with
/// `confirmed_timestamp_ms` set is still sitting in the hot
/// `withdrawal_txns` bag, and no committed request (linked to a withdrawal
/// txn) is lingering in the hot `requests` bag.
///
/// Under the v2 package `confirm_withdrawal` leaves the transaction (and
/// its requests) in the hot bags; the leader's deferred-archival GC
/// (`archive_confirmed_withdrawals`, armed by the confirm) later moves
/// them to `confirmed_txns`/`processed`. The mirror does not track those
/// archive bags, so "archived" is observable exactly as the ids draining
/// from every node's hot-bag mirror.
pub async fn wait_for_withdrawal_archival(
    networks: &TestNetworks,
    timeout: Duration,
) -> Result<()> {
    info!("Waiting for the withdrawal archival to reach every node's mirror...");
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let laggard =
            networks
                .hashi_network
                .nodes()
                .iter()
                .enumerate()
                .find_map(|(index, node)| {
                    let state = node.hashi().onchain_state();
                    let confirmed_txns = state
                        .withdrawal_txns()
                        .iter()
                        .filter(|txn| txn.is_confirmed())
                        .count();
                    let terminal_requests = state
                        .withdrawal_requests()
                        .iter()
                        .filter(|request| request.is_committed())
                        .count();
                    (confirmed_txns > 0 || terminal_requests > 0).then_some((
                        index,
                        confirmed_txns,
                        terminal_requests,
                    ))
                });
        let Some((index, confirmed_txns, terminal_requests)) = laggard else {
            info!("Every node's mirror shows the confirmed withdrawals archived");
            return Ok(());
        };
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!(
                "Timeout after {timeout:?} waiting for the withdrawal archival: node {index}'s \
                 mirror still shows {confirmed_txns} confirmed txn(s) in the hot bag and \
                 {terminal_requests} post-commit request(s)"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Chain-truth oracle for one TOB bucket, reading over RPC rather than
/// the mirror (production cert readers are mirror reads, so the tests
/// need an independent source): find the bucket Field in the tob bag,
/// decode its nodes in whichever layout the bucket's on-chain value
/// type names (bare submissions are lifted to the stamped form the
/// mirror stores), and walk the `LinkedTable` in link order. Returns
/// `None` when the bucket does not exist on-chain.
pub async fn fetch_tob_certs_from_chain(
    networks: &TestNetworks,
    key: hashi_types::move_types::TobKey,
) -> Result<Option<Vec<(Address, StampedDealerSubmissionV1)>>> {
    let tob_id = networks.hashi_network.nodes()[0]
        .hashi()
        .onchain_state()
        .tob_id();
    let client = networks.sui_network.client.clone();
    let key_bcs = bcs::to_bytes(&key)?;

    let Some(field) = list_all_dynamic_fields(&client, tob_id)
        .await?
        .into_iter()
        .find(|field| field.name().value() == key_bcs.as_slice())
    else {
        return Ok(None);
    };
    let value_type: StructTag = field
        .value_type_opt()
        .ok_or_else(|| anyhow!("TOB bucket field carried no value_type"))?
        .parse()?;
    let stamped = if value_type.module() == "tob" && value_type.name() == "EpochCertsV1" {
        false
    } else if value_type.module() == "tob" && value_type.name() == "StampedEpochCertsV1" {
        true
    } else {
        anyhow::bail!("unknown TOB bucket value type: {value_type}");
    };
    // The two bucket structs are BCS-identical; only the node layout
    // differs.
    let bucket: hashi_types::move_types::EpochCertsV1 = field
        .value()
        .deserialize()
        .map_err(|e| anyhow!("failed to deserialize EpochCertsV1: {e}"))?;

    let mut nodes = std::collections::HashMap::new();
    for field in list_all_dynamic_fields(&client, bucket.certs.id).await? {
        let dealer: Address = field
            .name()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize a tob node dealer: {e}"))?;
        let node: hashi_types::move_types::LinkedTableNode<Address, StampedDealerSubmissionV1> =
            if stamped {
                field
                    .value()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize a stamped tob node: {e}"))?
            } else {
                let bare: hashi_types::move_types::LinkedTableNode<
                    Address,
                    hashi_types::move_types::DealerSubmissionV1,
                > = field
                    .value()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize a tob node: {e}"))?;
                hashi_types::move_types::LinkedTableNode {
                    prev: bare.prev,
                    next: bare.next,
                    value: StampedDealerSubmissionV1 {
                        submission: bare.value,
                        timestamp_ms: 0,
                    },
                }
            };
        nodes.insert(dealer, node);
    }
    let mut certs = Vec::with_capacity(nodes.len());
    let mut current = bucket.certs.head;
    while let Some(dealer) = current {
        let Some(node) = nodes.remove(&dealer) else {
            break;
        };
        certs.push((dealer, node.value));
        current = node.next;
    }
    Ok(Some(certs))
}

/// Page through every dynamic field of `parent` with name, value, and
/// value type.
async fn list_all_dynamic_fields(
    client: &sui_rpc::Client,
    parent: Address,
) -> Result<Vec<DynamicField>> {
    let mut fields = Vec::new();
    let mut page_token = None;
    loop {
        let mut request = ListDynamicFieldsRequest::default()
            .with_parent(parent)
            .with_page_size(1_000)
            .with_read_mask(FieldMask::from_paths([
                DynamicField::path_builder().name().finish(),
                DynamicField::path_builder().value().finish(),
                DynamicField::path_builder().value_type(),
            ]));
        if let Some(token) = page_token.take() {
            request = request.with_page_token(token);
        }
        let page = client
            .clone()
            .state_client()
            .list_dynamic_fields(request)
            .await?
            .into_inner();
        fields.extend(page.dynamic_fields);
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }
    Ok(fields)
}

/// Assert the mirrored TOB matches the chain: every bucket the mirror
/// holds must read back from the chain oracle with the mirror's certs
/// as a prefix, in order. Prefix rather than equality because cert
/// submissions may still be landing (e.g. a presignature refill)
/// between the mirror read and the chain fetch.
pub async fn assert_tob_mirror_parity(networks: &TestNetworks) -> Result<()> {
    let state = networks.hashi_network.nodes()[0]
        .hashi()
        .onchain_state()
        .clone();
    let keys = state.tob_bucket_keys();
    anyhow::ensure!(
        !keys.is_empty(),
        "expected at least one mirrored TOB bucket after DKG"
    );
    for (key, _) in keys {
        let (layout, mirrored) = state
            .tob_certs(key.epoch, key.batch_index, key.protocol_type)?
            .ok_or_else(|| anyhow!("mirrored TOB bucket {key:?} vanished mid-check"))?;
        anyhow::ensure!(
            layout == TobCertLayout::Bare || key.protocol_type == ProtocolType::NonceGeneration,
            "only nonce buckets use the stamped layout, got {key:?}"
        );
        let fetched = fetch_tob_certs_from_chain(networks, key)
            .await?
            .ok_or_else(|| anyhow!("TOB bucket {key:?} is in the mirror but not on-chain"))?;
        anyhow::ensure!(
            fetched.len() >= mirrored.len() && fetched[..mirrored.len()] == mirrored[..],
            "TOB bucket {key:?} diverged: mirror holds {mirrored:?}, chain holds {fetched:?}"
        );
    }
    info!("TOB mirror parity verified");
    Ok(())
}

/// Assert the object mirror routed every changed object on every
/// running node. A nonzero counter means a Hashi-package object arrived
/// that the mirror could not place — a lossless-coverage gap.
pub fn assert_no_unrouted_objects(networks: &TestNetworks) {
    for (index, node) in networks.hashi_network.nodes().iter().enumerate() {
        if !node.is_running() {
            continue;
        }
        let unrouted = node.hashi().metrics.watcher_unrouted_objects_total.get();
        assert_eq!(
            unrouted, 0,
            "node {index}'s mirror failed to route {unrouted} object(s); \
             check the 'could not route' warnings in its log"
        );
    }
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
