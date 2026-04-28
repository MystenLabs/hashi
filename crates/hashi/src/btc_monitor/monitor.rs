// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use kyoto::FeeRate;
use kyoto::HeaderCheckpoint;
use kyoto::Warning;
use sui_futures::service::Service;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use super::config::MonitorConfig;
use crate::metrics::Metrics;

/// 1 sat/vB expressed as sat/kwu.
const FALLBACK_FEE_RATE_SAT_PER_KWU: u64 = 250;

/// Number of consecutive connection failures before restarting Kyoto.
const KYOTO_MAX_CONSECUTIVE_FAILURES: u32 = 30;

/// Delay before restarting Kyoto after connectivity loss.
const KYOTO_RESTART_DELAY: Duration = Duration::from_secs(5);

/// How many Bitcoin blocks a deposit observation can go without being
/// refreshed before it's dropped from the confirmation-metrics cache.
const STALE_OBSERVATION_BLOCKS: u32 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxStatus {
    Confirmed { confirmations: u32 },
    InMempool,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CachedDepositObservation {
    NotFound,
    InMempool,
    InBlock { height: u32 },
}

#[derive(Debug, Clone, Copy)]
struct CachedDepositEntry {
    observation: CachedDepositObservation,
    last_updated_tip: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum DepositConfirmError {
    #[error("UTXO {txid}:{vout} has already been spent on Bitcoin")]
    UtxoSpent { txid: bitcoin::Txid, vout: u32 },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

enum KyotoEventLoopExit {
    ConnectivityLost,
    Shutdown,
}

/// Monitor loop that tracks the state of the Bitcoin chain.
///
/// Client provides functions for querying for specific transactions,
/// fee information, and transaction submission.
pub struct Monitor {
    config: MonitorConfig,
    metrics: Arc<Metrics>,
    bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    requester: kyoto::Requester,
    tip: Option<HeaderCheckpoint>,
    block_height_tx: tokio::sync::watch::Sender<u32>,
    pending_deposits: Vec<PendingDeposit>,
    pending_deposit_workers: JoinSet<()>,
    rpc_workers: JoinSet<()>,
    deposit_observation_cache: HashMap<bitcoin::OutPoint, CachedDepositEntry>,
}

/// Offload a blocking Bitcoin Core RPC call to the tokio blocking thread pool.
async fn btc_rpc_call<F, T>(client: &Arc<corepc_client::client_sync::v29::Client>, f: F) -> T
where
    F: FnOnce(&corepc_client::client_sync::v29::Client) -> T + Send + 'static,
    T: Send + 'static,
{
    let client = Arc::clone(client);
    tokio::task::spawn_blocking(move || f(&client))
        .await
        .expect("btc_rpc_call: spawn_blocking task panicked")
}

impl Monitor {
    fn build_kyoto_node(config: &MonitorConfig) -> (kyoto::Node, kyoto::Client) {
        let checkpoint = match config.network {
            bitcoin::Network::Bitcoin if config.start_height > 709_631 => {
                kyoto::HeaderCheckpoint::taproot_activation()
            }
            bitcoin::Network::Bitcoin if config.start_height > 481_823 => {
                kyoto::HeaderCheckpoint::segwit_activation()
            }
            network => kyoto::HeaderCheckpoint::from_genesis(network),
        };

        let mut builder = kyoto::Builder::new(config.network)
            .add_dns_peers(config.dns_peers.iter().cloned())
            // Only connect to the configured trusted peers. Prevents Kyoto from
            // discovering additional peers via DNS seeding or addr gossip.
            // If all peers disconnect, the node exits with NoReachablePeers
            // and the supervision loop rebuilds it.
            .whitelist_only()
            .chain_state(kyoto::ChainState::Checkpoint(checkpoint));

        if let Some(data_dir) = &config.data_dir {
            builder = builder.data_dir(data_dir.clone());
        }

        builder.build()
    }

    /// Run a BTC monitor with the given configuration.
    /// Returns the client for interacting with the monitor and a Service for lifecycle management.
    pub fn run(config: MonitorConfig, metrics: Arc<Metrics>) -> Result<(MonitorClient, Service)> {
        let bitcoind_rpc = crate::btc_monitor::config::new_rpc_client(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);
        let (block_height_tx, block_height_rx) = tokio::sync::watch::channel(0u32);

        let service = Service::new().spawn_aborting({
            let client_tx = client_tx.clone();
            async move {
                let bitcoind_rpc = Arc::new(bitcoind_rpc);

                // Build initial Kyoto node.
                let (kyoto_node, kyoto_client) = Self::build_kyoto_node(&config);

                let mut monitor = Monitor {
                    config,
                    metrics,
                    bitcoind_rpc,
                    requester: kyoto_client.requester.clone(),
                    client_tx,
                    tip: None,
                    block_height_tx,
                    pending_deposits: vec![],
                    pending_deposit_workers: JoinSet::new(),
                    rpc_workers: JoinSet::new(),
                    deposit_observation_cache: HashMap::new(),
                };

                monitor
                    .run_with_supervision(kyoto_node, kyoto_client, &mut client_rx)
                    .await
            }
        });

        Ok((
            MonitorClient {
                tx: client_tx,
                block_height_rx,
            },
            service,
        ))
    }

    /// Run the monitor with automatic Kyoto restart on connectivity loss.
    async fn run_with_supervision(
        &mut self,
        kyoto_node: kyoto::Node,
        kyoto_client: kyoto::Client,
        client_rx: &mut tokio::sync::mpsc::Receiver<MonitorMessage>,
    ) -> Result<()> {
        let mut current_node = kyoto_node;
        let mut current_client = kyoto_client;

        loop {
            info!(
                "Starting Bitcoin monitor for network: {:?}",
                self.config.network
            );

            // Spawn the Kyoto node as a background task. Node::run() takes
            // ownership, so we move it in and get a JoinHandle back.
            let kyoto_handle = tokio::spawn(async move { current_node.run().await });

            let result = self.run_event_loop(&mut current_client, client_rx).await;

            // Abort the Kyoto node task regardless of exit reason.
            kyoto_handle.abort();

            match result {
                KyotoEventLoopExit::ConnectivityLost => {
                    warn!(
                        "Lost connectivity to Bitcoin peers after {KYOTO_MAX_CONSECUTIVE_FAILURES} \
                         consecutive failures. Restarting Kyoto node..."
                    );

                    self.metrics.kyoto_restarts.inc();
                    self.metrics.kyoto_connected_peers.set(0);
                    self.metrics.kyoto_synced.set(0);
                    self.metrics.kyoto_consecutive_failures.set(0);

                    // Wait before restarting to avoid tight restart loops.
                    tokio::time::sleep(KYOTO_RESTART_DELAY).await;

                    // Build a fresh Kyoto node with the trusted peers re-added
                    // to the whitelist.
                    let (new_node, new_client) = Self::build_kyoto_node(&self.config);
                    current_node = new_node;
                    current_client = new_client;
                    self.requester = current_client.requester.clone();

                    info!("Kyoto node rebuilt, resuming monitor");
                }
                KyotoEventLoopExit::Shutdown => {
                    info!("Bitcoin monitor stopped");
                    return Ok(());
                }
            }
        }
    }

    /// Map a Kyoto `Warning` variant to a short label for metrics.
    fn warning_label(warning: &Warning) -> &'static str {
        match warning {
            Warning::NeedConnections { .. } => "need_connections",
            Warning::PeerTimedOut => "peer_timed_out",
            Warning::CouldNotConnect => "could_not_connect",
            Warning::NoCompactFilters => "no_compact_filters",
            Warning::PotentialStaleTip => "potential_stale_tip",
            Warning::UnsolicitedMessage => "unsolicited_message",
            Warning::TransactionRejected { .. } => "transaction_rejected",
            Warning::EvaluatingFork => "evaluating_fork",
            Warning::UnexpectedSyncError { .. } => "unexpected_sync_error",
            Warning::ChannelDropped => "channel_dropped",
        }
    }

    /// Run the main event loop, returning the reason it exited.
    #[tracing::instrument(name = "btc_monitor", skip_all)]
    async fn run_event_loop(
        &mut self,
        kyoto_client: &mut kyoto::Client,
        client_rx: &mut tokio::sync::mpsc::Receiver<MonitorMessage>,
    ) -> KyotoEventLoopExit {
        let mut consecutive_failures: u32 = 0;
        let mut required_peers: usize = 0;

        loop {
            tokio::select! {
                Some(event) = kyoto_client.event_rx.recv() => {
                    self.process_kyoto_event(event);
                }
                Some(msg) = client_rx.recv() => {
                    self.process_client_message(msg);
                }
                Some(msg) = kyoto_client.info_rx.recv() => {
                    info!("Kyoto: {msg}");
                    // Reset failure counter on any info message (successful
                    // activity like syncing, handshakes, etc).
                    consecutive_failures = 0;
                    self.metrics.kyoto_consecutive_failures.set(0);

                    // Parse info messages for metrics where possible.
                    Self::update_info_metrics(&self.metrics, &msg, required_peers);
                }
                Some(warning) = kyoto_client.warn_rx.recv() => {
                    warn!("Kyoto: {warning}");
                    self.metrics.kyoto_warnings.with_label_values(&[Self::warning_label(&warning)]).inc();

                    // Track connected peer count from NeedConnections
                    if let Warning::NeedConnections { connected, required } = &warning {
                        self.metrics.kyoto_connected_peers.set(*connected as i64);
                        required_peers = *required;
                    }

                    let is_connectivity_failure = matches!(
                        warning,
                        Warning::CouldNotConnect
                        | Warning::PeerTimedOut
                        | Warning::NeedConnections { connected: 0, .. }
                    );
                    if is_connectivity_failure {
                        consecutive_failures += 1;
                        self.metrics.kyoto_consecutive_failures.set(consecutive_failures as i64);
                        if consecutive_failures >= KYOTO_MAX_CONSECUTIVE_FAILURES {
                            return KyotoEventLoopExit::ConnectivityLost;
                        }
                    }
                }
                Some(join_result) = self.pending_deposit_workers.join_next() => {
                    if let Err(e) = join_result {
                        error!("Pending deposit worker task failed: {e}");
                    }
                }
                Some(join_result) = self.rpc_workers.join_next() => {
                    if let Err(e) = join_result {
                        error!("RPC worker task failed: {e}");
                    }
                }
                else => {
                    return KyotoEventLoopExit::Shutdown;
                }
            }
        }
    }

    /// Extract metrics from Kyoto info messages.
    fn update_info_metrics(metrics: &Metrics, msg: &kyoto::Info, required_peers: usize) {
        match msg {
            kyoto::Info::ConnectionsMet => {
                metrics.kyoto_connected_peers.set(required_peers as i64);
            }
            kyoto::Info::Progress(progress) => {
                metrics
                    .kyoto_sync_percent
                    .set(progress.percentage_complete() as i64);
            }
            _ => {}
        }
    }

    fn process_kyoto_event(&mut self, event: kyoto::Event) {
        match event {
            kyoto::Event::ChainUpdate(changes) => self.process_chain_update(changes),
            kyoto::Event::FiltersSynced(sync_update) => self.process_synced(sync_update),
            kyoto::Event::IndexedFilter(filter) => {
                debug!(
                    "Received compact block filter at height {} (block {})",
                    filter.height(),
                    filter.block_hash()
                );
            }
        }
    }

    fn process_chain_update(&mut self, changes: kyoto::chain::BlockHeaderChanges) {
        match changes {
            kyoto::chain::BlockHeaderChanges::Connected(indexed_header) => {
                info!(
                    "New block header at height {} ({})",
                    indexed_header.height,
                    indexed_header.block_hash()
                );
                self.metrics.kyoto_blocks_received.inc();
                self.metrics
                    .kyoto_best_height
                    .set(indexed_header.height as i64);
                self.tip = Some(kyoto::HeaderCheckpoint::new(
                    indexed_header.height,
                    indexed_header.block_hash(),
                ));
                let _ = self.block_height_tx.send(indexed_header.height);
                self.process_pending_deposits();
            }
            kyoto::chain::BlockHeaderChanges::Reorganized {
                accepted,
                reorganized,
            } => {
                info!(
                    "Reorg detected: {} accepted, {} disconnected",
                    accepted.len(),
                    reorganized.len()
                );
                self.metrics.kyoto_reorgs.inc();
                if let Some(new_tip) = accepted.last() {
                    self.tip = Some(kyoto::HeaderCheckpoint::new(
                        new_tip.height,
                        new_tip.block_hash(),
                    ));
                    self.metrics.kyoto_best_height.set(new_tip.height as i64);
                    let _ = self.block_height_tx.send(new_tip.height);
                }
                // Re-check pending deposits — some may have been on the
                // reorged branch and need re-verification.
                self.process_pending_deposits();
            }
            kyoto::chain::BlockHeaderChanges::ForkAdded(indexed_header) => {
                debug!(
                    "Fork header received at height {} ({})",
                    indexed_header.height,
                    indexed_header.block_hash()
                );
            }
        }
    }

    fn process_synced(&mut self, sync_update: kyoto::SyncUpdate) {
        let tip = sync_update.tip;
        info!(
            "Synchronized to height {} ({}) with {} recent headers",
            tip.height,
            tip.hash,
            sync_update.recent_history.len()
        );
        self.metrics.kyoto_synced.set(1);
        self.metrics.kyoto_best_height.set(tip.height as i64);
        self.metrics.kyoto_sync_percent.set(100);
        self.tip = Some(tip);
        let _ = self.block_height_tx.send(tip.height);
        self.process_pending_deposits();
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::ConfirmDeposit(pending_deposit) => {
                self.confirm_deposit(pending_deposit);
            }
            MonitorMessage::GetRecentFeeRate(conf_target, result_tx) => {
                self.rpc_workers.spawn(Self::get_recent_fee_rate(
                    self.bitcoind_rpc.clone(),
                    self.metrics.clone(),
                    conf_target,
                    result_tx,
                ));
            }
            MonitorMessage::BroadcastTransaction(tx, result_tx) => {
                self.rpc_workers.spawn(Self::broadcast_transaction(
                    self.bitcoind_rpc.clone(),
                    self.requester.clone(),
                    tx,
                    result_tx,
                ));
            }
            MonitorMessage::GetTransactionStatus(txid, result_tx) => {
                self.rpc_workers.spawn(Self::get_transaction_status(
                    self.bitcoind_rpc.clone(),
                    txid,
                    result_tx,
                ));
            }
            MonitorMessage::RecordDepositObservation {
                outpoint,
                observation,
            } => {
                self.record_deposit_observation(outpoint, observation);
                self.rebuild_confirmation_metrics();
            }
            MonitorMessage::ForgetDeposit(outpoint) => {
                if self.deposit_observation_cache.remove(&outpoint).is_some() {
                    self.rebuild_confirmation_metrics();
                }
            }
        }
    }

    fn record_deposit_observation(
        &mut self,
        outpoint: bitcoin::OutPoint,
        observation: CachedDepositObservation,
    ) {
        let last_updated_tip = self.tip.as_ref().map(|t| t.height).unwrap_or(0);
        self.deposit_observation_cache.insert(
            outpoint,
            CachedDepositEntry {
                observation,
                last_updated_tip,
            },
        );
    }

    /// Drop cache entries that haven't been refreshed in the last
    /// `STALE_OBSERVATION_BLOCKS` Bitcoin blocks, then write the current
    /// bucket counts to `deposit_request_confirmations`.
    fn rebuild_confirmation_metrics(&mut self) {
        let tip_height = self.tip.as_ref().map(|t| t.height).unwrap_or(0);
        rebuild_confirmation_metrics_inner(
            &mut self.deposit_observation_cache,
            tip_height,
            &self.metrics,
        );
    }

    fn confirm_deposit(&mut self, pending_deposit: PendingDeposit) {
        debug!(
            "Processing deposit confirmation for {}",
            pending_deposit.outpoint.txid
        );

        let Some(tip) = &self.tip else {
            debug!(
                "Transaction {} confirmation on hold, pending chain tip update.",
                pending_deposit.outpoint.txid
            );
            self.pending_deposits.push(pending_deposit);
            return;
        };

        if pending_deposit.checked_at_height >= tip.height {
            debug!(
                "Transaction {} already checked at height {}. Waiting for more blocks.",
                pending_deposit.outpoint.txid, pending_deposit.checked_at_height
            );
            self.pending_deposits.push(pending_deposit);
            return;
        }

        let confirmation_threshold = pending_deposit.confirmation_threshold;
        self.pending_deposit_workers
            .spawn(Monitor::process_pending_deposit(
                tip.to_owned(),
                confirmation_threshold,
                self.bitcoind_rpc.clone(),
                self.requester.clone(),
                self.client_tx.clone(),
                pending_deposit,
            ));
    }

    async fn get_recent_fee_rate(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        metrics: Arc<Metrics>,
        conf_target: u16,
        result_tx: oneshot::Sender<Result<FeeRate>>,
    ) {
        // ECONOMICAL tracks spot fees more closely than the default
        // CONSERVATIVE, which blends in a long-horizon max.
        let result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.call::<corepc_client::types::v29::EstimateSmartFee>(
                "estimatesmartfee",
                &[
                    serde_json::json!(conf_target as u32),
                    serde_json::json!("ECONOMICAL"),
                ],
            )
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|res| Ok(res.into_model()?))
        .map(|res| {
            let sat_per_kwu = match res.fee_rate {
                Some(fee_rate) => fee_rate.to_sat_per_kwu(),
                None => {
                    warn!(
                        conf_target,
                        fallback_sat_per_kwu = FALLBACK_FEE_RATE_SAT_PER_KWU,
                        "Node could not estimate fee rate; falling back to minimum relay fee"
                    );
                    FALLBACK_FEE_RATE_SAT_PER_KWU
                }
            };
            metrics
                .btc_fee_rate_sat_per_kvb
                .set((sat_per_kwu * 4) as i64);
            FeeRate::from_sat_per_kwu(sat_per_kwu)
        });
        let _ = result_tx.send(result);
    }

    async fn broadcast_transaction(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        requester: kyoto::Requester,
        tx: bitcoin::Transaction,
        result_tx: oneshot::Sender<Result<()>>,
    ) {
        // Temp hack to get warning messages when a transaction would be rejected
        // TODO: https://linear.app/mysten-labs/issue/IOP-216/better-error-reporting-for-failed-btc-broadcasts
        let txid = tx.compute_txid();
        let accept_result = btc_rpc_call(&bitcoind_rpc, {
            let tx = tx.clone();
            move |rpc| rpc.test_mempool_accept(std::slice::from_ref(&tx))
        })
        .await;
        match accept_result {
            Ok(results) => match results.0.first() {
                Some(result) if !result.allowed => {
                    error!(
                        "Bitcoin Core mempool will reject tx {txid}: {}",
                        result.reject_reason.as_deref().unwrap_or("unknown reason")
                    );
                }
                Some(_) => {
                    debug!("Bitcoin Core mempool would accept tx {txid}");
                }
                None => {
                    warn!("Bitcoin Core testmempoolaccept returned no result for tx {txid}");
                }
            },
            Err(e) => {
                warn!("Failed to run testmempoolaccept for tx {txid}: {e}");
            }
        }

        match requester.broadcast_tx(tx).await {
            Ok(wtxid) => {
                info!("Transaction {txid} broadcast acknowledged (wtxid: {wtxid})");
                let _ = result_tx.send(Ok(()));
            }
            Err(e) => {
                error!("Failed to broadcast transaction {txid}: {e}");
                let _ = result_tx.send(Err(anyhow::anyhow!(e)));
            }
        }
    }

    async fn get_transaction_status(
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        txid: bitcoin::Txid,
        result_tx: oneshot::Sender<Result<TxStatus>>,
    ) {
        let rpc_result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.get_raw_transaction_verbose(txid)
        })
        .await;
        let result = match rpc_result {
            Ok(tx_info) => match tx_info.into_model() {
                Ok(tx_info) => {
                    if tx_info.block_hash.is_some() {
                        let confirmations = tx_info.confirmations.unwrap_or(0) as u32;
                        Ok(TxStatus::Confirmed { confirmations })
                    } else {
                        Ok(TxStatus::InMempool)
                    }
                }
                Err(e) => Err(anyhow::anyhow!("Failed to parse transaction info: {e}")),
            },
            Err(corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(ref e)))
                if e.code == -5 =>
            {
                // RPC error -5: "No such mempool or blockchain transaction"
                Ok(TxStatus::NotFound)
            }
            Err(e) => Err(anyhow::anyhow!("Failed to query transaction status: {e}")),
        };
        let _ = result_tx.send(result);
    }

    fn process_pending_deposits(&mut self) {
        self.rebuild_confirmation_metrics();

        let Some(tip) = &self.tip else {
            // Can't confirm deposits if we don't yet know the tip of the chain.
            return;
        };
        if self.pending_deposits.is_empty() {
            return;
        }

        info!(
            "Processing {} pending deposits",
            self.pending_deposits.len()
        );
        for pending_deposit in std::mem::take(&mut self.pending_deposits) {
            let confirmation_threshold = pending_deposit.confirmation_threshold;
            self.pending_deposit_workers
                .spawn(Monitor::process_pending_deposit(
                    tip.to_owned(),
                    confirmation_threshold,
                    self.bitcoind_rpc.clone(),
                    self.requester.clone(),
                    self.client_tx.clone(),
                    pending_deposit,
                ));
        }
    }

    async fn process_pending_deposit(
        tip: HeaderCheckpoint,
        confirmation_threshold: u32,
        bitcoind_rpc: Arc<corepc_client::client_sync::v29::Client>,
        requester: kyoto::Requester,
        client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
        mut pending_deposit: PendingDeposit,
    ) {
        if pending_deposit.result_tx.is_closed() {
            // Cancel if the receiver is no longer listening.
            return;
        }

        pending_deposit.checked_at_height = tip.height;
        let mut pending_deposit = PendingDepositGuard::new(pending_deposit, client_tx.clone());
        let outpoint = pending_deposit.outpoint;

        // Look up block from the txid.
        let block_info = match pending_deposit.block_info {
            Some(block_info) => block_info,
            None => {
                debug!(
                    "Looking up block for transaction {}",
                    pending_deposit.outpoint.txid
                );
                let txid = pending_deposit.outpoint.txid;
                let tx_info = match btc_rpc_call(&bitcoind_rpc, move |rpc| {
                    rpc.get_raw_transaction_verbose(txid)
                })
                .await
                {
                    Ok(tx_info) => tx_info,
                    Err(corepc_client::client_sync::Error::JsonRpc(
                        jsonrpc::error::Error::Rpc(ref e),
                    )) if e.code == -5 => {
                        // RPC error -5: "No such mempool or blockchain transaction"
                        debug!("Transaction {txid} not found in mempool or blockchain");
                        send_observation(&client_tx, outpoint, CachedDepositObservation::NotFound)
                            .await;
                        return;
                    }
                    Err(e) => {
                        error!("Failed to look up txid {txid}: {e}");
                        return;
                    }
                };
                let tx_info = match tx_info.into_model() {
                    Ok(info) => info,
                    Err(e) => {
                        error!(
                            "Failed to parse transaction info for {}: {e}",
                            pending_deposit.outpoint.txid
                        );
                        return;
                    }
                };
                let Some(block_hash) = tx_info.block_hash else {
                    debug!(
                        "Transaction {} is not yet included in a block",
                        pending_deposit.outpoint.txid
                    );
                    send_observation(&client_tx, outpoint, CachedDepositObservation::InMempool)
                        .await;
                    return;
                };
                // Verify the block hash is in kyoto's independently-validated
                // chain of most work. This catches a malicious bitcoind reporting
                // a fake or forked block hash.
                let height = match requester.height_of_hash(block_hash).await {
                    Ok(Some(height)) => height,
                    Ok(None) => {
                        warn!(
                            "Block hash {block_hash} not found in kyoto's chain of most work. \
                             Possibly malicious behavior by the Bitcoin Core node."
                        );
                        return;
                    }
                    Err(e) => {
                        error!("Failed to look up block hash {block_hash} in kyoto: {e}");
                        return;
                    }
                };
                let block_info = kyoto::HeaderCheckpoint {
                    height,
                    hash: block_hash,
                };
                pending_deposit.block_info = Some(block_info);
                block_info
            }
        };

        send_observation(
            &client_tx,
            outpoint,
            CachedDepositObservation::InBlock {
                height: block_info.height,
            },
        )
        .await;

        // Check if the deposit has enough confirmations yet.
        let confirmations = (tip.height + 1).saturating_sub(block_info.height);
        if confirmations < confirmation_threshold {
            debug!(
                "Transaction {} has {confirmations}/{confirmation_threshold} confirmations. Waiting for more blocks.",
                pending_deposit.outpoint.txid,
            );
            return;
        }

        // If deposit is confirmed, look up the TxOut info.
        let block = match requester.get_block(block_info.hash).await {
            Ok(block) => block,
            Err(kyoto::error::FetchBlockError::UnknownHash) => {
                // Error: The block is no longer in the current chain.
                // TODO: Verify kyoto won't return blocks outside the chain of most work
                warn!(
                    "Pending deposit {:?}: Block is no longer in the current chain",
                    pending_deposit.as_ref(),
                );
                pending_deposit.block_info = None;
                return;
            }
            Err(e) => {
                error!("Failed to look up block {}: {}", block_info.hash, e);
                return;
            }
        };
        let Some(transaction) = block
            .block
            .txdata
            .iter()
            .find(|tx| tx.compute_txid() == pending_deposit.outpoint.txid)
        else {
            // Error: The transaction is not actually in the block.
            warn!(
                "Pending deposit {:?}: Transaction not present in the block reported by the Bitcoin Core node! Possibly malicious behavior by the Bitcoin Core node.",
                pending_deposit.as_ref(),
            );
            pending_deposit.block_info = None;
            return;
        };

        let txout = match transaction.tx_out(pending_deposit.outpoint.vout.try_into().unwrap()) {
            Ok(txout) => txout.clone(),
            Err(e) => {
                send_forget(&client_tx, outpoint).await;
                let pending_deposit = pending_deposit.take();
                let _ = pending_deposit
                    .result_tx
                    .send(Err(anyhow::anyhow!(e).into()));
                return;
            }
        };

        // Verify the UTXO is still unspent in Bitcoin's UTXO set (including mempool).
        // Use raw `call()` because gettxout returns null when the UTXO is spent,
        // and the typed `get_tx_out` method doesn't return Option.
        let outpoint_txid = pending_deposit.outpoint.txid;
        let outpoint_vout = pending_deposit.outpoint.vout;
        let gettxout_result = btc_rpc_call(&bitcoind_rpc, move |rpc| {
            rpc.call::<Option<serde_json::Value>>(
                "gettxout",
                &[
                    serde_json::json!(outpoint_txid),
                    serde_json::json!(outpoint_vout),
                    serde_json::json!(true), // include_mempool
                ],
            )
        })
        .await;
        match gettxout_result {
            Ok(Some(_)) => {
                info!(
                    "Deposit {}:{} confirmed with {confirmations}/{confirmation_threshold} confirmations",
                    pending_deposit.outpoint.txid, pending_deposit.outpoint.vout,
                );
                send_forget(&client_tx, outpoint).await;
                let pending_deposit = pending_deposit.take();
                let _ = pending_deposit.result_tx.send(Ok(txout));
            }
            Ok(None) => {
                warn!(
                    "Deposit UTXO {}:{} has already been spent on Bitcoin. Rejecting deposit.",
                    pending_deposit.outpoint.txid, pending_deposit.outpoint.vout,
                );
                let txid = pending_deposit.outpoint.txid;
                let vout = pending_deposit.outpoint.vout;
                send_forget(&client_tx, outpoint).await;
                let pending_deposit = pending_deposit.take();
                let _ = pending_deposit
                    .result_tx
                    .send(Err(DepositConfirmError::UtxoSpent { txid, vout }));
            }
            Err(e) => {
                error!("Failed to check UTXO spent status via gettxout: {e}");
            }
        }
    }
}

/// GC stale entries from the cache, then write bucket counts into the
/// `deposit_request_confirmations` gauge.
fn rebuild_confirmation_metrics_inner(
    cache: &mut HashMap<bitcoin::OutPoint, CachedDepositEntry>,
    tip_height: u32,
    metrics: &Metrics,
) {
    let min_fresh = tip_height.saturating_sub(STALE_OBSERVATION_BLOCKS);
    cache.retain(|_, entry| entry.last_updated_tip >= min_fresh);

    let mut counts = [0i64; crate::metrics::CONFIRMATION_STATUS_LABELS.len()];
    for entry in cache.values() {
        let idx = match entry.observation {
            CachedDepositObservation::NotFound => 0,
            CachedDepositObservation::InMempool => 1,
            CachedDepositObservation::InBlock { height } => {
                let confirmations = (tip_height + 1).saturating_sub(height);
                // +2 skips the not_found/mempool slots; 0..=6 confirmations land in indices 2..=8.
                (2 + confirmations.min(6) as usize).min(8)
            }
        };
        counts[idx] += 1;
    }

    for (i, label) in crate::metrics::CONFIRMATION_STATUS_LABELS
        .iter()
        .enumerate()
    {
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .set(counts[i]);
    }
}

async fn send_observation(
    client_tx: &tokio::sync::mpsc::Sender<MonitorMessage>,
    outpoint: bitcoin::OutPoint,
    observation: CachedDepositObservation,
) {
    if let Err(e) = client_tx
        .send(MonitorMessage::RecordDepositObservation {
            outpoint,
            observation,
        })
        .await
    {
        debug!("Failed to record deposit observation (monitor shutting down?): {e}");
    }
}

async fn send_forget(
    client_tx: &tokio::sync::mpsc::Sender<MonitorMessage>,
    outpoint: bitcoin::OutPoint,
) {
    if let Err(e) = client_tx
        .send(MonitorMessage::ForgetDeposit(outpoint))
        .await
    {
        debug!("Failed to forget deposit observation (monitor shutting down?): {e}");
    }
}

#[derive(Debug)]
struct PendingDeposit {
    outpoint: bitcoin::OutPoint,
    /// Number of confirmations required to consider this deposit
    /// canonical. Captured at submit time from `OnchainState` so the
    /// monitor stays Sui-unaware. Stays with the deposit through any
    /// re-enqueues by `PendingDepositGuard`.
    confirmation_threshold: u32,
    block_info: Option<kyoto::HeaderCheckpoint>,
    result_tx: oneshot::Sender<Result<bitcoin::TxOut, DepositConfirmError>>,
    checked_at_height: u32,
}

/// RAII guard that re-enqueues a pending deposit on drop unless marked as complete.
struct PendingDepositGuard {
    deposit: Option<PendingDeposit>,
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl PendingDepositGuard {
    fn new(deposit: PendingDeposit, client_tx: tokio::sync::mpsc::Sender<MonitorMessage>) -> Self {
        Self {
            deposit: Some(deposit),
            client_tx,
        }
    }

    fn take(mut self) -> PendingDeposit {
        self.deposit.take().unwrap()
    }
}

impl std::ops::Deref for PendingDepositGuard {
    type Target = PendingDeposit;

    fn deref(&self) -> &Self::Target {
        self.deposit.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for PendingDepositGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.deposit.as_mut().unwrap()
    }
}

impl AsRef<PendingDeposit> for PendingDepositGuard {
    fn as_ref(&self) -> &PendingDeposit {
        self.deposit.as_ref().unwrap()
    }
}

impl Drop for PendingDepositGuard {
    fn drop(&mut self) {
        if let Some(deposit) = self.deposit.take()
            && let Err(e) = self
                .client_tx
                .try_send(MonitorMessage::ConfirmDeposit(deposit))
        {
            warn!("Failed to re-enqueue PendingDeposit on drop: {e}");
        }
    }
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    block_height_rx: tokio::sync::watch::Receiver<u32>,
}

impl MonitorClient {
    pub fn subscribe_block_height(&self) -> tokio::sync::watch::Receiver<u32> {
        self.block_height_rx.clone()
    }

    pub async fn confirm_deposit(
        &self,
        outpoint: bitcoin::OutPoint,
        confirmation_threshold: u32,
    ) -> Result<bitcoin::TxOut, DepositConfirmError> {
        let (tx, rx) = oneshot::channel();
        let pending_deposit = PendingDeposit {
            outpoint,
            confirmation_threshold,
            block_info: None,
            result_tx: tx,
            checked_at_height: 0,
        };
        self.tx
            .send(MonitorMessage::ConfirmDeposit(pending_deposit))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .map_err(|_| {
                anyhow::anyhow!("confirm_deposit timed out waiting for Bitcoin confirmation")
            })?
            .map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn get_recent_fee_rate(&self, conf_target: u16) -> Result<FeeRate> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::GetRecentFeeRate(conf_target, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn broadcast_transaction(&self, transaction: bitcoin::Transaction) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::BroadcastTransaction(transaction, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn get_transaction_status(&self, txid: bitcoin::Txid) -> Result<TxStatus> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::GetTransactionStatus(txid, tx))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }
}

enum MonitorMessage {
    // Locates the given OutPoint in a block, waits for it to have enough
    // confirmations, and returns output information. Will keep trying to
    // confirm indefinitely, unless the proivded channel is closed.
    ConfirmDeposit(PendingDeposit),

    // Returns an estimated fee rate targeting confirmation within `conf_target` blocks.
    GetRecentFeeRate(u16, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),

    // Query the status of a transaction (confirmed, in mempool, or not found).
    GetTransactionStatus(bitcoin::Txid, oneshot::Sender<Result<TxStatus>>),

    // Updates `deposit_observation_cache`
    RecordDepositObservation {
        outpoint: bitcoin::OutPoint,
        observation: CachedDepositObservation,
    },

    // Drop a deposit from `deposit_observation_cache`
    ForgetDeposit(bitcoin::OutPoint),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    fn make_outpoint(seed: u8) -> bitcoin::OutPoint {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array(bytes),
            vout: 0,
        }
    }

    fn fresh_metrics() -> Metrics {
        Metrics::new(&prometheus::Registry::new())
    }

    fn bucket(metrics: &Metrics, label: &str) -> i64 {
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .get()
    }

    fn entry(observation: CachedDepositObservation, last_updated_tip: u32) -> CachedDepositEntry {
        CachedDepositEntry {
            observation,
            last_updated_tip,
        }
    }

    #[test]
    fn empty_cache_writes_all_labels_as_zero() {
        let metrics = fresh_metrics();
        let mut cache: HashMap<bitcoin::OutPoint, CachedDepositEntry> = HashMap::new();

        rebuild_confirmation_metrics_inner(&mut cache, 100, &metrics);

        for label in crate::metrics::CONFIRMATION_STATUS_LABELS {
            assert_eq!(bucket(&metrics, label), 0, "label {label} should be zero");
        }
    }

    #[test]
    fn observation_to_bucket_mapping() {
        // (observation, tip, expected bucket). Covers NotFound, InMempool,
        // and InBlock at 0 (height > tip via saturating_sub), 1, 5, 6 (boundary),
        // and a far-clamp case.
        let cases: &[(CachedDepositObservation, u32, &str)] = &[
            (CachedDepositObservation::NotFound, 100, "not_found"),
            (CachedDepositObservation::InMempool, 100, "mempool"),
            (CachedDepositObservation::InBlock { height: 101 }, 100, "0"),
            (CachedDepositObservation::InBlock { height: 100 }, 100, "1"),
            (CachedDepositObservation::InBlock { height: 96 }, 100, "5"),
            (
                CachedDepositObservation::InBlock { height: 95 },
                100,
                "6_plus",
            ),
            (
                CachedDepositObservation::InBlock { height: 0 },
                100,
                "6_plus",
            ),
        ];

        for &(observation, tip, want_label) in cases {
            let metrics = fresh_metrics();
            let mut cache = HashMap::from([(make_outpoint(1), entry(observation, tip))]);
            rebuild_confirmation_metrics_inner(&mut cache, tip, &metrics);
            assert_eq!(
                bucket(&metrics, want_label),
                1,
                "{observation:?} with tip {tip} should land in {want_label}"
            );
        }
    }

    #[test]
    fn tip_advance_shifts_buckets_without_fresh_observations() {
        let metrics = fresh_metrics();
        let mut cache = HashMap::from([(
            make_outpoint(1),
            entry(CachedDepositObservation::InBlock { height: 100 }, 100),
        )]);

        // Tip 100: confirmations = (100+1) - 100 = 1 → bucket "1".
        rebuild_confirmation_metrics_inner(&mut cache, 100, &metrics);
        assert_eq!(bucket(&metrics, "1"), 1);

        // Tip 101 (no re-observation): confirmations = 2 → bucket "2".
        rebuild_confirmation_metrics_inner(&mut cache, 101, &metrics);
        assert_eq!(bucket(&metrics, "1"), 0);
        assert_eq!(bucket(&metrics, "2"), 1);
    }

    #[test]
    fn stale_entries_gced_at_inclusive_boundary() {
        let metrics = fresh_metrics();
        let tip = 100;
        let mut cache = HashMap::from([
            // On the boundary: kept (inclusive).
            (
                make_outpoint(1),
                entry(
                    CachedDepositObservation::InMempool,
                    tip - STALE_OBSERVATION_BLOCKS,
                ),
            ),
            // Just past the boundary: dropped.
            (
                make_outpoint(2),
                entry(
                    CachedDepositObservation::InMempool,
                    tip - STALE_OBSERVATION_BLOCKS - 1,
                ),
            ),
        ]);

        rebuild_confirmation_metrics_inner(&mut cache, tip, &metrics);

        assert_eq!(cache.len(), 1, "entry past boundary should be GC'd");
        assert!(cache.contains_key(&make_outpoint(1)));
        assert_eq!(bucket(&metrics, "mempool"), 1);
    }

    #[test]
    fn tip_zero_bootstrap_keeps_entries() {
        // Before the first block, tip is 0. Entries with `last_updated_tip = 0`
        // must not be GC'd immediately, otherwise fresh observations would
        // vanish before the first block arrives.
        let metrics = fresh_metrics();
        let mut cache = HashMap::from([(
            make_outpoint(1),
            entry(CachedDepositObservation::InMempool, 0),
        )]);

        rebuild_confirmation_metrics_inner(&mut cache, 0, &metrics);

        assert_eq!(cache.len(), 1);
        assert_eq!(bucket(&metrics, "mempool"), 1);
    }
}
