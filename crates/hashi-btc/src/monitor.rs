use std::sync::Arc;

use anyhow::Result;
use bitcoincore_rpc::RpcApi;
use kyoto::FeeRate;
use kyoto::HeaderCheckpoint;
use tokio::sync::oneshot;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::config::MonitorConfig;

/// Monitor loop that tracks the state of the Bitcoin chain.
///
/// Client provides functions for querying for specific transactions,
/// fee information, and transaction submission.
pub struct Monitor {
    config: MonitorConfig,
    bitcoind_rpc: Arc<bitcoincore_rpc::Client>,
    client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
    requester: kyoto::Requester,
    tip: Option<HeaderCheckpoint>,
    pending_deposits: Vec<PendingDeposit>,
}

impl Monitor {
    /// Run a BTC monitor with the given configuration.
    pub fn run(config: MonitorConfig) -> Result<MonitorClient> {
        let (kyoto_node, mut kyoto_client) = kyoto::NodeBuilder::new(config.network)
            .add_peers(config.trusted_peers.iter().cloned())
            // TODO: should we set this higher than default?
            // .required_peers(num_peers)
            // Need a dummy script to prevent default match on every single block.
            // TODO: Remove once commit
            // https://github.com/rust-bitcoin/rust-bitcoin/commit/e7d992a5ff75807ec454655d112a671294a101dd
            // is available in a released version of the bitcoin crate.
            .add_scripts(vec![bitcoin::ScriptBuf::new()])
            .after_checkpoint(kyoto::HeaderCheckpoint::closest_checkpoint_below_height(
                config.start_height,
                config.network,
            ))
            .build()?;

        let bitcoind_rpc = bitcoincore_rpc::Client::new(
            config.bitcoind_rpc_url.as_str(),
            config.bitcoind_rpc_auth.clone(),
        )?;

        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);
        let mut monitor = Self {
            config,
            bitcoind_rpc: Arc::new(bitcoind_rpc),
            requester: kyoto_client.requester.clone(),
            client_tx: client_tx.clone(),
            tip: None,
            pending_deposits: vec![],
        };

        // Spawn tasks.
        tokio::spawn(async move {
            info!("Starting Kyoto node");
            if let Err(e) = kyoto_node.run().await {
                error!("Kyoto node error: {}", e);
            }
        });
        tokio::spawn(async move {
            info!(
                "Starting Bitcoin monitor for network: {:?}",
                monitor.config.network
            );
            loop {
                tokio::select! {
                    Some(event) = kyoto_client.event_rx.recv() => {
                        monitor.process_kyoto_event(event);
                    }
                    Some(msg) = client_rx.recv() => {
                        monitor.process_client_message(msg);
                    }
                    Some(msg) = kyoto_client.info_rx.recv() => {
                        info!("Kyoto: {msg}");
                    }
                    Some(msg) = kyoto_client.warn_rx.recv() => {
                        warn!("Kyoto: {msg}");
                    }
                    else => {
                        break;
                    }
                }
            }
            info!("Bitcoin monitor stopped");
        });

        Ok(MonitorClient { tx: client_tx })
    }

    fn process_kyoto_event(&mut self, event: kyoto::Event) {
        match event {
            kyoto::Event::Block(block) => self.process_block(block),
            kyoto::Event::Synced(sync_update) => self.process_synced(sync_update),
            kyoto::Event::BlocksDisconnected {
                accepted,
                disconnected,
            } => self.process_blocks_disconnected(accepted, disconnected),
        }
    }

    fn process_block(&mut self, block: kyoto::IndexedBlock) {
        info!(
            "Got block {} at height {} with {} transactions",
            block.block.block_hash(),
            block.height,
            block.block.txdata.len()
        );
    }

    fn process_synced(&mut self, sync_update: kyoto::messages::SyncUpdate) {
        let tip = sync_update.tip;
        info!(
            "Synchronized to height {} ({}) with {} recent headers",
            tip.height,
            tip.hash,
            sync_update.recent_history.len()
        );
        self.tip = Some(tip);
        self.process_pending_deposits();
    }

    fn process_blocks_disconnected(
        &mut self,
        accepted: Vec<kyoto::chain::IndexedHeader>,
        disconnected: Vec<kyoto::chain::IndexedHeader>,
    ) {
        info!(
            "Got reorg with {} accepted blocks and {} disconnected blocks",
            accepted.len(),
            disconnected.len()
        );
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::ConfirmDeposit(pending_deposit) => {
                self.confirm_deposit(pending_deposit);
            }
            MonitorMessage::GetRecentFeeRate(percentile, result_tx) => {
                self.get_recent_fee_rate(percentile, result_tx);
            }
            MonitorMessage::BroadcastTransaction(tx, result_tx) => {
                self.broadcast_transaction(tx, result_tx);
            }
        }
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

        tokio::spawn(Monitor::process_pending_deposit(
            tip.to_owned(),
            self.config.confirmation_threshold,
            self.bitcoind_rpc.clone(),
            self.requester.clone(),
            self.client_tx.clone(),
            pending_deposit,
        ));
    }

    fn get_recent_fee_rate(
        &mut self,
        _percentile: u32,
        _result_tx: oneshot::Sender<Result<FeeRate>>,
    ) {
        todo!()
    }

    fn broadcast_transaction(
        &mut self,
        tx: bitcoin::Transaction,
        result_tx: oneshot::Sender<Result<()>>,
    ) {
        let result = self.requester.broadcast_tx(kyoto::TxBroadcast {
            tx,
            broadcast_policy: kyoto::TxBroadcastPolicy::AllPeers,
        });
        let _ = result_tx.send(result.map_err(|e| anyhow::anyhow!(e)));
    }

    fn process_pending_deposits(&mut self) {
        let Some(tip) = &self.tip else {
            // Can't confirm deposits if we don't yet know the tip of the chain.
            return;
        };

        info!(
            "Reprocessing {} pending deposits",
            self.pending_deposits.len()
        );
        for pending_deposit in std::mem::take(&mut self.pending_deposits) {
            tokio::spawn(Monitor::process_pending_deposit(
                tip.to_owned(),
                self.config.confirmation_threshold,
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
        bitcoind_rpc: Arc<bitcoincore_rpc::Client>,
        requester: kyoto::Requester,
        client_tx: tokio::sync::mpsc::Sender<MonitorMessage>,
        mut pending_deposit: PendingDeposit,
    ) {
        if pending_deposit.result_tx.is_closed() {
            // Cancel if the receiver is no longer listening.
            return;
        }

        pending_deposit.checked_at_height = tip.height;
        let mut pending_deposit = PendingDepositGuard::new(pending_deposit, client_tx);

        // Look up block from the txid.
        let block_info = match pending_deposit.block_info {
            Some(block_info) => block_info,
            None => {
                debug!(
                    "Looking up block for transaction {}",
                    pending_deposit.outpoint.txid
                );
                let tx_info = match bitcoind_rpc
                    .get_raw_transaction_info(&pending_deposit.outpoint.txid, None)
                {
                    Ok(tx_info) => tx_info,
                    Err(e) => {
                        error!(
                            "Failed to look up txid {}: {e}",
                            pending_deposit.outpoint.txid
                        );
                        return;
                    }
                };
                let Some(block_hash) = tx_info.blockhash else {
                    debug!(
                        "Transaction {} is not yet included in a block",
                        pending_deposit.outpoint.txid
                    );
                    return;
                };
                let block_header = match bitcoind_rpc.get_block_header_info(&block_hash) {
                    Ok(block_header) => block_header,
                    Err(e) => {
                        error!("Failed to look up block header {}: {e}", block_hash);
                        return;
                    }
                };
                // Double check header with Kyoto to verify the height reported by bitcoind.
                let kyoto_header = match requester.get_header(block_header.height as u32).await {
                    Ok(kyoto_header) => kyoto_header,
                    Err(e) => {
                        error!(
                            "Failed to look up header at height {}: {e}",
                            block_header.height
                        );
                        return;
                    }
                };
                if kyoto_header.block_hash() != block_hash {
                    warn!(
                        "Block hash mismatch at height {}! Possibly malicious behavior by the Bitcoin Core node. {} != {}",
                        block_header.height,
                        kyoto_header.block_hash(),
                        block_hash
                    );
                    return;
                }
                let block_info = kyoto::HeaderCheckpoint {
                    height: block_header.height as u32,
                    hash: block_header.hash,
                };
                pending_deposit.block_info = Some(block_info);
                block_info
            }
        };

        // Check if the deposit has enough confirmations yet.
        if block_info.height > tip.height - confirmation_threshold - 1 {
            debug!(
                "Transaction {} is not yet confirmed. Block height is {}, tip is {}. Waiting for more blocks.",
                pending_deposit.outpoint.txid, block_info.height, tip.height
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

        let result = transaction.tx_out(pending_deposit.outpoint.vout.try_into().unwrap());
        let pending_deposit = pending_deposit.take();
        let _ = pending_deposit
            .result_tx
            .send(result.cloned().map_err(|e| e.into()));
    }
}

#[derive(Debug)]
struct PendingDeposit {
    outpoint: bitcoin::OutPoint,
    block_info: Option<kyoto::HeaderCheckpoint>,
    result_tx: oneshot::Sender<Result<bitcoin::TxOut>>,
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
        if let Some(deposit) = self.deposit.take() {
            let client_tx = self.client_tx.clone();
            tokio::spawn(async move {
                client_tx
                    .send(MonitorMessage::ConfirmDeposit(deposit))
                    .await
                    .expect("re-enqueue PendingDeposit must succeed");
            });
        }
    }
}

#[derive(Clone)]
pub struct MonitorClient {
    tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl MonitorClient {
    pub async fn confirm_deposit(&self, outpoint: bitcoin::OutPoint) -> Result<bitcoin::TxOut> {
        let (tx, rx) = oneshot::channel();
        let pending_deposit = PendingDeposit {
            outpoint,
            block_info: None,
            result_tx: tx,
            checked_at_height: 0,
        };
        self.tx
            .send(MonitorMessage::ConfirmDeposit(pending_deposit))
            .await
            .map_err(|e| anyhow::anyhow!(e))?;
        rx.await.map_err(|e| anyhow::anyhow!(e))?
    }

    pub async fn get_recent_fee_rate(&self, percentile: u32) -> Result<FeeRate> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(MonitorMessage::GetRecentFeeRate(percentile, tx))
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
}

enum MonitorMessage {
    // Locates the given OutPoint in a block, waits for it to have enough
    // confirmations, and returns output information. Will keep trying to
    // confirm indefinitely, unless the proivded channel is closed.
    ConfirmDeposit(PendingDeposit),

    // Returns the Nth-percentile fee rate of confirmed transactions on the
    // network, over the last several blocks.
    // TODO: should lookback window be configurable?
    GetRecentFeeRate(u32, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),
}
