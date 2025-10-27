use anyhow::Result;
use kyoto::FeeRate;
use kyoto::HeaderCheckpoint;
use tokio::sync::oneshot;
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
    requester: kyoto::Requester,
    tip: Option<HeaderCheckpoint>,
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

        let mut monitor = Self {
            config,
            requester: kyoto_client.requester.clone(),
            tip: None,
        };
        let (client_tx, mut client_rx) = tokio::sync::mpsc::channel(100);

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

        Ok(MonitorClient { _tx: client_tx })
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
    }

    fn process_blocks_disconnected(
        &mut self,
        accepted: Vec<kyoto::chain::IndexedHeader>,
        disconnected: Vec<kyoto::chain::IndexedHeader>,
    ) {
        info!(
            "Processing reorg with {} accepted blocks and {} disconnected blocks",
            accepted.len(),
            disconnected.len()
        );
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            MonitorMessage::ConfirmDeposit(txid, script, result_tx) => {
                self.confirm_deposit(txid, script, result_tx);
            }
            MonitorMessage::GetRecentFeeRate(percentile, result_tx) => {
                self.get_recent_fee_rate(percentile, result_tx);
            }
            MonitorMessage::BroadcastTransaction(tx, result_tx) => {
                self.broadcast_transaction(tx, result_tx);
            }
        }
    }

    fn confirm_deposit(
        &mut self,
        _txid: bitcoin::Txid,
        _script: bitcoin::ScriptBuf,
        _result_tx: oneshot::Sender<Result<()>>,
    ) {
        todo!()
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
        _result_tx: oneshot::Sender<Result<()>>,
    ) {
        let _ = self.requester.broadcast_tx(kyoto::TxBroadcast {
            tx,
            broadcast_policy: kyoto::TxBroadcastPolicy::AllPeers,
        });
        todo!()
    }
}

pub struct MonitorClient {
    _tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl MonitorClient {
    // TODO: Wrap messages below with client functions.
}

enum MonitorMessage {
    // Locates the given transaction in a block, waits for it to have enough
    // confirmations, and returns deposit information. Will wait indefinitely
    // unless the proivded channel is closed.
    ConfirmDeposit(
        bitcoin::Txid,
        bitcoin::ScriptBuf,
        oneshot::Sender<Result<()>>,
    ),

    // Returns the Nth-percentile fee rate of confirmed transactions on the
    // network, over the last several blocks.
    // TODO: should lookback window be configurable?
    GetRecentFeeRate(u32, oneshot::Sender<Result<FeeRate>>),

    // Broadcast a transaction to the network.
    BroadcastTransaction(bitcoin::Transaction, oneshot::Sender<Result<()>>),
}
