use anyhow::Result;
use bdk_chain::local_chain::LocalChain;
use bdk_core::BlockId;
use tracing::debug;
use tracing::error;
use tracing::info;

use crate::config::MontiorConfig;

// TODO: doc comment
pub struct Monitor {
    config: MontiorConfig,

    local_chain: LocalChain,
}

impl Monitor {
    /// Create a new UTXO pool with the given configuration.
    pub fn new(config: MontiorConfig) -> Result<Self> {
        let genesis_hash = match config.network {
            bitcoin::Network::Bitcoin => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).block_hash()
            }
            bitcoin::Network::Testnet => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet).block_hash()
            }
            bitcoin::Network::Testnet4 => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Testnet4)
                    .block_hash()
            }
            bitcoin::Network::Signet => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Signet).block_hash()
            }
            bitcoin::Network::Regtest => {
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).block_hash()
            }
        };
        let (local_chain, _) = LocalChain::from_genesis_hash(genesis_hash);

        Ok(Self {
            config,
            local_chain,
        })
    }

    pub fn run(mut self) -> Result<MonitorClient> {
        let (kyoto_node, mut kyoto_client) = kyoto::NodeBuilder::new(self.config.network)
            .add_peers(self.config.trusted_peers.iter().cloned())
            // TODO: should we set this higher than default?
            // .required_peers(num_peers)
            .after_checkpoint(kyoto::HeaderCheckpoint::closest_checkpoint_below_height(
                self.config.start_height,
                self.config.network,
            ))
            .build()?;

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
                self.config.network
            );
            loop {
                tokio::select! {
                    Some(event) = kyoto_client.event_rx.recv() => {
                        self.process_kyoto_event(event);
                    }
                    Some(msg) = client_rx.recv() => {
                        self.process_client_message(msg);
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

    // TODO: make sure this can't race with newly added addresses from Sui.
    fn process_block(&mut self, block: kyoto::IndexedBlock) {
        let block_id = BlockId {
            height: block.height,
            hash: block.block.block_hash(),
        };
        debug!(
            "Processing block {block_id:?} with {} transactions",
            block.block.txdata.len()
        );

        // Update local data structures with any relevant tx (from our watched addresses).
        // TODO: persist changesets for crash recovery
        let _chain_changeset = self
            .local_chain
            .insert_block(block_id)
            .expect("insert_block must not fail");
    }

    fn process_synced(&mut self, sync_update: kyoto::messages::SyncUpdate) {
        let tip = sync_update.tip();
        debug!("Synchronized to height {} ({})", tip.height, tip.hash);

        self.local_chain
            .insert_block(BlockId {
                height: tip.height,
                hash: tip.hash,
            })
            .expect("insert_block must not fail");

        // TODO: check whether any requested txid are now considered confirmed?
    }

    fn process_blocks_disconnected(
        &mut self,
        accepted: Vec<kyoto::chain::IndexedHeader>,
        disconnected: Vec<kyoto::chain::IndexedHeader>,
    ) {
        debug!(
            "Processing reorg with {} accepted blocks and {} disconnected blocks",
            accepted.len(),
            disconnected.len()
        );

        let mut changeset = bdk_chain::local_chain::ChangeSet::default();
        for block in disconnected {
            changeset.blocks.insert(block.height, None);
        }
        for block in accepted {
            changeset
                .blocks
                .insert(block.height, Some(block.block_hash()));
        }
        self.local_chain
            .apply_changeset(&changeset)
            .expect("apply_changeset must not fail");
    }

    fn process_client_message(&mut self, msg: MonitorMessage) {
        match msg {
            // No variants yet
        }
    }
}

pub struct MonitorClient {
    _tx: tokio::sync::mpsc::Sender<MonitorMessage>,
}

impl MonitorClient {
    // TODO: this wraps the pool messages to provide a functional query interface to
    // the pool event loop
}

enum MonitorMessage {
    // add a subscriber which reports deposits, withdrawals
    //   with some kind of starting timestamp or seq number? or just start from current and then
    // request info e.g. current utxo set
    // request a withdrawal - are eligible utxos provided? or do we somehow also keep seq numbers in here?
    // request governance actions e.g. key rotation

    // how do we do persistence?
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::CompactTarget;
    use bitcoin::Transaction;
    use bitcoin::block::Header;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;

    fn create_test_pool() -> Monitor {
        let config = MontiorConfig {
            network: bitcoin::Network::Regtest,
            confirmation_threshold: 6,
            trusted_peers: vec![],
            start_height: 0,
        };
        Monitor::new(config).expect("Failed to create test pool")
    }

    fn create_test_block(height: u32, transactions: Vec<Transaction>) -> kyoto::IndexedBlock {
        let header = Header {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        };

        let block = Block {
            header,
            txdata: transactions,
        };

        kyoto::IndexedBlock { height, block }
    }

    #[test]
    fn test_process_block_empty() {
        let mut pool = create_test_pool();

        let block = create_test_block(100, vec![]);
        pool.process_block(block);

        // Verify the chain was updated.
        let chain_tip = pool.local_chain.tip();
        assert_eq!(chain_tip.height(), 100);
    }

    #[test]
    fn test_process_synced_update_chain_tip() {
        use std::collections::BTreeMap;

        let mut pool = create_test_pool();

        let sync_update = kyoto::messages::SyncUpdate {
            tip: kyoto::chain::checkpoints::HeaderCheckpoint {
                hash: BlockHash::all_zeros(),
                height: 500,
            },
            recent_history: BTreeMap::new(),
        };

        pool.process_synced(sync_update);

        // Verify chain tip was updated.
        let chain_tip = pool.local_chain.tip();
        assert_eq!(chain_tip.height(), 500);
    }

    #[test]
    fn test_process_blocks_disconnected() {
        let mut pool = create_test_pool();

        // First, process some blocks that will later be disconnected.
        let block1 = create_test_block(100, vec![]);
        pool.process_block(block1);

        let block2 = create_test_block(101, vec![]);
        pool.process_block(block2);

        let block3 = create_test_block(102, vec![]);
        pool.process_block(block3);

        // Verify these blocks are in the chain.
        assert_eq!(pool.local_chain.tip().height(), 102);

        // Now create headers for disconnection that match our processed blocks.
        let disconnected = vec![
            kyoto::chain::IndexedHeader {
                height: 100,
                header: Header {
                    version: Version::from_consensus(1),
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                },
            },
            kyoto::chain::IndexedHeader {
                height: 101,
                header: Header {
                    version: Version::from_consensus(1),
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                },
            },
            kyoto::chain::IndexedHeader {
                height: 102,
                header: Header {
                    version: Version::from_consensus(1),
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 0,
                },
            },
        ];

        // Create new accepted blocks with different hashes (different nonces).
        let accepted = vec![
            kyoto::chain::IndexedHeader {
                height: 100,
                header: Header {
                    version: Version::from_consensus(1),
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 999,
                },
            },
            kyoto::chain::IndexedHeader {
                height: 101,
                header: Header {
                    version: Version::from_consensus(1),
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: bitcoin::hash_types::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: CompactTarget::from_consensus(0),
                    nonce: 1000,
                },
            },
        ];

        // Process the reorg.
        pool.process_blocks_disconnected(accepted.clone(), disconnected);

        // Verify the chain tip is from the replacement blocks.
        let chain_tip = pool.local_chain.tip();
        assert_eq!(chain_tip.height(), 101);
        assert_eq!(chain_tip.hash(), accepted[1].block_hash());
    }
}
