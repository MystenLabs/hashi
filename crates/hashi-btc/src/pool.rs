use anyhow::Result;
use bdk_chain::IndexedTxGraph;
use bdk_chain::local_chain::LocalChain;
use bdk_chain::spk_txout::SpkTxOutIndex;
use bdk_core::BlockId;
use bitcoin::ScriptBuf;
use tracing::debug;
use tracing::error;
use tracing::info;

use crate::config::PoolConfig;

// TODO: doc comment
pub struct Pool {
    config: PoolConfig,

    tx_graph: IndexedTxGraph<BlockId, SpkTxOutIndex<ScriptBuf>>,
    local_chain: LocalChain,
}

impl Pool {
    /// Create a new UTXO pool with the given configuration.
    pub fn new(config: PoolConfig) -> Result<Self> {
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

        // Add initial scripts to monitor.
        let mut spk_index = SpkTxOutIndex::default();
        for script in config.monitored_scripts.iter() {
            spk_index.insert_spk(script.clone(), script.clone());
        }

        let tx_graph = IndexedTxGraph::new(spk_index);
        let (local_chain, _) = LocalChain::from_genesis_hash(genesis_hash);

        Ok(Self {
            config,
            tx_graph,
            local_chain,
        })
    }

    pub fn run(mut self) -> Result<PoolClient> {
        let (kyoto_node, mut kyoto_client) = kyoto::NodeBuilder::new(self.config.network)
            .add_scripts(self.tx_graph.index.all_spks().values().cloned())
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
                "Starting UTXO pool monitoring for network: {:?}",
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
            info!("UTXO pool monitoring stopped");
        });

        Ok(PoolClient { _tx: client_tx })
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
        let graph_changeset = self
            .tx_graph
            .apply_block_relevant(&block.block, block.height);
        self.dump_changeset(&graph_changeset, &block_id); // TODO: eventually remove debug logs

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

        // TODO: emit oracle events for newly confirmed deposits, spends, etc. at this point
        // (but if we only get this msg once, also need a way to do it periodically in the absence
        // of new matching block deliveries)
        // For now just dump some stats.
        self.dump_utxo_stats();
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

    fn process_client_message(&mut self, msg: PoolMessage) {
        match msg {
            // No variants yet
        }
    }

    fn dump_changeset(
        &self,
        changeset: &bdk_chain::indexed_tx_graph::ChangeSet<
            BlockId,
            <SpkTxOutIndex<u32> as bdk_chain::indexer::Indexer>::ChangeSet,
        >,
        block_id: &BlockId,
    ) {
        // Log added UTXOs from whole transactions (relevant to our watched addresses)
        let mut added_utxos = Vec::new();

        // Check all new transactions for relevant outputs
        for tx in &changeset.tx_graph.txs {
            for (vout, txout) in tx.output.iter().enumerate() {
                // Check if this output matches any of our monitored scripts
                if self
                    .tx_graph
                    .index
                    .index_of_spk(txout.script_pubkey.clone())
                    .is_some()
                {
                    added_utxos.push((tx.compute_txid(), vout as u32, txout));
                }
            }
        }

        // Also include partial txouts if any
        for (outpoint, txout) in &changeset.tx_graph.txouts {
            if self
                .tx_graph
                .index
                .index_of_spk(txout.script_pubkey.clone())
                .is_some()
            {
                added_utxos.push((outpoint.txid, outpoint.vout, txout));
            }
        }

        // Log the added UTXOs
        if !added_utxos.is_empty() {
            info!("=== Added UTXOs in block {} ===", block_id.hash);
            for (txid, vout, txout) in &added_utxos {
                info!(
                    "  Added UTXO: {}:{} value={} sat, script={}",
                    txid,
                    vout,
                    txout.value.to_sat(),
                    txout.script_pubkey
                );
            }
        }

        // Log spent UTXOs (only from relevant transactions that our indexer tracks)
        if !changeset.tx_graph.txs.is_empty() {
            let mut has_spent = false;
            for tx in &changeset.tx_graph.txs {
                // Skip coinbase transactions (they don't spend UTXOs)
                if !tx.is_coinbase() {
                    for input in &tx.input {
                        // Check if this input spends a UTXO we're tracking
                        if let Some(prev_out) =
                            self.tx_graph.graph().get_txout(input.previous_output)
                        {
                            if !has_spent {
                                info!("=== Spent UTXOs in block {} ===", block_id.hash);
                                has_spent = true;
                            }
                            info!(
                                "  Spent UTXO: {}:{} value={} sat (spent by tx {})",
                                input.previous_output.txid,
                                input.previous_output.vout,
                                prev_out.value.to_sat(),
                                tx.compute_txid()
                            );
                        }
                    }
                }
            }
        }

        // Log transaction summary
        if !changeset.tx_graph.txs.is_empty() || !changeset.tx_graph.txouts.is_empty() {
            info!(
                "Block {} summary: {} relevant txs, {} added outputs",
                block_id.hash,
                changeset.tx_graph.txs.len(),
                added_utxos.len()
            );
        }
    }

    fn dump_utxo_stats(&self) {
        use bdk_chain::CanonicalizationParams;
        use bdk_chain::ChainPosition;
        use std::collections::HashMap;

        let chain_tip = self.local_chain.tip();
        let tip_height = chain_tip.height();

        // Only consider UTXOs with at least 6 confirmations
        if tip_height < self.config.confirmation_threshold {
            return;
        }
        let max_confirmed_height = tip_height - self.config.confirmation_threshold;

        // Group UTXOs by script pubkey: (unspent_count, spent_count, unspent_balance)
        let mut stats_by_script: HashMap<bitcoin::ScriptBuf, (usize, usize, u64)> = HashMap::new();

        // Get all outpoints from the indexer
        let outpoints = self.tx_graph.index.outpoints();

        // Filter to get canonical UTXOs
        let params = CanonicalizationParams::default();
        let utxos = self.tx_graph.graph().filter_chain_txouts(
            &self.local_chain,
            chain_tip.block_id(),
            params,
            outpoints.iter().cloned(),
        );

        for (_, full_txout) in utxos {
            // Check confirmation depth using the confirmation_height_upper_bound method
            let is_confirmed = match &full_txout.chain_position {
                ChainPosition::Confirmed { anchor, .. } => {
                    // Use the anchor's height (upper bound for confirmation)
                    anchor.height <= max_confirmed_height
                }
                ChainPosition::Unconfirmed { .. } => false,
            };

            if is_confirmed {
                let entry = stats_by_script
                    .entry(full_txout.txout.script_pubkey.clone())
                    .or_insert((0, 0, 0));

                // Check if this UTXO is spent
                if full_txout.spent_by.is_some() {
                    entry.1 += 1; // increment spent UTXO count
                // Don't add to balance since it's spent
                } else {
                    entry.0 += 1; // increment unspent UTXO count
                    entry.2 += full_txout.txout.value.to_sat(); // add to unspent balance
                }
            }
        }

        // Log the stats
        if !stats_by_script.is_empty() {
            info!(
                "=== UTXO Stats at height {} ({}+ confirmations) ===",
                tip_height, self.config.confirmation_threshold,
            );
            for (script, (unspent_count, spent_count, balance)) in stats_by_script {
                if spent_count > 0 {
                    info!(
                        "  Address {}: {} unspent UTXOs ({} sat), {} spent UTXOs",
                        script, unspent_count, balance, spent_count
                    );
                } else {
                    info!(
                        "  Address {}: {} unspent UTXOs ({} sat)",
                        script, unspent_count, balance
                    );
                }
            }
        } else {
            info!(
                "No confirmed UTXOs found for tracked addresses (height {})",
                tip_height
            );
        }
    }
}

pub struct PoolClient {
    _tx: tokio::sync::mpsc::Sender<PoolMessage>,
}

impl PoolClient {
    // TODO: this wraps the pool messages to provide a functional query interface to
    // the pool event loop
}

enum PoolMessage {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Amount;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::CompactTarget;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::Sequence;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::Txid;
    use bitcoin::Witness;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Header;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;

    fn create_test_pool() -> Pool {
        create_test_pool_with_scripts(vec![])
    }

    fn create_test_pool_with_scripts(scripts: Vec<ScriptBuf>) -> Pool {
        let config = PoolConfig {
            network: bitcoin::Network::Regtest,
            confirmation_threshold: 6,
            trusted_peers: vec![],
            start_height: 0,
            monitored_scripts: scripts,
        };
        Pool::new(config).expect("Failed to create test pool")
    }

    fn create_test_script() -> ScriptBuf {
        // Use a simple P2WPKH script for testing.
        ScriptBuf::from_hex("0014abcd1234abcd1234abcd1234abcd1234abcd1234").unwrap()
    }

    fn create_test_transaction(
        inputs: Vec<(Txid, u32)>,
        outputs: Vec<(ScriptBuf, u64)>,
    ) -> Transaction {
        let tx_ins: Vec<TxIn> = inputs
            .into_iter()
            .map(|(txid, vout)| TxIn {
                previous_output: OutPoint { txid, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect();

        let tx_outs: Vec<TxOut> = outputs
            .into_iter()
            .map(|(script_pubkey, value)| TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            })
            .collect();

        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: tx_outs,
        }
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
    fn test_process_block_with_relevant_transactions() {
        let script = create_test_script();
        let mut pool = create_test_pool_with_scripts(vec![script.clone()]);

        // Create a transaction that outputs to our monitored script.
        let tx =
            create_test_transaction(vec![(Txid::all_zeros(), 0)], vec![(script.clone(), 50_000)]);

        let block = create_test_block(100, vec![tx.clone()]);
        pool.process_block(block);

        // Verify the transaction was added to the graph.
        let graph_tx = pool.tx_graph.graph().get_tx(tx.compute_txid());
        assert!(graph_tx.is_some());
    }

    #[test]
    fn test_process_block_with_irrelevant_transactions() {
        let monitored_script = create_test_script();
        let mut pool = create_test_pool_with_scripts(vec![monitored_script]);

        // Create a transaction with outputs to a different script.
        let other_script =
            ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let tx =
            create_test_transaction(vec![(Txid::all_zeros(), 0)], vec![(other_script, 50_000)]);

        let block = create_test_block(100, vec![tx.clone()]);
        pool.process_block(block);

        // The transaction should not be in the graph.
        let graph_tx = pool.tx_graph.graph().get_tx(tx.compute_txid());
        assert!(graph_tx.is_none());
    }

    #[test]
    fn test_process_block_with_spent_utxos() {
        let script = create_test_script();
        let mut pool = create_test_pool_with_scripts(vec![script.clone()]);

        // First block: Create a UTXO.
        let tx1 = create_test_transaction(
            vec![(Txid::all_zeros(), 0)],
            vec![(script.clone(), 100_000)],
        );
        let block1 = create_test_block(100, vec![tx1.clone()]);
        pool.process_block(block1);

        // Second block: Spend the UTXO.
        let other_script =
            ScriptBuf::from_hex("76a914000000000000000000000000000000000000000088ac").unwrap();
        let tx2 =
            create_test_transaction(vec![(tx1.compute_txid(), 0)], vec![(other_script, 90_000)]);
        let block2 = create_test_block(101, vec![tx2.clone()]);
        pool.process_block(block2);

        // Both transactions should be in the graph.
        assert!(pool.tx_graph.graph().get_tx(tx1.compute_txid()).is_some());
        assert!(pool.tx_graph.graph().get_tx(tx2.compute_txid()).is_some());
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
