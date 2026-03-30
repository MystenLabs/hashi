// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A lightweight Bitcoin node handle that connects to an already-running node
//! (e.g. a local signet node). Unlike [`BitcoinNodeHandle`], this does NOT
//! spawn or manage the bitcoind process.

use anyhow::{Result, anyhow};
use bitcoin::{Address, Amount, Txid};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use std::time::Duration;
use tracing::info;

use crate::hashi_network::BitcoinNodeInfo;

pub struct ExternalBitcoinNode {
    rpc_client: Client,
    rpc_url: String,
    p2p_address: String,
    rpc_user: String,
    rpc_pass: String,
}

impl ExternalBitcoinNode {
    /// Connect to an already-running Bitcoin node.
    ///
    /// # Arguments
    /// - `rpc_url`: Bitcoin RPC URL (e.g. `http://127.0.0.1:38332`)
    /// - `rpc_user`: RPC username (empty string for no auth)
    /// - `rpc_pass`: RPC password
    /// - `wallet`: Optional wallet name to load
    /// - `p2p_address`: P2P address for Kyoto light client (e.g. `127.0.0.1:38333`)
    pub fn new(
        rpc_url: &str,
        rpc_user: &str,
        rpc_pass: &str,
        wallet: Option<&str>,
        p2p_address: &str,
    ) -> Result<Self> {
        let url = if let Some(wallet_name) = wallet {
            format!("{}/wallet/{}", rpc_url, wallet_name)
        } else {
            rpc_url.to_string()
        };

        let auth = if rpc_user.is_empty() {
            Auth::None
        } else {
            Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string())
        };

        let rpc_client = Client::new(&url, auth)?;

        // Verify connectivity
        let blockchain_info = rpc_client.get_blockchain_info().map_err(|e| {
            anyhow!(
                "Failed to connect to Bitcoin node at {}: {}. \
                 Ensure the node is running.",
                rpc_url,
                e
            )
        })?;
        info!(
            "Connected to external Bitcoin node: chain={}, blocks={}",
            blockchain_info.chain, blockchain_info.blocks
        );

        Ok(Self {
            rpc_client,
            rpc_url: rpc_url.to_string(),
            p2p_address: p2p_address.to_string(),
            rpc_user: rpc_user.to_string(),
            rpc_pass: rpc_pass.to_string(),
        })
    }

    pub fn rpc_client(&self) -> &Client {
        &self.rpc_client
    }

    pub fn rpc_user(&self) -> &str {
        &self.rpc_user
    }

    pub fn rpc_pass(&self) -> &str {
        &self.rpc_pass
    }

    pub fn send_to_address(&self, address: &Address, amount: Amount) -> Result<Txid> {
        let txid = self
            .rpc_client
            .send_to_address(address, amount, None, None, None, None, None, None)?;
        info!("Sent {} to {}: {}", amount, address, txid);
        Ok(txid)
    }

    pub fn get_block_count(&self) -> Result<u64> {
        Ok(self.rpc_client.get_block_count()?)
    }

    /// Wait until `txid` has at least `min_confirmations` confirmations.
    pub async fn wait_for_confirmations(
        &self,
        txid: &Txid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            if start.elapsed() > timeout {
                return Err(anyhow!(
                    "Timeout waiting for {} confirmations on tx {} after {:?}",
                    min_confirmations,
                    txid,
                    timeout
                ));
            }

            match self.rpc_client.get_transaction(txid, None) {
                Ok(info) => {
                    let confirmations = info.info.confirmations;
                    if confirmations >= min_confirmations as i32 {
                        info!(
                            "Transaction {} has {} confirmations (needed {})",
                            txid, confirmations, min_confirmations
                        );
                        return Ok(());
                    }
                    info!(
                        "Transaction {} has {} confirmations, waiting for {}...",
                        txid, confirmations, min_confirmations
                    );
                }
                Err(_) => {
                    info!("Transaction {} not yet visible, waiting...", txid);
                }
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }

    pub fn get_balance(&self) -> Result<Amount> {
        Ok(self.rpc_client.get_balance(None, None)?)
    }

    pub fn get_new_address(&self) -> Result<Address> {
        let address = self.rpc_client.get_new_address(None, None)?;
        Ok(address.assume_checked())
    }
}

impl BitcoinNodeInfo for ExternalBitcoinNode {
    fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    fn p2p_address(&self) -> String {
        self.p2p_address.clone()
    }
}
