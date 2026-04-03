// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use bitcoin::Txid;
use hashi_types::guardian::time_utils::UnixSeconds;
use tracing::debug;
use tracing::warn;

use crate::config::Config;

pub struct BtcRpcClient {
    client: corepc_client::client_sync::v29::Client,
}

impl BtcRpcClient {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let auth = cfg.btc.rpc_auth.to_corepc_auth();
        let client = match auth {
            corepc_client::client_sync::Auth::None => {
                corepc_client::client_sync::v29::Client::new(&cfg.btc.rpc_url)
            }
            auth => corepc_client::client_sync::v29::Client::new_with_auth(&cfg.btc.rpc_url, auth)
                .with_context(|| {
                    format!("failed to connect to bitcoin rpc at {}", cfg.btc.rpc_url)
                })?,
        };
        Ok(Self { client })
    }

    /// Query BTC RPC to check if a transaction is confirmed.
    /// Returns
    /// - `Ok(Some(block_time))` if txid is confirmed,
    /// - `Ok(None)` if txid is not seen or txid is seen but not confirmed,
    /// - `Err(...)` for all other errors
    pub fn lookup_confirmation(&self, txid: Txid) -> anyhow::Result<Option<UnixSeconds>> {
        // Note: rpc returns Ok(...) even for unconfirmed txid in the mempool.
        let tx_info = match self.client.get_raw_transaction_verbose(txid) {
            Ok(tx_info) => tx_info,
            Err(e) if txid_not_found(&e) => {
                debug!(%txid, "bitcoin tx not found in mempool or chain yet");
                return Ok(None);
            }
            Err(e) => {
                warn!(%txid, error = %e, "failed to fetch bitcoin tx from rpc");
                anyhow::bail!("failed to fetch bitcoin tx {} from rpc: {}", txid, e)
            }
        };

        let Some(block_hash_hex) = tx_info.block_hash else {
            debug!(%txid, "bitcoin tx found but not mined yet");
            return Ok(None);
        };

        let block_hash: bitcoin::BlockHash = block_hash_hex
            .parse()
            .with_context(|| format!("failed to parse block hash '{}'", block_hash_hex))?;

        let block_header = self
            .client
            .get_block_header_verbose(&block_hash)
            .with_context(|| format!("failed to fetch block header for {}", block_hash))?;

        let block_time = u64::try_from(block_header.time)
            .with_context(|| format!("invalid block timestamp for {}", block_hash))?;

        Ok(Some(block_time))
    }
}

// https://github.com/bitcoin/bitcoin/blob/v25.0/src/rpc/protocol.h#L41
fn txid_not_found(error: &corepc_client::client_sync::Error) -> bool {
    matches!(
        error,
        corepc_client::client_sync::Error::JsonRpc(jsonrpc::error::Error::Rpc(rpc_error))
            if rpc_error.code == -5
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use anyhow::Result;
    use bitcoin::Amount;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash as _;
    use e2e_tests::BitcoinNodeBuilder;
    use e2e_tests::bitcoin_node::RPC_PASSWORD;
    use e2e_tests::bitcoin_node::RPC_USER;
    use tempfile::TempDir;

    use super::BtcRpcClient;
    use crate::config::BtcConfig;
    use crate::config::BtcRpcAuth;
    use crate::config::Config;
    use crate::config::NextEventDelays;
    use crate::config::SuiConfig;
    use crate::domain::WithdrawalEventType;

    static TRACING_INIT: Once = Once::new();

    fn init_test_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init();
        });
    }

    fn test_config(rpc_url: String) -> Config {
        Config {
            next_event_delays: NextEventDelays::new(vec![
                (WithdrawalEventType::E1HashiApproved, 100),
                (WithdrawalEventType::E2GuardianApproved, 200),
            ])
            .expect("valid next event delays"),
            clock_skew: 10,
            guardian: hashi_types::guardian::S3Config::mock_for_testing(),
            sui: SuiConfig {
                rpc_url: "http://sui".to_string(),
            },
            btc: BtcConfig {
                rpc_url,
                rpc_auth: BtcRpcAuth::UserPass {
                    username: RPC_USER.to_string(),
                    password: RPC_PASSWORD.to_string(),
                },
            },
        }
    }

    // Note that this test requires local bitcoind running.
    #[tokio::test]
    async fn lookup_btc_confirmation_with_local_regtest() -> Result<()> {
        init_test_tracing();

        let temp_dir = TempDir::new()?;
        let node = BitcoinNodeBuilder::new()
            .dir(temp_dir.path())
            .build()
            .await?;
        let cfg = test_config(node.rpc_url().to_string());
        let btc_rpc_client = BtcRpcClient::new(&cfg)?;

        let unknown_txid = Txid::from_slice(&[7u8; 32])?;
        let unknown = btc_rpc_client.lookup_confirmation(unknown_txid)?;
        assert!(
            unknown.is_none(),
            "expected unknown tx lookup to return none"
        );

        let destination = node.get_new_address()?;
        let txid = node.send_to_address(&destination, Amount::from_sat(50_000))?;

        let unconfirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(unconfirmed.is_none(), "expected unconfirmed transaction");

        node.generate_blocks(1)?;

        let confirmed = btc_rpc_client.lookup_confirmation(txid)?;
        assert!(confirmed.is_some(), "expected confirmed transaction");

        Ok(())
    }
}
