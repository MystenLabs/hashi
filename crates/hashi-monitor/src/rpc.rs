//! RPC and S3 utilities for fetching events from Sui, Guardian, and Bitcoin.

use bitcoin::Txid;
use std::collections::BTreeSet;

use crate::OutputUTXO;
use crate::config::Config;
use crate::domain::UnixSeconds;

/// Query BTC RPC to check if a transaction is confirmed.
/// Returns `Some(block_time, utxos)` if confirmed, `None` if not yet confirmed.
pub fn lookup_btc_confirmation(
    _cfg: &Config,
    _txid: Txid,
) -> anyhow::Result<Option<(UnixSeconds, BTreeSet<OutputUTXO>)>> {
    // TODO:
    // - Call `getrawtransaction` or similar RPC to get tx details.
    // - If tx is in a block, return block timestamp.
    // - If tx is in mempool or unknown, return None.
    Ok(None) // Stub: assume not confirmed
}
