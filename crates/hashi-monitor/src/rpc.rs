//! RPC and S3 utilities for fetching events from Sui, Guardian, and Bitcoin.

use bitcoin::Txid;

use crate::config::Config;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;

// =============================================================================
// Sui
// =============================================================================

/// Download Sui events in a time range. Used by BatchAuditor.
/// Returns (events, cursor) where cursor is the latest timestamp with complete data.
pub fn download_sui(
    _cfg: &Config,
    _start: UnixSeconds,
    end: UnixSeconds,
) -> anyhow::Result<(Vec<WithdrawalEvent>, UnixSeconds)> {
    // TODO:
    // - Query Sui events across checkpoints that intersect [start, end]
    // - Return actual cursor based on latest checkpoint timestamp.
    let cursor = end; // Stub: assume we got everything requested
    Ok((vec![], cursor))
}

/// Poll Sui RPC for events since the given cursor. Used by ContinuousAuditor.
/// Returns (events, new_cursor).
pub fn poll_sui(
    _cfg: &Config,
    cursor: UnixSeconds,
) -> anyhow::Result<(Vec<WithdrawalEvent>, UnixSeconds)> {
    // TODO:
    // - Query Sui RPC for events since `cursor`
    // - Return new events and updated cursor
    Ok((vec![], cursor))
}

// =============================================================================
// Guardian (S3)
// =============================================================================

/// Download Guardian events in a time range. Used by BatchAuditor.
/// Returns (events, cursor) where cursor is the latest timestamp with complete data.
pub fn download_guardian(
    _cfg: &Config,
    _start: UnixSeconds,
    end: UnixSeconds,
) -> anyhow::Result<(Vec<WithdrawalEvent>, UnixSeconds)> {
    // TODO:
    // - List S3 objects by time-bucket prefix (planned key scheme: YYYY/MM/DD/HH/...)
    // - Download and deserialize Guardian log envelopes.
    // - Return actual cursor based on latest complete bucket.
    let cursor = end; // Stub: assume we got everything requested
    Ok((vec![], cursor))
}

/// Poll Guardian S3 for events since the given cursor. Used by ContinuousAuditor.
/// Returns (events, new_cursor).
pub fn poll_guardian(
    _cfg: &Config,
    cursor: UnixSeconds,
) -> anyhow::Result<(Vec<WithdrawalEvent>, UnixSeconds)> {
    // TODO:
    // - List S3 objects since `cursor`
    // - Download and deserialize Guardian log envelopes
    // - Return new events and updated cursor
    Ok((vec![], cursor))
}

// =============================================================================
// Bitcoin
// =============================================================================

/// Query BTC RPC to check if a transaction is confirmed.
/// Returns `Some(block_time)` if confirmed, `None` if not yet confirmed.
pub fn lookup_btc_confirmation(_cfg: &Config, _txid: Txid) -> anyhow::Result<Option<UnixSeconds>> {
    // TODO:
    // - Call `getrawtransaction` or similar RPC to get tx details.
    // - If tx is in a block, return block timestamp.
    // - If tx is in mempool or unknown, return None.
    Ok(None) // Stub: assume not confirmed
}
