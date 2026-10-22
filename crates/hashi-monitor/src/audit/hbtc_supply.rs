// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor checks that Bitcoin backs every hBTC on Sui.
//!
//! Why it exists: the other checks follow the events that the monitor reads.
//! A mint path that the monitor does not follow, or a Move bug, changes the
//! hBTC supply without such an event. One comparison of state catches all of
//! them.
//!
//! How it works:
//! 1. After each pool maintenance tick, read the hBTC supply and sum the
//!    held UTXO amounts. Export both as gauges.
//! 2. While the supply exceeds the pool value, keep the time it started.
//! 3. Report `HbtcSupplyExceedsPool` at each tick once that lasts
//!    `HBTC_SUPPLY_GRACE`.
//!
//! Assumptions:
//! - In an honest bridge, the supply never exceeds the pool value. The pool
//!   takes a deposit at its Bitcoin confirmation, and Move mints at least
//!   `deposit_time_delay_ms` after the approval. Move burns a withdrawal at
//!   E1, and the pool drops it at E3. The burned amount includes the miner
//!   fee, so it equals what leaves the pool.
//! - The supply exceeds the pool value only for a short time when the
//!   monitor's Bitcoin side lags. `HBTC_SUPPLY_GRACE` is `SOURCE_STALE_LIMIT`:
//!   a longer lag is a `SourceStale` finding already.

use super::Auditor;
use super::rpc_pollers::SOURCE_STALE_LIMIT;
use crate::findings::MonitorFinding;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

/// How long the hBTC supply may exceed the pool value before a finding, in
/// seconds.
const HBTC_SUPPLY_GRACE: u64 = SOURCE_STALE_LIMIT;

impl Auditor {
    /// Read the hBTC supply and compare it with the pool value. A failed read
    /// skips the check; a lasting Sui failure is a `SourceStale` finding.
    pub async fn check_hbtc_supply(&mut self) {
        let supply = match self.read_hbtc_supply().await {
            Ok(supply) => supply,
            Err(error) => {
                tracing::warn!(?error, "hBTC supply read failed; retrying at the next tick");
                return;
            }
        };
        let pool_value = self.utxo_pool.value();
        let (since, finding) = judge_hbtc_supply(
            self.hbtc_supply_above_pool_since,
            supply,
            pool_value,
            now_timestamp_secs(),
        );
        self.hbtc_supply_above_pool_since = since;
        self.report_findings("hbtc_supply", finding.as_slice());
    }

    /// Read the hBTC supply and export it with the pool value.
    pub async fn read_hbtc_supply(&mut self) -> anyhow::Result<u64> {
        let supply = self.rpc_pollers.sui_poller.hbtc_supply().await?;
        self.metrics
            .set_hbtc_backing(supply, self.utxo_pool.value());
        Ok(supply)
    }
}

/// Judge the hBTC supply against the pool value at `now`. Returns the new
/// time since the supply exceeds the pool, and a finding once that lasts
/// `HBTC_SUPPLY_GRACE`.
fn judge_hbtc_supply(
    above_since: Option<UnixSeconds>,
    hbtc_supply: u64,
    pool_value: u64,
    now: UnixSeconds,
) -> (Option<UnixSeconds>, Option<MonitorFinding>) {
    if hbtc_supply <= pool_value {
        return (None, None);
    }
    let since = above_since.unwrap_or(now);
    let finding = (now.saturating_sub(since) >= HBTC_SUPPLY_GRACE).then_some(
        MonitorFinding::HbtcSupplyExceedsPool {
            hbtc_supply,
            pool_value,
            since,
        },
    );
    (Some(since), finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_supply_above_the_pool_is_reported_after_the_grace() {
        // Below or equal is fine and clears an earlier excess.
        assert_eq!(judge_hbtc_supply(Some(5), 100, 100, 10), (None, None));

        // The first excess starts the grace.
        assert_eq!(
            judge_hbtc_supply(None, 101, 100, 1_000),
            (Some(1_000), None)
        );
        let within = 1_000 + HBTC_SUPPLY_GRACE - 1;
        assert_eq!(
            judge_hbtc_supply(Some(1_000), 101, 100, within),
            (Some(1_000), None)
        );

        let after = 1_000 + HBTC_SUPPLY_GRACE;
        assert_eq!(
            judge_hbtc_supply(Some(1_000), 101, 100, after),
            (
                Some(1_000),
                Some(MonitorFinding::HbtcSupplyExceedsPool {
                    hbtc_supply: 101,
                    pool_value: 100,
                    since: 1_000,
                })
            )
        );
    }
}
