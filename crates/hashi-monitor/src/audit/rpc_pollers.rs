// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor polls Sui, guardian logs, and Bitcoin through these methods.
//!
//! Why it exists:
//! - `RpcPollers` owns the three source handles and records how far each source is checked.
//! - Auditor tick handlers read each source and update the flow machines.
//!
//! How it works:
//! 1. Read Sui events and guardian logs into the flow machines.
//! 2. Before the mint, check that each fresh deposit approval names an unspent outpoint.
//! 3. Check Bitcoin confirmations after each withdrawal has both Sui and guardian approvals.
//! 4. Find each source that is behind its limit. The auditor reports it as a `SourceStale` finding.
//! 5. Leave pool updates and checks to the auditor scheduler.

use super::Auditor;
use crate::config::Config;
use crate::domain::Cursors;
use crate::findings::MonitorFinding;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SUI;
use crate::rpc::PollCursor;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::btc::checked_confirmation_threshold;
use crate::rpc::guardian::GuardianCursor;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiPoller;
use crate::rpc::sui::read_hashi_settings;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashSet;
use std::time::Duration;

/// How far behind a source may fall before a `SourceStale` finding, in
/// seconds. The guardian cursor is the start of the current hour directory,
/// which is finished 10 minutes after the hour, at the next poll. So it
/// normally lags up to about 75 minutes. Sui and Bitcoin lag a few minutes.
pub(super) const SOURCE_STALE_LIMIT: u64 = 3 * 60 * 60;

pub struct RpcPollers {
    pub guardian_poller: GuardianWithdrawalsPoller,
    pub sui_poller: SuiPoller,
    pub btc_client: BtcRpcClient,
    /// When the last full Bitcoin pass started. It starts at the startup
    /// time. Thus a Bitcoin node that is down at startup becomes stale only
    /// after `SOURCE_STALE_LIMIT`.
    btc_checked_through: UnixSeconds,
    /// Move's minimum time from a deposit approval to its mint, in seconds.
    pub deposit_delay_secs: u64,
}

impl RpcPollers {
    /// Initialize the source handles at their saved or genesis positions.
    pub async fn new(
        cfg: &Config,
        guardian_start: GuardianCursor,
        sui_start: u64,
    ) -> anyhow::Result<Self> {
        let mut guardian_poller = GuardianWithdrawalsPoller::new(cfg, guardian_start).await?;
        let (hashi_btc_keys, hashi_object_id) = guardian_poller
            .read_hashi_identity(cfg.deployment.bitcoin_network)
            .await?;
        let settings = read_hashi_settings(&cfg.sui, hashi_object_id).await?;
        let confirmations = checked_confirmation_threshold(
            settings.confirmation_threshold,
            cfg.deployment.bitcoin_network,
        )?;
        tracing::info!(
            confirmations,
            deposit_delay_secs = settings.deposit_delay_secs,
            "read Hashi's Bitcoin confirmation threshold and deposit delay"
        );
        let mut sui_poller = SuiPoller::new(&cfg.sui, hashi_btc_keys, sui_start)?;
        sui_poller.find_hbtc_treasury_cap(hashi_object_id).await?;
        Ok(Self {
            guardian_poller,
            sui_poller,
            btc_client: BtcRpcClient::new(cfg, confirmations, SOURCE_STALE_LIMIT)?,
            btc_checked_through: now_timestamp_secs(),
            deposit_delay_secs: settings.deposit_delay_secs,
        })
    }

    pub fn cursors(&self) -> Cursors {
        Cursors {
            sui: self.sui_read_until(),
            guardian: self.guardian_read_until(),
        }
    }

    /// A `SourceStale` finding for each source checked longer ago than
    /// `SOURCE_STALE_LIMIT`.
    pub fn stale_sources(&self, now: UnixSeconds) -> Vec<MonitorFinding> {
        [
            (SOURCE_SUI, self.sui_read_until()),
            (SOURCE_GUARDIAN, self.guardian_read_until()),
            (SOURCE_BTC, self.btc_read_until()),
        ]
        .into_iter()
        .filter(|(_, checked_through)| now.saturating_sub(*checked_through) > SOURCE_STALE_LIMIT)
        .map(|(source, checked_through)| MonitorFinding::SourceStale {
            source,
            checked_through,
            limit_secs: SOURCE_STALE_LIMIT,
        })
        .collect()
    }
}

// ====================
//         Sui
// ====================

impl RpcPollers {
    pub fn sui_read_until(&self) -> UnixSeconds {
        self.sui_poller.read_until()
    }

    /// The newest checkpoint the Sui node serves.
    async fn latest_sui_checkpoint(&mut self) -> anyhow::Result<u64> {
        self.sui_poller.latest_checkpoint().await
    }

    /// Fail unless the Sui node still serves the start. See
    /// `SuiPoller::ensure_start_is_served`.
    pub async fn ensure_sui_serves_start(&mut self) -> anyhow::Result<()> {
        self.sui_poller.ensure_start_is_served().await
    }
}

/// The wait after the first failed try of an initial catch-up.
const CATCH_UP_FIRST_BACKOFF: Duration = Duration::from_secs(1);
/// The longest wait between two tries of a failed initial catch-up.
const CATCH_UP_MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The wait before the next try of a failed initial catch-up. It doubles at
/// each failure, up to `CATCH_UP_MAX_BACKOFF`.
struct CatchUpBackoff {
    delay: Duration,
}

impl CatchUpBackoff {
    fn new() -> Self {
        Self {
            delay: CATCH_UP_FIRST_BACKOFF,
        }
    }

    /// Log the failure, then wait before the next try.
    async fn wait(&mut self, source: &'static str, error: anyhow::Error) {
        tracing::warn!(
            source,
            ?error,
            retry_in = ?self.delay,
            "initial catch-up failed; retrying"
        );
        tokio::time::sleep(self.delay).await;
        self.delay = (self.delay * 2).min(CATCH_UP_MAX_BACKOFF);
    }
}

impl Auditor {
    /// Catch up Sui, then the guardian, then Bitcoin. Retry a failed source
    /// with a backoff until it is current. Sui and the guardian add the
    /// machines, so Bitcoin comes last and looks up all of them.
    pub async fn catch_up_sources(&mut self) {
        let mut backoff = CatchUpBackoff::new();
        while let Err(error) = self.tick_sui().await {
            backoff.wait(SOURCE_SUI, error).await;
        }
        tracing::info!(source = SOURCE_SUI, "finished initial catch-up");
        let mut backoff = CatchUpBackoff::new();
        while let Err(error) = self.tick_guardian().await {
            backoff.wait(SOURCE_GUARDIAN, error).await;
        }
        tracing::info!(source = SOURCE_GUARDIAN, "finished initial catch-up");
        let mut backoff = CatchUpBackoff::new();
        while let Err(error) = self.tick_btc() {
            backoff.wait(SOURCE_BTC, error).await;
        }
        tracing::info!(source = SOURCE_BTC, "finished initial catch-up");
    }

    pub async fn tick_sui(&mut self) -> anyhow::Result<()> {
        // The head at the tick's start bounds the tick, so it ends.
        let up_to = self.rpc_pollers.latest_sui_checkpoint().await?;
        while let Some(poll) = self.rpc_pollers.sui_poller.poll(up_to).await? {
            self.report_findings("sui", &poll.findings);
            self.ingest_batch(poll.events);
            self.metrics
                .set_checked_through(SOURCE_SUI, self.rpc_pollers.sui_read_until());
        }
        Ok(())
    }
}

// ====================
//       Guardian
// ====================

impl RpcPollers {
    pub fn guardian_read_until(&self) -> UnixSeconds {
        self.guardian_poller.read_until()
    }
}

impl Auditor {
    /// Read every finished directory, then the new logs of the current one.
    pub async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        loop {
            let poll = self.rpc_pollers.guardian_poller.poll().await?;
            self.report_findings("guardian", &poll.findings);
            self.ingest_batch(poll.events);
            self.metrics
                .set_checked_through(SOURCE_GUARDIAN, self.rpc_pollers.guardian_read_until());
            if !poll.dir_done {
                return Ok(());
            }
        }
    }
}

// ====================
//       Bitcoin
// ====================

impl RpcPollers {
    pub fn btc_read_until(&self) -> UnixSeconds {
        self.btc_checked_through
    }
}

impl Auditor {
    /// Collect Bitcoin lookup targets and log their counts.
    fn txids_to_poll(&self) -> Vec<Txid> {
        let withdrawals = self
            .pending_withdrawals
            .values()
            .filter(|sm| sm.expects_btc());
        let deposits = self.pending_deposits.values().filter(|sm| sm.expects_btc());
        let withdrawal_count = withdrawals.clone().count();
        let deposit_count = deposits.clone().count();
        let unique_txids = withdrawals
            .map(WithdrawalStateMachine::btc_txid)
            .chain(deposits.map(DepositStateMachine::btc_txid))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        tracing::info!(
            withdrawal_count,
            deposit_count,
            unique_txids = unique_txids.len(),
            "starting bitcoin confirmation lookups"
        );
        unique_txids
    }

    /// Pings Bitcoin RPC for all relevant withdrawals & deposits.
    /// Returns domain findings and bubbles up infra errors. `started_at` is
    /// taken before the lookups, so the machines record it as their check time.
    fn fetch_btc_info(&mut self, started_at: UnixSeconds) -> anyhow::Result<Vec<MonitorFinding>> {
        let tip_height = self.rpc_pollers.btc_client.synced_height()?;
        // Report now, so that a later error in this tick does not lose them.
        let fresh = self.check_fresh_approvals(tip_height, started_at)?;
        self.report_findings("btc", &fresh);
        // A "not confirmed yet" answer goes stale. A confirmed one is kept
        // until no flow names its txid.
        self.rpc_pollers.btc_client.forget_unconfirmed();
        let unique_txids = self.txids_to_poll();
        self.rpc_pollers
            .btc_client
            .prefetch_confirmations(&unique_txids, tip_height)?;
        let mut findings = Vec::new();
        for sm in self.pending_withdrawals.values_mut() {
            findings.extend(sm.try_fetch_btc_tx(
                &self.cfg.timing,
                &self.rpc_pollers.btc_client,
                started_at,
            )?);
        }

        for sm in self.pending_deposits.values_mut() {
            findings.extend(sm.try_fetch_btc_tx(
                &self.cfg.timing,
                &self.rpc_pollers.btc_client,
                started_at,
            )?);
        }

        Ok(findings)
    }

    /// Read Bitcoin confirmations and report findings for pending flows.
    /// Complete flows' dependent machines must already be closed or ready to close when this tick finishes.
    pub fn tick_btc(&mut self) -> anyhow::Result<()> {
        let started_at = now_timestamp_secs();
        let findings = self.fetch_btc_info(started_at)?;
        // The machines Bitcoin answered stay until pool maintenance removes them.
        tracing::info!(
            withdrawals_waiting = self
                .pending_withdrawals
                .values()
                .filter(|sm| sm.expects_btc())
                .count(),
            deposits_waiting = self
                .pending_deposits
                .values()
                .filter(|sm| sm.expects_btc())
                .count(),
            "finished bitcoin confirmation lookups"
        );
        self.report_findings("btc", &findings);
        self.rpc_pollers.btc_checked_through = started_at;
        self.metrics.set_checked_through(SOURCE_BTC, started_at);
        Ok(())
    }
}

#[cfg(test)]
impl RpcPollers {
    /// Create source handles for tests that do not poll external services.
    pub fn for_tests(cfg: &Config, timestamp: UnixSeconds) -> Self {
        use crate::rpc::btc::MAINNET_MIN_CONFIRMATIONS;
        use crate::rpc::sui::tests::poller_scanned;

        Self {
            guardian_poller: GuardianWithdrawalsPoller::for_tests(cfg, timestamp),
            sui_poller: poller_scanned(timestamp),
            btc_client: BtcRpcClient::new(cfg, MAINNET_MIN_CONFIRMATIONS, SOURCE_STALE_LIMIT)
                .unwrap(),
            btc_checked_through: timestamp,
            deposit_delay_secs: 600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_source_behind_its_limit_is_stale() {
        let mut pollers = RpcPollers::for_tests(&Config::for_tests(), 1_700_000_000);
        let sui = pollers.sui_read_until();
        let guardian = pollers.guardian_read_until();
        pollers.btc_checked_through = sui;
        let stale = |now| {
            pollers
                .stale_sources(now)
                .into_iter()
                .map(|finding| match finding {
                    MonitorFinding::SourceStale { source, .. } => source,
                    other => panic!("unexpected {other}"),
                })
                .collect::<Vec<_>>()
        };

        // The guardian cursor is at the start of the hour, behind Sui.
        assert!(guardian < sui);
        assert!(stale(guardian + SOURCE_STALE_LIMIT).is_empty());
        assert_eq!(
            stale(guardian + SOURCE_STALE_LIMIT + 1),
            vec![SOURCE_GUARDIAN]
        );
        assert_eq!(
            stale(sui + SOURCE_STALE_LIMIT + 1),
            vec![SOURCE_SUI, SOURCE_GUARDIAN, SOURCE_BTC]
        );
    }
}
