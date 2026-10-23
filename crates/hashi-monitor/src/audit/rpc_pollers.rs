// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor polls Sui, guardian logs, and Bitcoin through these methods.
//!
//! Why it exists:
//! - `RpcPollers` owns the three source handles.
//! - Auditor tick handlers read each source and update the flow machines.
//!
//! How it works:
//! 1. Read Sui events and guardian logs into the flow machines.
//! 2. Check Bitcoin confirmations after each withdrawal has both Sui and guardian approvals.
//! 3. Leave pool updates and checks to the auditor scheduler.

use super::Auditor;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::metrics::SOURCE_BTC;
use crate::metrics::SOURCE_GUARDIAN;
use crate::metrics::SOURCE_SUI;
use crate::rpc::PollCursor;
use crate::rpc::btc::BtcRpcClient;
use crate::rpc::btc::checked_confirmation_threshold;
use crate::rpc::guardian::GuardianWithdrawalsPoller;
use crate::rpc::sui::SuiEventsPoller;
use crate::rpc::sui::read_confirmation_threshold;
use crate::state_machine::DepositStateMachine;
use crate::state_machine::WithdrawalStateMachine;
use bitcoin::Txid;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashSet;

pub struct RpcPollers {
    pub guardian_poller: GuardianWithdrawalsPoller,
    pub sui_poller: SuiEventsPoller,
    pub btc_client: BtcRpcClient,
}

impl RpcPollers {
    /// Initialize the source handles at their saved or genesis positions.
    pub async fn new(
        cfg: &Config,
        guardian_start: S3HourDirectory,
        sui_start: u64,
    ) -> anyhow::Result<Self> {
        let mut guardian_poller = GuardianWithdrawalsPoller::new(cfg, guardian_start).await?;
        let (hashi_btc_keys, hashi_object_id) = guardian_poller
            .read_hashi_identity(cfg.deployment.bitcoin_network)
            .await?;
        let confirmations = checked_confirmation_threshold(
            read_confirmation_threshold(&cfg.sui, hashi_object_id).await?,
            cfg.deployment.bitcoin_network,
        )?;
        tracing::info!(confirmations, "read Hashi's Bitcoin confirmation threshold");
        let sui_poller = SuiEventsPoller::new(&cfg.sui, hashi_btc_keys, sui_start)?;
        Ok(Self {
            guardian_poller,
            sui_poller,
            btc_client: BtcRpcClient::new(cfg, confirmations)?,
        })
    }

    pub fn cursors(&self) -> Cursors {
        Cursors {
            sui: self.sui_read_until(),
            guardian: self.guardian_read_until(),
        }
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
    /// `SuiEventsPoller::ensure_start_is_served`.
    pub async fn ensure_sui_serves_start(&mut self) -> anyhow::Result<()> {
        self.sui_poller.ensure_start_is_served().await
    }
}

impl Auditor {
    pub async fn tick_sui(&mut self) -> anyhow::Result<()> {
        // The head at the tick's start bounds the tick, so it ends.
        let up_to = self.rpc_pollers.latest_sui_checkpoint().await?;
        while let PollOutcome::CursorAdvanced { events, findings } =
            self.rpc_pollers.sui_poller.poll(up_to).await?
        {
            self.report_findings("sui", &findings);
            self.ingest_batch(events);
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
    pub async fn tick_guardian(&mut self) -> anyhow::Result<()> {
        while let PollOutcome::CursorAdvanced { events, findings } =
            self.rpc_pollers.guardian_poller.poll_one_hour().await?
        {
            self.report_findings("guardian", &findings);
            self.ingest_batch(events);
            self.metrics
                .set_checked_through(SOURCE_GUARDIAN, self.rpc_pollers.guardian_read_until());
        }
        Ok(())
    }
}

// ====================
//       Bitcoin
// ====================

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
        self.report_findings("btc", &findings);
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
            btc_client: BtcRpcClient::new(cfg, MAINNET_MIN_CONFIRMATIONS).unwrap(),
        }
    }
}
