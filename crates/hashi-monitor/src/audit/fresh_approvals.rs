// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor checks that each fresh deposit approval names an unspent outpoint.
//!
//! Why it exists:
//! - A fresh approval is a Sui deposit approval whose delay ends more than
//!   `DELAY_END_MARGIN` from now. The delay is Move's minimum time from an
//!   approval to its mint (`bitcoin_deposit_time_delay_ms`).
//! - The deposit judge proves that Bitcoin paid the outpoint. It does not
//!   check that the outpoint is unspent now.
//! - Move refuses only the outpoints that it tracks. A dishonest committee
//!   can spend an untracked bridge output through the recovery leaf, then
//!   approve a deposit of it. The mint is then unbacked.
//! - The daily pool check finds this spend, but only after the mint. This
//!   check finds it during the delay, so operators can pause Hashi.
//!
//! How it works:
//! 1. On ingest, keep each fresh approval.
//! 2. At each Bitcoin tick, drop the approvals that are no longer fresh.
//! 3. Look up the outpoints of the remaining approvals. A spend in the
//!    mempool counts.
//! 4. Report a spent outpoint as `DepositUnbacked`, and drop its approval.
//! 5. Drop an approval whose outpoint is unspent. One lookup is sufficient:
//!    an attacker gains nothing from a spend before the mint over a spend
//!    after it.
//! 6. Keep an approval whose outpoint Bitcoin does not show yet, because the
//!    monitor's node can be behind. The next tick looks it up again.
//!
//! Assumptions:
//! - An honest deposit UTXO joins Move's active pool at `confirm_deposit`,
//!   when its delay ends or later. Withdrawals spend only active UTXOs. So no
//!   honest transaction spends the outpoint before its delay ends, not even
//!   in the mempool.
//! - `DELAY_END_MARGIN` covers lookup time and clock skew between the
//!   monitor and Sui, so a lookup never sees an honest spend after the mint.
//! - An approval that the monitor reads when it is no longer fresh skips
//!   this check. The daily pool check covers it. With a delay shorter than
//!   `DELAY_END_MARGIN`, no approval is fresh.
//! - The snapshot does not keep the approvals, because a restart usually
//!   takes longer than the delay.
//! - A spend after the delay ends is out of scope. It is the same as a
//!   recovery spend of any held UTXO, which the daily pool check reports.

use super::Auditor;
use crate::domain::SuiDepositApprovedEvent;
use crate::findings::MonitorFinding;
use crate::rpc::btc::OutpointState;
use bitcoin::OutPoint;
use hashi_types::guardian::time::UnixSeconds;
use std::collections::HashMap;

/// How long before the delay ends the lookups stop, in seconds.
const DELAY_END_MARGIN: u64 = 2 * 60;

impl Auditor {
    /// Whether the delay of `event` ends more than `DELAY_END_MARGIN` after `now`.
    fn is_fresh(&self, event: &SuiDepositApprovedEvent, now: UnixSeconds) -> bool {
        now.saturating_add(DELAY_END_MARGIN)
            < event
                .timestamp_secs
                .saturating_add(self.rpc_pollers.deposit_delay_secs)
    }

    /// Keep `event` for the Bitcoin tick if it is fresh at `now`. For each
    /// outpoint, keep the first approval: no honest spend comes before its
    /// delay ends.
    pub(super) fn note_fresh_approval(
        &mut self,
        event: &SuiDepositApprovedEvent,
        now: UnixSeconds,
    ) {
        if self.is_fresh(event, now) {
            self.fresh_approvals
                .entry(OutPoint::from(event.deposit_id))
                .or_insert_with(|| event.clone());
        }
    }

    /// Drop the approvals that are not fresh at `now`. After the mint, an
    /// honest withdrawal can spend the outpoint.
    fn drop_stale_approvals(&mut self, now: UnixSeconds) {
        let stale = self
            .fresh_approvals
            .iter()
            .filter(|(_, event)| !self.is_fresh(event, now))
            .map(|(outpoint, _)| *outpoint)
            .collect::<Vec<_>>();
        for outpoint in stale {
            self.fresh_approvals.remove(&outpoint);
        }
    }

    /// Report each fresh approval whose outpoint is spent. Keep only the
    /// approvals whose outpoint Bitcoin does not show yet.
    fn judge_fresh_approvals(
        &mut self,
        states: &HashMap<OutPoint, OutpointState>,
    ) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        self.fresh_approvals
            .retain(|outpoint, event| match states.get(outpoint) {
                Some(OutpointState::Spent) => {
                    findings.push(MonitorFinding::DepositUnbacked { sui: event.clone() });
                    false
                }
                Some(OutpointState::Unspent { .. }) => false,
                Some(OutpointState::Missing) | None => true,
            });
        findings
    }

    /// Look up the outpoints of the fresh approvals at `tip_height`. On an
    /// RPC error, keep every approval for the next tick.
    pub(super) fn check_fresh_approvals(
        &mut self,
        tip_height: u64,
        now: UnixSeconds,
    ) -> anyhow::Result<Vec<MonitorFinding>> {
        self.drop_stale_approvals(now);
        if self.fresh_approvals.is_empty() {
            return Ok(Vec::new());
        }
        let outpoints = self.fresh_approvals.keys().copied().collect::<Vec<_>>();
        tracing::info!(
            approvals = outpoints.len(),
            "checking fresh deposit approvals"
        );
        let states = self
            .rpc_pollers
            .btc_client
            .lookup_outpoint_states(&outpoints, tip_height, true)?;
        Ok(self.judge_fresh_approvals(&states))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with_pool;
    use crate::domain::MonitorEvent;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use hashi_types::guardian::time::now_timestamp_secs;

    /// An approval of `txid(9):1` at `approved_at`.
    fn approval(approved_at: UnixSeconds) -> SuiDepositApprovedEvent {
        approval_of(&deposit_request(), approved_at)
    }

    fn states(
        approval: &SuiDepositApprovedEvent,
        state: OutpointState,
    ) -> HashMap<OutPoint, OutpointState> {
        HashMap::from([(OutPoint::from(approval.deposit_id), state)])
    }

    #[tokio::test]
    async fn only_a_fresh_approval_is_kept() {
        let mut auditor = auditor_with_pool().await;
        let delay = auditor.rpc_pollers.deposit_delay_secs;
        let old = approval(now_timestamp_secs() - delay - 60);
        auditor.ingest(MonitorEvent::DepositApproved(old));
        assert!(auditor.fresh_approvals.is_empty());

        let fresh = approval(now_timestamp_secs());
        auditor.ingest(MonitorEvent::DepositApproved(fresh.clone()));
        assert_eq!(
            auditor.fresh_approvals,
            HashMap::from([(OutPoint::from(fresh.deposit_id), fresh.clone())])
        );

        // Freshness ends `DELAY_END_MARGIN` before the delay ends.
        let end = fresh.timestamp_secs + delay - DELAY_END_MARGIN;
        let mut auditor = auditor_with_pool().await;
        auditor.note_fresh_approval(&fresh, end);
        assert!(auditor.fresh_approvals.is_empty());
        auditor.note_fresh_approval(&fresh, end - 1);
        assert_eq!(auditor.fresh_approvals.len(), 1);
    }

    #[tokio::test]
    async fn a_fresh_approval_of_a_spent_outpoint_is_unbacked() {
        let mut auditor = auditor_with_pool().await;
        let fresh = approval(1_000);
        auditor.note_fresh_approval(&fresh, 1_000);

        let findings = auditor.judge_fresh_approvals(&states(&fresh, OutpointState::Spent));

        assert_eq!(
            findings,
            vec![MonitorFinding::DepositUnbacked { sui: fresh }]
        );
        assert!(auditor.fresh_approvals.is_empty());
    }

    #[tokio::test]
    async fn a_missing_outpoint_is_checked_again_and_an_unspent_one_is_dropped() {
        let mut auditor = auditor_with_pool().await;
        let fresh = approval(1_000);
        auditor.note_fresh_approval(&fresh, 1_000);

        let missing = states(&fresh, OutpointState::Missing);
        assert!(auditor.judge_fresh_approvals(&missing).is_empty());
        assert_eq!(auditor.fresh_approvals.len(), 1);

        let unspent = OutpointState::Unspent { block_time: 900 };
        assert!(
            auditor
                .judge_fresh_approvals(&states(&fresh, unspent))
                .is_empty()
        );
        assert!(auditor.fresh_approvals.is_empty());
    }

    #[tokio::test]
    async fn an_approval_is_dropped_without_a_lookup_once_it_is_not_fresh() {
        let mut auditor = auditor_with_pool().await;
        let end = 1_000 + auditor.rpc_pollers.deposit_delay_secs - DELAY_END_MARGIN;
        let fresh = approval(1_000);
        auditor.note_fresh_approval(&fresh, 1_000);

        auditor.drop_stale_approvals(end - 1);
        assert_eq!(auditor.fresh_approvals.len(), 1);

        // No lookup: the test client has no Bitcoin node to answer it.
        let findings = auditor.check_fresh_approvals(0, end).unwrap();
        assert!(findings.is_empty());
        assert!(auditor.fresh_approvals.is_empty());
    }
}
