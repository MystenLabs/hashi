// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor checks that each deposit approval names an output that pays
//! it, on the monitor's node and on a reference source.
//!
//! Why it exists:
//! - Move refuses only the outpoints that it tracks. A dishonest committee
//!   can approve a deposit that Bitcoin never paid, or spend an untracked
//!   bridge output through the recovery leaf, then approve a deposit of it.
//! - Whoever controls the peers of the monitor's node can withhold blocks
//!   from it, so an honest payment looks missing there. The reference source
//!   (see `rpc::esplora`) has other peers.
//!
//! How it works:
//! 1. On ingest, keep each approval, with a deadline `APPROVAL_DEADLINE`
//!    after the monitor read it.
//! 2. At each Bitcoin tick, even when the node fails its sync check, look the
//!    kept approvals up on both sources. A source that fails answers nothing.
//! 3. While the approval is fresh, either source showing the outpoint spent,
//!    also in the mempool, is `DepositUnbacked` (`Spent`). Withholding blocks
//!    cannot fake a spend. An approval is fresh until `DELAY_END_MARGIN`
//!    before its mint delay ends.
//! 4. Otherwise, either source showing an output that pays the approval,
//!    spent or not, settles it.
//! 5. Neither source showing that by the deadline is `DepositUnbacked`
//!    (`Unverified`).
//!
//! Each approval is settled once, then dropped.
//!
//! Assumptions:
//! - An honest deposit is confirmed when Hashi approves it, so a working
//!   source shows it paid at the first lookup. Both sources failing until the
//!   deadline gives a false `Unverified`.
//! - No honest transaction spends a deposit outpoint before its delay ends:
//!   it joins Move's active pool at `confirm_deposit`. After that, a
//!   withdrawal may spend it.
//! - The snapshot does not keep the approvals. After a restart, the catch-up
//!   reads the recent ones again and checks them once more.

use super::Auditor;
use crate::domain::SuiDepositApprovedEvent;
use crate::findings::DepositUnbackedReason;
use crate::findings::MonitorFinding;
use crate::rpc::btc::OutpointState;
use crate::rpc::esplora::ReferenceOutput;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashMap;

/// How long before the mint delay ends a spend stops counting, in seconds.
/// It covers lookup time and clock skew between the monitor and Sui.
const DELAY_END_MARGIN: u64 = 2 * 60;

/// How long after the monitor reads an approval a source must show its
/// payment, in seconds. It leaves most of Move's ten-minute delay for the
/// pause.
const APPROVAL_DEADLINE: u64 = 3 * 60;

/// Whether the delay of `event` ends more than `DELAY_END_MARGIN` after `now`.
fn is_fresh(event: &SuiDepositApprovedEvent, now: UnixSeconds, delay: u64) -> bool {
    now.saturating_add(DELAY_END_MARGIN) < event.timestamp_secs.saturating_add(delay)
}

impl Auditor {
    /// Keep `event`, read at `now`, until a source settles it. For each
    /// outpoint, keep the first approval.
    pub(super) fn note_approval(&mut self, event: &SuiDepositApprovedEvent, now: UnixSeconds) {
        self.unsettled_approvals
            .entry(OutPoint::from(event.deposit_id))
            .or_insert_with(|| (event.clone(), now.saturating_add(APPROVAL_DEADLINE)));
    }

    /// Judge each kept approval on the answers, at `finished`, when the
    /// lookups returned. Keep only the approvals that neither source settled,
    /// until their deadline.
    fn judge_approvals(
        &mut self,
        node: &HashMap<OutPoint, OutpointState>,
        reference: &HashMap<OutPoint, ReferenceOutput>,
        finished: UnixSeconds,
    ) -> Vec<MonitorFinding> {
        let delay = self.rpc_pollers.deposit_delay_secs;
        let mut findings = Vec::new();
        self.unsettled_approvals
            .retain(|outpoint, (event, deadline)| {
                let pays = |amount: u64, script_pubkey: &ScriptBuf| {
                    amount == event.amount && *script_pubkey == event.script_pubkey
                };
                let (node_spent, node_paid) = match node.get(outpoint) {
                    Some(OutpointState::Spent { output }) => {
                        (true, pays(output.value.to_sat(), &output.script_pubkey))
                    }
                    Some(OutpointState::Unspent { output, .. }) => {
                        (false, pays(output.value.to_sat(), &output.script_pubkey))
                    }
                    Some(OutpointState::Missing) | None => (false, false),
                };
                let (reference_spent, reference_paid) = match reference.get(outpoint) {
                    Some(ReferenceOutput::Spent {
                        amount,
                        script_pubkey,
                    }) => (true, pays(*amount, script_pubkey)),
                    Some(ReferenceOutput::Unspent {
                        amount,
                        script_pubkey,
                    }) => (false, pays(*amount, script_pubkey)),
                    Some(ReferenceOutput::Missing) | None => (false, false),
                };
                let unbacked = |reason| MonitorFinding::DepositUnbacked {
                    sui: event.clone(),
                    reason,
                };
                if (node_spent || reference_spent) && is_fresh(event, finished, delay) {
                    findings.push(unbacked(DepositUnbackedReason::Spent));
                    return false;
                }
                if node_paid || reference_paid {
                    return false;
                }
                if finished >= *deadline {
                    findings.push(unbacked(DepositUnbackedReason::Unverified));
                    return false;
                }
                true
            });
        findings
    }

    /// Look up the kept approvals on the node at `tip_height`, if it passed
    /// its sync check, and on the reference source.
    pub(super) fn check_approvals(&mut self, tip_height: Option<u64>) -> Vec<MonitorFinding> {
        if self.unsettled_approvals.is_empty() {
            return Vec::new();
        }
        let outpoints = self.unsettled_approvals.keys().copied().collect::<Vec<_>>();
        tracing::info!(approvals = outpoints.len(), "checking deposit approvals");
        let node = match tip_height {
            Some(tip_height) => self
                .rpc_pollers
                .btc_client
                .lookup_outpoint_states(&outpoints, tip_height, true)
                .unwrap_or_else(|error| {
                    tracing::warn!(?error, "node lookup of deposit approvals failed");
                    HashMap::new()
                }),
            None => HashMap::new(),
        };
        let reference = self
            .rpc_pollers
            .reference_btc
            .lookup_outputs(&outpoints)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "reference lookup of deposit approvals failed");
                HashMap::new()
            });
        self.judge_approvals(&node, &reference, now_timestamp_secs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with_pool;
    use crate::domain::MonitorEvent;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use bitcoin::Amount;
    use bitcoin::TxOut;

    #[tokio::test]
    async fn every_approval_is_kept_until_its_deadline() {
        let mut auditor = auditor_with_pool().await;
        let now = now_timestamp_secs();
        // Read long after its mint.
        let late = approval_of(&deposit_request(), now - 3_600);
        auditor.ingest(MonitorEvent::DepositApproved(late.clone()));
        assert_eq!(
            auditor.unsettled_approvals[&OutPoint::from(late.deposit_id)].1,
            now + APPROVAL_DEADLINE
        );
    }

    #[tokio::test]
    async fn either_source_can_settle_or_condemn_an_approval() {
        use DepositUnbackedReason::*;
        let approval = approval_of(&deposit_request(), 1_000);
        let output = |amount, script_pubkey| TxOut {
            value: Amount::from_sat(amount),
            script_pubkey,
        };
        let paid = output(approval.amount, approval.script_pubkey.clone());
        let node_unspent = OutpointState::Unspent {
            block_time: 900,
            output: paid.clone(),
        };
        let node_spent = OutpointState::Spent {
            output: paid.clone(),
        };
        let reference = |spent, amount| {
            let script_pubkey = approval.script_pubkey.clone();
            if spent {
                ReferenceOutput::Spent {
                    amount,
                    script_pubkey,
                }
            } else {
                ReferenceOutput::Unspent {
                    amount,
                    script_pubkey,
                }
            }
        };
        let amount = approval.amount;
        // Read at 1_000, so the deadline is 1_180. Fresh until 1_480.
        let deadline = 1_000 + APPROVAL_DEADLINE;
        // Read at 5_000, after the mint, so the deadline is 5_180.
        let late = 5_000;
        let cases = [
            // (read at, node, reference, judged at, finding, kept)
            (
                1_000,
                Some(node_spent.clone()),
                None,
                1_000,
                Some(Spent),
                false,
            ),
            (
                1_000,
                Some(node_unspent.clone()),
                Some(reference(true, amount)),
                1_000,
                Some(Spent),
                false,
            ),
            (1_000, Some(node_unspent.clone()), None, 1_000, None, false),
            // A node that peers withhold blocks from does not see the payment.
            (
                1_000,
                Some(OutpointState::Missing),
                Some(reference(false, amount)),
                1_000,
                None,
                false,
            ),
            (
                1_000,
                Some(OutpointState::Missing),
                Some(ReferenceOutput::Missing),
                deadline - 1,
                None,
                true,
            ),
            (1_000, None, None, deadline, Some(Unverified), false),
            // Another amount, or a real output that pays someone else, is
            // not the approved payment.
            (
                1_000,
                None,
                Some(reference(false, amount + 1)),
                deadline,
                Some(Unverified),
                false,
            ),
            (
                1_000,
                Some(OutpointState::Unspent {
                    block_time: 900,
                    output: output(amount, ScriptBuf::new()),
                }),
                None,
                deadline,
                Some(Unverified),
                false,
            ),
            // After the mint, a withdrawal may spend the deposit.
            (late, Some(node_spent.clone()), None, late, None, false),
            (late, None, Some(reference(true, amount)), late, None, false),
            (
                late,
                None,
                None,
                late + APPROVAL_DEADLINE,
                Some(Unverified),
                false,
            ),
        ];
        for (read_at, node, reference, finished, reason, kept) in cases {
            let case = format!("read at {read_at}: {node:?} {reference:?} at {finished}");
            let mut auditor = auditor_with_pool().await;
            auditor.note_approval(&approval, read_at);
            let outpoint = OutPoint::from(approval.deposit_id);
            let node = node
                .map(|s| HashMap::from([(outpoint, s)]))
                .unwrap_or_default();
            let reference = reference
                .map(|s| HashMap::from([(outpoint, s)]))
                .unwrap_or_default();
            let findings = auditor.judge_approvals(&node, &reference, finished);
            let expected = reason
                .map(|reason| MonitorFinding::DepositUnbacked {
                    sui: approval.clone(),
                    reason,
                })
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(findings, expected, "{case}");
            assert_eq!(auditor.unsettled_approvals.is_empty(), !kept, "{case}");
        }
    }
}
