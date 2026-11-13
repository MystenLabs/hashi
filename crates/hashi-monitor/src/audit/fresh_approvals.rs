// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor checks that each fresh deposit approval names a paid,
//! unspent outpoint, on the monitor's node and on a reference source.
//!
//! Why it exists:
//! - A fresh approval is a Sui deposit approval whose delay ends more than
//!   `DELAY_END_MARGIN` from now. The delay is Move's minimum time from an
//!   approval to its mint (`bitcoin_deposit_time_delay_ms`).
//! - Move refuses only the outpoints that it tracks. A dishonest committee
//!   can approve a deposit that Bitcoin never paid, or spend an untracked
//!   bridge output through the recovery leaf, then approve a deposit of it.
//! - Whoever controls the peers of the monitor's node can withhold blocks
//!   from it, so an honest payment looks missing there. The reference source
//!   (see `rpc::esplora`) has other peers.
//!
//! How it works, at each Bitcoin tick, even when the node fails its sync check:
//! 1. Drop the approvals that are no longer fresh, before and after the
//!    lookups, because a slow lookup can see an honest spend after the mint.
//! 2. Look up the rest on both sources. A source that fails answers nothing.
//! 3. Either source showing the outpoint spent, also in the mempool, is
//!    `DepositUnbacked` (`Spent`). Withholding blocks cannot fake a spend.
//! 4. Either source showing it paid as approved verifies it. One lookup is
//!    sufficient: an attacker gains nothing from a spend before the mint
//!    over a spend after it.
//! 5. Neither source showing it paid `FRESH_APPROVAL_DEADLINE` after the
//!    approval is `DepositUnbacked` (`Unverified`).
//!
//! Assumptions:
//! - An honest deposit is confirmed when Hashi approves it, so a working
//!   source shows it paid at the first lookup. Both sources failing until the
//!   deadline gives a false `Unverified`.
//! - The deposit judge reports a node payment of another amount or script.
//! - No honest transaction spends a deposit outpoint before its delay ends:
//!   it joins Move's active pool at `confirm_deposit`.
//! - The snapshot does not keep the approvals. After a restart, the catch-up
//!   reads the fresh ones again, and their deadlines count from the approval.
//! - An approval read after it stopped being fresh skips this check. The
//!   daily pool check covers it.

use super::Auditor;
use crate::domain::SuiDepositApprovedEvent;
use crate::findings::DepositUnbackedReason;
use crate::findings::MonitorFinding;
use crate::rpc::btc::OutpointState;
use crate::rpc::esplora::ReferenceOutput;
use bitcoin::OutPoint;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashMap;

/// How long before the delay ends the lookups stop, in seconds.
const DELAY_END_MARGIN: u64 = 2 * 60;

/// How long after an approval a source must show its payment, in seconds. It
/// leaves most of Move's ten-minute delay for the pause.
const FRESH_APPROVAL_DEADLINE: u64 = 3 * 60;

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

    /// Judge each approval that is still fresh at `finished`, when the
    /// lookups returned. Keep only the approvals that neither source shows
    /// paid yet, until their deadline.
    fn judge_fresh_approvals(
        &mut self,
        node: &HashMap<OutPoint, OutpointState>,
        reference: &HashMap<OutPoint, ReferenceOutput>,
        finished: UnixSeconds,
    ) -> Vec<MonitorFinding> {
        self.drop_stale_approvals(finished);
        let mut findings = Vec::new();
        self.fresh_approvals.retain(|outpoint, event| {
            let node = node.get(outpoint);
            let reference = reference.get(outpoint);
            let unbacked = |reason| MonitorFinding::DepositUnbacked {
                sui: event.clone(),
                reason,
            };
            if matches!(node, Some(OutpointState::Spent))
                || matches!(reference, Some(ReferenceOutput::Spent))
            {
                findings.push(unbacked(DepositUnbackedReason::Spent));
                return false;
            }
            let paid_on_reference = matches!(
                reference,
                Some(ReferenceOutput::Unspent { amount, script_pubkey })
                    if *amount == event.amount && *script_pubkey == event.script_pubkey
            );
            let paid_on_node = matches!(
                node,
                Some(OutpointState::Unspent { output, .. })
                    if output.value.to_sat() == event.amount
                        && output.script_pubkey == event.script_pubkey
            );
            if paid_on_reference || paid_on_node {
                return false;
            }
            if finished >= event.timestamp_secs.saturating_add(FRESH_APPROVAL_DEADLINE) {
                findings.push(unbacked(DepositUnbackedReason::Unverified));
                return false;
            }
            true
        });
        findings
    }

    /// Look up the outpoints of the fresh approvals on the node at
    /// `tip_height`, if it passed its sync check, and on the reference source.
    pub(super) fn check_fresh_approvals(
        &mut self,
        tip_height: Option<u64>,
        now: UnixSeconds,
    ) -> Vec<MonitorFinding> {
        self.drop_stale_approvals(now);
        if self.fresh_approvals.is_empty() {
            return Vec::new();
        }
        let outpoints = self.fresh_approvals.keys().copied().collect::<Vec<_>>();
        tracing::info!(
            approvals = outpoints.len(),
            "checking fresh deposit approvals"
        );
        let node = match tip_height {
            Some(tip_height) => self
                .rpc_pollers
                .btc_client
                .lookup_outpoint_states(&outpoints, tip_height, true)
                .unwrap_or_else(|error| {
                    tracing::warn!(?error, "node lookup of fresh approvals failed");
                    HashMap::new()
                }),
            None => HashMap::new(),
        };
        let reference = self
            .rpc_pollers
            .reference_btc
            .lookup_outputs(&outpoints)
            .unwrap_or_else(|error| {
                tracing::warn!(?error, "reference lookup of fresh approvals failed");
                HashMap::new()
            });
        self.judge_fresh_approvals(&node, &reference, now_timestamp_secs())
    }

    /// Confirm each `NotFound` on the reference source, so a fake deposit the
    /// monitor reads late, after its delay, still pauses. The reference
    /// showing it paid as approved keeps `NotFound`: only the node misses it.
    /// A spend is `Spent`. Anything else, a failed lookup too, is
    /// `Unverified`.
    pub(super) fn confirm_not_found(&self, findings: &mut [MonitorFinding]) {
        let reference = &self.rpc_pollers.reference_btc;
        for finding in findings {
            let MonitorFinding::DepositUnbacked {
                sui,
                reason: reason @ DepositUnbackedReason::NotFound,
            } = finding
            else {
                continue;
            };
            let outpoint = OutPoint::from(sui.deposit_id);
            let output = reference
                .lookup_outputs(&[outpoint])
                .map(|mut outputs| outputs.remove(&outpoint))
                .unwrap_or_else(|error| {
                    tracing::warn!(?error, %outpoint, "reference lookup of an unbacked deposit failed");
                    None
                });
            *reason = match output {
                Some(ReferenceOutput::Unspent {
                    amount,
                    script_pubkey,
                }) if amount == sui.amount && script_pubkey == sui.script_pubkey => {
                    DepositUnbackedReason::NotFound
                }
                Some(ReferenceOutput::Spent) => DepositUnbackedReason::Spent,
                _ => DepositUnbackedReason::Unverified,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with_pool;
    use crate::domain::MonitorEvent;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;

    /// An approval of `txid(9):1` at `approved_at`.
    fn approval(approved_at: UnixSeconds) -> SuiDepositApprovedEvent {
        approval_of(&deposit_request(), approved_at)
    }

    /// A fresh approval at 1_000, judged at `finished` on the given answers.
    /// Returns the findings and whether the approval was dropped.
    async fn judge(
        node: Option<OutpointState>,
        reference: Option<ReferenceOutput>,
        finished: UnixSeconds,
    ) -> (Vec<MonitorFinding>, bool) {
        let mut auditor = auditor_with_pool().await;
        let fresh = approval(1_000);
        auditor.note_fresh_approval(&fresh, 1_000);
        let outpoint = OutPoint::from(fresh.deposit_id);
        let node = node
            .map(|s| HashMap::from([(outpoint, s)]))
            .unwrap_or_default();
        let reference = reference
            .map(|s| HashMap::from([(outpoint, s)]))
            .unwrap_or_default();
        let findings = auditor.judge_fresh_approvals(&node, &reference, finished);
        (findings, auditor.fresh_approvals.is_empty())
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
    async fn either_source_can_verify_or_condemn_an_approval() {
        use DepositUnbackedReason::*;
        use OutpointState as Node;
        use ReferenceOutput as Reference;
        let fresh = approval(1_000);
        let paid = |amount| Reference::Unspent {
            amount,
            script_pubkey: fresh.script_pubkey.clone(),
        };
        let deadline = 1_000 + FRESH_APPROVAL_DEADLINE;
        // The approval stops being fresh here.
        let end = 1_000 + 600 - DELAY_END_MARGIN;
        let node_paid = |amount, script_pubkey| Node::Unspent {
            block_time: 900,
            output: bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(amount),
                script_pubkey,
            },
        };
        let unspent = node_paid(fresh.amount, fresh.script_pubkey.clone());
        let cases = [
            (Some(Node::Spent), None, 1_000, Some(Spent)),
            (
                Some(unspent.clone()),
                Some(Reference::Spent),
                1_000,
                Some(Spent),
            ),
            // A payment on one source does not outweigh a spend on the other.
            (
                Some(Node::Spent),
                Some(paid(fresh.amount)),
                1_000,
                Some(Spent),
            ),
            (Some(unspent), None, deadline, None),
            // A node that peers withhold blocks from does not see the payment.
            (
                Some(Node::Missing),
                Some(paid(fresh.amount)),
                deadline,
                None,
            ),
            (
                Some(Node::Missing),
                Some(Reference::Missing),
                deadline - 1,
                None,
            ),
            (None, None, deadline, Some(Unverified)),
            // Another amount is not the approved payment.
            (
                None,
                Some(paid(fresh.amount + 1)),
                deadline,
                Some(Unverified),
            ),
            // A real output that pays someone else is not the payment.
            (
                Some(node_paid(fresh.amount, bitcoin::ScriptBuf::new())),
                None,
                deadline,
                Some(Unverified),
            ),
            // A lookup that returns after the approval stopped being fresh.
            (Some(Node::Spent), None, end, None),
        ];
        for (node, reference, finished, reason) in cases {
            let case = format!("{node:?} {reference:?} at {finished}");
            let (findings, dropped) = judge(node, reference, finished).await;
            let expected = reason
                .map(|reason| MonitorFinding::DepositUnbacked {
                    sui: fresh.clone(),
                    reason,
                })
                .into_iter()
                .collect::<Vec<_>>();
            assert_eq!(findings, expected, "{case}");
            // Only an approval that neither source settled is kept.
            let kept = finished == deadline - 1;
            assert_eq!(dropped, !kept, "{case}");
        }
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
        assert!(auditor.check_fresh_approvals(None, end).is_empty());
        assert!(auditor.fresh_approvals.is_empty());
    }

    #[tokio::test]
    async fn a_not_found_deposit_pauses_unless_the_reference_shows_it_paid() {
        use crate::rpc::esplora::EsploraClient;
        use crate::test_utils::btc_rpc_answering;
        let late = approval(1_000);
        let not_found = || {
            vec![MonitorFinding::DepositUnbacked {
                sui: late.clone(),
                reason: DepositUnbackedReason::NotFound,
            }]
        };
        let paid = format!(
            r#"{{"status":{{"confirmed":true,"block_height":95}},"vout":[{{"value":0,"scriptpubkey":"00"}},{{"value":{},"scriptpubkey":"{}"}}]}}"#,
            late.amount,
            late.script_pubkey.to_hex_string()
        );
        let unconfirmed = r#"{"status":{"confirmed":false},"vout":[]}"#.to_owned();
        let cases = [
            (
                Some(vec![
                    "100".to_owned(),
                    paid,
                    r#"{"spent":false}"#.to_owned(),
                ]),
                DepositUnbackedReason::NotFound,
            ),
            (
                Some(vec!["100".to_owned(), unconfirmed]),
                DepositUnbackedReason::Unverified,
            ),
            // Nothing listens: the lookup fails.
            (None, DepositUnbackedReason::Unverified),
        ];
        for (answers, reason) in cases {
            let mut auditor = auditor_with_pool().await;
            let (url, server) = match answers {
                Some(answers) => {
                    let (url, server) = btc_rpc_answering(answers);
                    (url, Some(server))
                }
                None => ("http://127.0.0.1:1".to_owned(), None),
            };
            auditor.rpc_pollers.reference_btc = EsploraClient::new(&url, 1);
            let mut findings = not_found();
            auditor.confirm_not_found(&mut findings);
            if let Some(server) = server {
                server.join().unwrap();
            }
            assert_eq!(
                findings,
                vec![MonitorFinding::DepositUnbacked {
                    sui: late.clone(),
                    reason
                }]
            );
        }
    }
}
