// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor checks its unspent transaction output (UTXO) pool against Bitcoin.
//!
//! Why it exists:
//! - Bitcoin can report a spend before the auditor reads its Sui withdrawal record.
//! - A suspect spend is a Bitcoin spend that the auditor has not yet judged.
//!
//! How it works:
//! 1. Check Bitcoin at the first maintenance tick, then after `UTXO_CHECK_INTERVAL` seconds since the last successful check.
//! 2. Keep suspect spends until Sui polling passes their lookup completion timestamps.
//! 3. Clear spends that pending or completed withdrawals explain.
//! 4. Report the remaining spends as findings.

use super::Auditor;
use crate::findings::MonitorFinding;
use crate::metrics::SOURCE_UTXO;
use bitcoin::OutPoint;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashSet;

/// How long after a successful pool check the next one is due, in seconds.
/// Every tick runs on the one audit task, so a check delays the polls by
/// the time its batched lookups take.
const UTXO_CHECK_INTERVAL: u64 = 24 * 60 * 60;

impl Auditor {
    /// Check each pool UTXO on Bitcoin and keep unexplained spends for `judge_suspect_spends`.
    /// Report findings and record the check time after success.
    pub fn check_utxo_pool(&mut self) -> anyhow::Result<()> {
        let tip_height = self.rpc_pollers.btc_client.synced_height()?;
        let pool = &self.utxo_pool;
        let outpoints = pool.outpoints();
        tracing::info!(utxos = outpoints.len(), "starting UTXO pool check");
        let states = self
            .rpc_pollers
            .btc_client
            .lookup_outpoint_states(&outpoints, tip_height)?;
        // Unlike `tick_btc` confirmation checks, `gettxout` reads live state.
        // The pool check does not use one Bitcoin snapshot and can see spends from newer blocks.
        // Record completion time so Sui polling must cover the whole lookup period.
        let now = now_timestamp_secs();
        let (findings, suspects) = pool.check(&states, now, &self.cfg.timing);
        tracing::info!(
            utxos = outpoints.len(),
            findings = findings.len(),
            suspects = suspects.len(),
            "finished UTXO pool check"
        );
        // A suspect already waiting keeps its earlier time.
        for (outpoint, suspect) in suspects {
            self.suspect_spends.entry(outpoint).or_insert(suspect);
        }
        self.report_findings(SOURCE_UTXO, &findings);
        self.metrics.set_checked_through(SOURCE_UTXO, now);
        self.last_successful_pool_check = Some(now);
        Ok(())
    }

    /// Whether a pool check is due at `now`: none has succeeded in this run,
    /// or the last one finished `UTXO_CHECK_INTERVAL` ago or more.
    pub fn pool_check_due(&self, now: UnixSeconds) -> bool {
        self.last_successful_pool_check
            .is_none_or(|last| now.saturating_sub(last) >= UTXO_CHECK_INTERVAL)
    }

    /// The inputs of every withdrawal the monitor follows. It spends them
    /// on Bitcoin before its flow completes, so a spend of one is explained.
    fn pending_withdrawal_inputs(&self) -> HashSet<OutPoint> {
        self.pending_withdrawals
            .values()
            .flat_map(|sm| sm.tx().inputs.iter())
            .map(|input| OutPoint {
                txid: Txid::from(input.id.txid),
                vout: input.id.vout,
            })
            .collect()
    }

    /// Wait until Sui polling passes the lookup completion time.
    /// Clear spends explained by pending withdrawals or the pool's spent record.
    /// Report the remaining spends as unexpected.
    pub fn judge_suspect_spends(&mut self) -> Vec<MonitorFinding> {
        let named = self.pending_withdrawal_inputs();
        let sui_cursor = self.rpc_pollers.sui_read_until();
        let mut findings = Vec::new();
        for (outpoint, suspect) in self
            .suspect_spends
            .extract_if(|_, suspect| sui_cursor > suspect.checked_at)
        {
            if named.contains(&outpoint) || self.utxo_pool.is_spent(&outpoint) {
                tracing::info!(%outpoint, "a withdrawal explains the spend the pool check saw");
            } else {
                findings.push(MonitorFinding::UtxoUnexpectedSpend {
                    outpoint,
                    amount: suspect.amount,
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with;
    use crate::audit::tests::auditor_with_pool;
    use crate::audit::tests::complete_withdrawal;
    use crate::config::Config;
    use crate::domain::ConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::utxo_pool::SuspectSpend;
    use crate::metrics::MonitorMetrics;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::txid;
    use hashi_types::guardian::WithdrawalID;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_suspect_spend_waits_while_the_sui_cursor_is_not_past_its_time() {
        let mut auditor = auditor_with_pool().await;
        let cursor = auditor.rpc_pollers.sui_read_until();
        let outpoint = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                checked_at: cursor,
                amount: 5_000,
            },
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.contains_key(&outpoint));
    }

    #[tokio::test]
    async fn a_suspect_spend_is_unexpected_once_the_sui_cursor_is_past_its_time() {
        let mut auditor = auditor_with_pool().await;
        let cursor = auditor.rpc_pollers.sui_read_until();
        let outpoint = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                checked_at: cursor - 1,
                amount: 5_000,
            },
        );

        let findings = auditor.judge_suspect_spends();

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnexpectedSpend {
                outpoint,
                amount: 5_000,
            }]
        );
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_suspect_spend_a_withdrawal_names_is_cleared_without_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let cursor = auditor.rpc_pollers.sui_read_until();
        // `withdrawal_tx` spends `txid(0x51):1`.
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                checked_at: cursor - 1,
                amount: 5_000,
            },
        );
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![outpoint], &timing),
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_suspect_spend_the_pool_took_a_withdrawal_for_is_cleared_without_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let cursor = auditor.rpc_pollers.sui_read_until();
        // `withdrawal_tx` spends `txid(0x51):1`.
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                checked_at: cursor - 1,
                amount: 5_000,
            },
        );
        // The withdrawal completed after the check: the pool took it, and
        // the auditor no longer follows it.
        let withdrawal = complete_withdrawal(7, 7, vec![outpoint], &timing);
        let pool = &mut auditor.utxo_pool;
        assert!(
            pool.add_deposit(&ConfirmedDeposit {
                deposit_id: DepositId::new(txid(0x51), 1),
                amount: 5_000,
                script_pubkey: p2wpkh(0x55),
                block_time: 900,
            })
            .is_none()
        );
        assert!(
            pool.add_withdrawals(&[withdrawal.confirmed().cloned().unwrap()])
                .is_empty()
        );

        assert!(auditor.judge_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_pool_check_is_due_until_one_succeeds_and_a_day_after() {
        let cfg = Config::for_tests();
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        assert!(auditor.pool_check_due(1_000));

        auditor.last_successful_pool_check = Some(1_000);
        assert!(!auditor.pool_check_due(1_000 + UTXO_CHECK_INTERVAL - 1));
        assert!(auditor.pool_check_due(1_000 + UTXO_CHECK_INTERVAL));
    }
}
