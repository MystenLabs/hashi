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
//! 2. Drop each suspect spend that the pool no longer holds. A completed
//!    withdrawal spent it.
//! 3. Keep the other suspect spends until Sui polling passes their lookup
//!    completion timestamps.
//! 4. Clear a spend of an input that a pending withdrawal lists, if that
//!    withdrawal's transaction is in a block. An output is spent only once,
//!    so that transaction is the spender. Bitcoin Core cannot name the
//!    spender of an output. Move locks an input to one withdrawal, so an
//!    input that two pending withdrawals list is a `WithdrawalInvalid`.
//! 5. Report the remaining spends as `UtxoUnexpectedSpend`. This includes an
//!    input of a pending withdrawal that another transaction spent.
//! 6. Log `DepositNotApproved` for each unapproved deposit whose latest
//!    request is more than `DEPOSIT_REQUEST_WATCH` before the Sui cursor.
//!    The log repeats at each check until an approval comes.
//! 7. Report `SourceStale` for the pool check when none has succeeded for
//!    `UTXO_CHECK_INTERVAL` plus `SOURCE_STALE_LIMIT`. Before the first
//!    success, count from the start of the audit loop, after the first
//!    catch-up.

use super::Auditor;
use super::rpc_pollers::SOURCE_STALE_LIMIT;
use crate::findings::MonitorFinding;
use crate::findings::WithdrawalInvalidReason;
use crate::metrics::SOURCE_UTXO;
use bitcoin::OutPoint;
use bitcoin::Txid;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use std::collections::HashMap;
use std::collections::HashSet;

/// How long after a successful pool check the next one is due, in seconds.
/// Every tick runs on the one audit task, so a check delays the polls by
/// the time its batched lookups take.
const UTXO_CHECK_INTERVAL: u64 = 24 * 60 * 60;

impl Auditor {
    /// Check each pool UTXO on Bitcoin and keep unexplained spends for `check_suspect_spends`.
    /// Report findings and record the check time after success.
    pub fn check_utxo_pool(&mut self) -> anyhow::Result<()> {
        let tip_height = self.rpc_pollers.btc_client.synced_height()?;
        let pool = &self.utxo_pool;
        let outpoints = pool.outpoints();
        tracing::info!(utxos = outpoints.len(), "starting UTXO pool check");
        let states = self
            .rpc_pollers
            .btc_client
            .lookup_outpoint_states(&outpoints, tip_height, false)?;
        // Unlike `tick_btc` confirmation checks, `gettxout` reads live state.
        // The pool check does not use one Bitcoin snapshot and can see spends from newer blocks.
        // Record completion time so Sui polling must cover the whole lookup period.
        let now = now_timestamp_secs();
        let (findings, suspects) = pool.check(&states, now, &self.cfg.timing);
        pool.log_unapproved_past_deadline(self.rpc_pollers.sui_read_until(), &self.cfg.timing);
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

    /// A `SourceStale` finding when no pool check has succeeded for
    /// `UTXO_CHECK_INTERVAL` plus `SOURCE_STALE_LIMIT` at `now`.
    pub fn stale_pool_check(&self, now: UnixSeconds) -> Option<MonitorFinding> {
        let checked_through = self.last_successful_pool_check.unwrap_or(self.started_at);
        let limit_secs = UTXO_CHECK_INTERVAL + SOURCE_STALE_LIMIT;
        (now.saturating_sub(checked_through) > limit_secs).then_some(MonitorFinding::SourceStale {
            source: SOURCE_UTXO,
            checked_through,
            limit_secs,
        })
    }

    /// The pending withdrawal that lists each input, by wid and txid. Also
    /// an `InputClaimed` for each input that a second withdrawal lists. The
    /// order by wid keeps the findings the same at each tick.
    fn pending_spenders(&self) -> (HashMap<OutPoint, (WithdrawalID, Txid)>, Vec<MonitorFinding>) {
        let mut machines = self.pending_withdrawals.values().collect::<Vec<_>>();
        machines.sort_by_key(|sm| sm.wid());
        let mut spenders = HashMap::new();
        let mut claims = Vec::new();
        for sm in machines {
            for input in &sm.tx().inputs {
                let outpoint = OutPoint {
                    txid: Txid::from(input.id.txid),
                    vout: input.id.vout,
                };
                if let Some((other, _)) = spenders.insert(outpoint, (sm.wid(), sm.btc_txid())) {
                    claims.push(MonitorFinding::WithdrawalInvalid {
                        wid: sm.wid(),
                        reason: WithdrawalInvalidReason::InputClaimed { outpoint, other },
                    });
                }
            }
        }
        (spenders, claims)
    }

    /// Wait until Sui polling passes the lookup completion time. Then clear
    /// the spends that a withdrawal explains, and report the others as
    /// unexpected. Also report each input that two pending withdrawals list.
    /// See the module doc. Return the spend findings for tests.
    pub fn check_suspect_spends(&mut self) -> Vec<MonitorFinding> {
        let pool = &self.utxo_pool;
        for (outpoint, _) in self
            .suspect_spends
            .extract_if(|outpoint, _| !pool.holds(outpoint))
        {
            tracing::info!(%outpoint, "a completed withdrawal explains the spend the pool check saw");
        }
        let sui_cursor = self.rpc_pollers.sui_read_until();
        let ready = self
            .suspect_spends
            .extract_if(|_, suspect| sui_cursor > suspect.checked_at)
            .collect::<Vec<_>>();
        let (spenders, claims) = self.pending_spenders();
        self.report_findings(SOURCE_UTXO, &claims);
        let txids = ready
            .iter()
            .filter_map(|(outpoint, _)| spenders.get(outpoint))
            .map(|(_, txid)| *txid)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mined = match self.rpc_pollers.btc_client.lookup_mined(&txids) {
            Ok(mined) => mined,
            Err(error) => {
                tracing::warn!(?error, "suspect spends wait for the next tick");
                self.suspect_spends.extend(ready);
                return Vec::new();
            }
        };
        let mut findings = Vec::new();
        let judged = ready.len();
        for (outpoint, suspect) in ready {
            if spenders
                .get(&outpoint)
                .is_some_and(|(_, txid)| mined.contains(txid))
            {
                tracing::info!(%outpoint, "a pending withdrawal explains the spend the pool check saw");
            } else {
                findings.push(MonitorFinding::UtxoUnexpectedSpend {
                    outpoint,
                    amount: suspect.amount,
                });
            }
        }
        // Only when there is work, so a quiet pool adds no line.
        if judged > 0 || !self.suspect_spends.is_empty() {
            tracing::info!(
                judged,
                unexpected = findings.len(),
                waiting_for_sui = self.suspect_spends.len(),
                "checked the suspect spends"
            );
        }
        self.report_findings(SOURCE_UTXO, &findings);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Auditor;
    use crate::audit::tests::auditor_with;
    use crate::audit::tests::auditor_with_pool;
    use crate::audit::tests::complete_withdrawal;
    use crate::config::Config;
    use crate::domain::BtcConfirmedDeposit;
    use crate::domain::DepositId;
    use crate::domain::MonitorWithdrawalEvent;
    use crate::domain::WithdrawalEventType;
    use crate::domain::utxo_pool::SuspectSpend;
    use crate::metrics::MonitorMetrics;
    use crate::state_machine::WithdrawalStateMachine;
    use crate::test_utils::approved;
    use crate::test_utils::btc_rpc_answering;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::synced_btc_node_answers;
    use crate::test_utils::txid;
    use crate::test_utils::unapproved;
    use crate::test_utils::withdrawal_tx;
    use bitcoin::Amount;
    use bitcoin::Transaction;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize_hex;
    use bitcoin::transaction::Version;
    use hashi_types::guardian::WithdrawalID;
    use std::sync::Arc;
    use std::thread::JoinHandle;

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
        assert!(
            auditor
                .utxo_pool
                .add_deposit(&unapproved(BtcConfirmedDeposit {
                    deposit_id: DepositId::new(txid(9), 1),
                    amount: 5_000,
                    script_pubkey: p2wpkh(0x54),
                    block_time: 900,
                }))
                .is_empty()
        );

        assert!(auditor.check_suspect_spends().is_empty());
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
        assert!(
            auditor
                .utxo_pool
                .add_deposit(&unapproved(BtcConfirmedDeposit {
                    deposit_id: DepositId::new(txid(9), 1),
                    amount: 5_000,
                    script_pubkey: p2wpkh(0x54),
                    block_time: 900,
                }))
                .is_empty()
        );

        let findings = auditor.check_suspect_spends();

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnexpectedSpend {
                outpoint,
                amount: 5_000,
            }]
        );
        assert!(auditor.suspect_spends.is_empty());
    }

    /// An auditor with a Bitcoin node that answers its requests with
    /// `bodies`, in order. Its pool holds `txid(0x51):1`, and a pool check
    /// saw it spent. A pending withdrawal with only E1 and the txid
    /// `btc_txid` lists it as an input.
    fn auditor_with_spent_pending_input(
        btc_txid: Txid,
        bodies: Vec<String>,
    ) -> (Auditor, OutPoint, JoinHandle<Vec<String>>) {
        let (rpc_url, server) = btc_rpc_answering(bodies);
        let mut cfg = Config::for_tests();
        cfg.btc.rpc_url = rpc_url;
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        // `withdrawal_tx` spends `txid(0x51):1`.
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        assert!(
            auditor
                .utxo_pool
                .add_deposit(&approved(BtcConfirmedDeposit {
                    deposit_id: DepositId::new(txid(0x51), 1),
                    amount: 5_000,
                    script_pubkey: p2wpkh(0x55),
                    block_time: 900,
                }))
                .is_empty()
        );
        let approval = MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E1HashiApproved,
            wid: WithdrawalID::new([7; 32]),
            timestamp_secs: 1_000,
            btc_txid,
            tx: withdrawal_tx(vec![0x55; 20]),
        };
        let sm = WithdrawalStateMachine::new(approval, &cfg.timing);
        auditor.pending_withdrawals.insert(sm.wid(), sm);
        let checked_at = auditor.rpc_pollers.sui_read_until() - 1;
        auditor.suspect_spends.insert(
            outpoint,
            SuspectSpend {
                checked_at,
                amount: 5_000,
            },
        );
        (auditor, outpoint, server)
    }

    #[tokio::test]
    async fn an_input_that_two_pending_withdrawals_list_is_invalid() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        // `withdrawal_tx` spends `txid(0x51):1`.
        let event = |event_type, wid_seed, fill| MonitorWithdrawalEvent {
            event_type,
            wid: WithdrawalID::new([wid_seed; 32]),
            timestamp_secs: 1_000,
            btc_txid: txid(fill),
            tx: withdrawal_tx(vec![0x55; 20]),
        };
        for event in [
            event(WithdrawalEventType::E1HashiApproved, 1, 1),
            event(WithdrawalEventType::E2GuardianApproved, 2, 2),
        ] {
            let sm = WithdrawalStateMachine::new(event, &timing);
            auditor.pending_withdrawals.insert(sm.wid(), sm);
        }

        let (spenders, claims) = auditor.pending_spenders();

        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        assert_eq!(
            claims,
            vec![MonitorFinding::WithdrawalInvalid {
                wid: WithdrawalID::new([2; 32]),
                reason: WithdrawalInvalidReason::InputClaimed {
                    outpoint,
                    other: WithdrawalID::new([1; 32]),
                },
            }]
        );
        assert_eq!(spenders[&outpoint], (WithdrawalID::new([2; 32]), txid(2)));
    }

    #[tokio::test]
    async fn a_pending_input_that_another_transaction_spent_is_unexpected() {
        let not_found = r#"[{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain transaction"},"id":0}]"#;
        let mut bodies = synced_btc_node_answers();
        bodies.push(not_found.to_string());
        let (mut auditor, outpoint, server) = auditor_with_spent_pending_input(txid(7), bodies);

        assert_eq!(
            auditor.check_suspect_spends(),
            vec![MonitorFinding::UtxoUnexpectedSpend {
                outpoint,
                amount: 5_000,
            }]
        );
        server.join().unwrap();
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_pending_input_that_its_withdrawal_spent_in_a_block_is_cleared() {
        // The withdrawal's transaction is one block deep, below the
        // threshold, so the machine has not found E3 yet.
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: txid(0x51),
                    vout: 1,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(4_000),
                script_pubkey: p2wpkh(0x53),
            }],
        };
        let body = format!(
            r#"[{{"result":{{"hex":"{}","blockhash":"{}","confirmations":1}},"error":null,"id":0}}]"#,
            serialize_hex(&tx),
            "11".repeat(32),
        );
        let mut bodies = synced_btc_node_answers();
        bodies.push(body);
        let (mut auditor, _, server) = auditor_with_spent_pending_input(tx.compute_txid(), bodies);

        assert!(auditor.check_suspect_spends().is_empty());
        // Before the join: a failed lookup sends fewer requests, and the join
        // would then wait for them.
        assert!(auditor.suspect_spends.is_empty());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_suspect_spend_waits_while_the_bitcoin_node_is_not_synced() {
        // A node that is not synced can answer "not found" for a mined
        // transaction, so the lookup must not run.
        let in_ibd = r#"{"result":{"chain":"regtest","blocks":90,"headers":100,"time":0,"initialblockdownload":true},"error":null,"id":"hashi-monitor"}"#;
        let (mut auditor, outpoint, server) =
            auditor_with_spent_pending_input(txid(7), vec![in_ibd.to_string()]);

        assert!(auditor.check_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.contains_key(&outpoint));
        let requests = server.join().unwrap();
        assert!(requests[0].contains("getblockchaininfo"), "{requests:?}");
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
            pool.add_deposit(&approved(BtcConfirmedDeposit {
                deposit_id: DepositId::new(txid(0x51), 1),
                amount: 5_000,
                script_pubkey: p2wpkh(0x55),
                block_time: 900,
            }))
            .is_empty()
        );
        assert!(
            pool.add_withdrawals(&[withdrawal.finished().unwrap()])
                .is_empty()
        );

        assert!(auditor.check_suspect_spends().is_empty());
        assert!(auditor.suspect_spends.is_empty());
    }

    #[tokio::test]
    async fn a_pool_check_that_does_not_succeed_is_stale() {
        let cfg = Config::for_tests();
        let mut auditor = auditor_with(&cfg, Arc::new(MonitorMetrics::new()));
        let limit_secs = UTXO_CHECK_INTERVAL + SOURCE_STALE_LIMIT;
        let stale = |checked_through| {
            Some(MonitorFinding::SourceStale {
                source: SOURCE_UTXO,
                checked_through,
                limit_secs,
            })
        };

        // Before the first success, the run's start counts.
        let start = auditor.started_at;
        assert_eq!(auditor.stale_pool_check(start + limit_secs), None);
        assert_eq!(
            auditor.stale_pool_check(start + limit_secs + 1),
            stale(start)
        );

        auditor.last_successful_pool_check = Some(start + 10);
        assert_eq!(auditor.stale_pool_check(start + 10 + limit_secs), None);
        assert_eq!(
            auditor.stale_pool_check(start + 10 + limit_secs + 1),
            stale(start + 10)
        );
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
