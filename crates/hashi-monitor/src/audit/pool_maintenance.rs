// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The auditor maintains the bridge's unspent transaction output (UTXO) pool.
//!
//! Why it exists:
//! - Complete flows change the pool's holdings.
//! - A due Bitcoin check starts after the pool update.
//!
//! How it works:
//! 1. Remove closed state machines, then add their complete flows to the pool.
//! 2. Check Bitcoin at the first maintenance tick.
//! 3. Repeat successful checks after `UTXO_CHECK_INTERVAL` seconds.
//! 4. Retry failed checks at the next maintenance tick.
//!
//! Assumptions:
//! - Polling and maintenance ticks run sequentially.
//!   For example, deposit D creates an output that withdrawal W spends. Bitcoin confirms both transactions.
//!   Within one Bitcoin tick, the auditor processes withdrawal results before deposit results.
//!   W therefore becomes complete while D still appears pending and its output is absent from the pool.
//!   Maintenance during this gap could apply W without adding D and report `UtxoUnknownInputSpent`.
//!   After the bitcoin tick finishes, maintenance takes both machines and adds D before applying W.

use super::Auditor;
use crate::domain::ConfirmedDeposit;
use crate::domain::ConfirmedWithdrawal;
use crate::domain::WithdrawalEventType;
use crate::findings::MonitorFinding;
use crate::metrics::SOURCE_UTXO;
use crate::time::human_timestamp_delta;
use crate::time::utc_timestamp;
use hashi_types::guardian::time::now_timestamp_secs;

impl Auditor {
    /// Run the Bitcoin check of the pool when it is due.
    /// A failed check is logged. The next maintenance tick retries it.
    pub fn check_utxo_pool_if_due(&mut self) {
        if self.pool_check_due(now_timestamp_secs())
            && let Err(error) = self.check_utxo_pool()
        {
            tracing::warn!(
                source = SOURCE_UTXO,
                ?error,
                "UTXO pool check failed; retrying at the next tick"
            );
        }
    }

    /// Take closed machines and add their complete flows to the pool.
    /// Report the findings and update the pool gauges. Return the findings for tests.
    /// Call between ticks, after all Bitcoin results have been processed.
    /// For complete withdrawals, dependent state machines must already be closed or ready to close.
    pub fn gc_and_update_pool(&mut self) -> Vec<MonitorFinding> {
        let mut findings = Vec::new();
        let (withdrawals_before, deposits_before) = self.open_flows();
        let confirmed_deposits = self.take_closed_deposits();
        let confirmed_withdrawals = self.take_closed_withdrawals();
        let (open_withdrawals, open_deposits) = self.open_flows();
        for deposit in &confirmed_deposits {
            findings.extend(self.utxo_pool.add_deposit(deposit));
        }
        findings.extend(self.utxo_pool.add_withdrawals(&confirmed_withdrawals));
        tracing::info!(
            withdrawals_closed = withdrawals_before - open_withdrawals,
            deposits_closed = deposits_before - open_deposits,
            deposits_paid = confirmed_deposits.len(),
            open_withdrawals,
            open_deposits,
            oldest_withdrawals = %self.oldest_open_withdrawals(),
            oldest_deposits = %self.oldest_open_deposits(),
            utxos_held = self.utxo_pool.len(),
            pool_value_sats = self.utxo_pool.value(),
            "removed the closed machines and updated the pool"
        );

        self.report_findings("pool", &findings);
        self.metrics
            .set_utxo_pool(self.utxo_pool.len(), self.utxo_pool.oldest_timestamp());
        findings
    }

    /// Remove the deposit machines that closed since the last call. Returns
    /// the deposits Bitcoin confirmed, for the pool.
    fn take_closed_deposits(&mut self) -> Vec<ConfirmedDeposit> {
        let mut deposits = Vec::new();
        for (request_id, sm) in self
            .pending_deposits
            .extract_if(|_, sm| sm.is_ready_for_gc())
        {
            let deposit_id = sm.deposit_id();
            let deposit = sm.into_confirmed();
            match &deposit {
                Some(deposit) => tracing::debug!(
                    deposit_id = %deposit.deposit_id,
                    amount = deposit.amount,
                    block_time = %utc_timestamp(deposit.block_time),
                    "deposit request confirmed on Bitcoin at a bridge address"
                ),
                // Bitcoin answered without a UTXO, or the request lapsed.
                None => tracing::debug!(
                    %request_id,
                    %deposit_id,
                    "deposit request closed without a UTXO"
                ),
            }
            deposits.extend(deposit);
        }
        deposits
    }

    /// Remove closed withdrawal machines and return their confirmed withdrawals for the pool.
    fn take_closed_withdrawals(&mut self) -> Vec<ConfirmedWithdrawal> {
        let mut withdrawals = Vec::new();
        for (wid, sm) in self
            .pending_withdrawals
            .extract_if(|_, sm| sm.is_ready_for_gc())
        {
            let e1 = sm
                .get(WithdrawalEventType::E1HashiApproved)
                .expect("completed withdrawal has E1");
            let e2 = sm
                .get(WithdrawalEventType::E2GuardianApproved)
                .expect("completed withdrawal has E2");
            let e3 = sm
                .get(WithdrawalEventType::E3BtcConfirmed)
                .expect("completed withdrawal has E3");
            tracing::debug!(
                %wid,
                e1_at = %utc_timestamp(e1.timestamp_secs),
                e2_at = %utc_timestamp(e2.timestamp_secs),
                e3_at = %utc_timestamp(e3.timestamp_secs),
                e1_to_e2 = %human_timestamp_delta(e2.timestamp_secs, e1.timestamp_secs),
                e2_to_e3 = %human_timestamp_delta(e3.timestamp_secs, e2.timestamp_secs),
                "withdrawal flow is complete"
            );
            withdrawals.extend(sm.into_confirmed());
        }
        withdrawals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with_pool;
    use crate::audit::tests::complete_withdrawal;
    use crate::test_utils::txid;
    use bitcoin::OutPoint;
    use hashi_types::guardian::WithdrawalID;

    #[tokio::test]
    async fn a_complete_withdrawal_spending_an_input_no_flow_names_is_a_finding() {
        let mut auditor = auditor_with_pool().await;
        let timing = auditor.cfg.timing.clone();
        let unknown = OutPoint {
            txid: txid(9),
            vout: 1,
        };
        auditor.pending_withdrawals.insert(
            WithdrawalID::new([7; 32]),
            complete_withdrawal(7, 7, vec![unknown], &timing),
        );

        let findings = auditor.gc_and_update_pool();

        assert_eq!(
            findings,
            vec![MonitorFinding::UtxoUnknownInputSpent {
                outpoint: unknown,
                txid: txid(7),
            }]
        );
        assert!(auditor.pending_withdrawals.is_empty());
    }
}
