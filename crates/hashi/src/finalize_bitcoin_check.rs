// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Sequence;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::Wtxid;
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use corepc_client::types::model::MempoolAcceptance;
use prometheus::IntGauge;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::metrics::Metrics;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::withdrawals::confirmed_unlocked_utxo_ids;

const MEMBER_WAIT: Duration = Duration::from_secs(10);
const FAILURE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    ScriptFailure {
        reason: String,
        details: Option<String>,
    },
    RejectedOther {
        reason: String,
    },
    Unavailable(String),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Accepted => "accepted",
            Verdict::ScriptFailure { .. } => "script_failure",
            Verdict::RejectedOther { .. } => "rejected_other",
            Verdict::Unavailable(_) => "unavailable",
        }
    }

    pub(crate) fn ensure_signable(
        self,
        withdrawal_id: Address,
        txid: bitcoin::Txid,
    ) -> anyhow::Result<()> {
        if let Verdict::ScriptFailure { reason, details } = self {
            anyhow::bail!(
                "bitcoind fails withdrawal {withdrawal_id}'s signed transaction {txid}: {reason}{}",
                details.map(|d| format!(" ({d})")).unwrap_or_default()
            );
        }
        Ok(())
    }
}

pub fn classify(results: &[MempoolAcceptance]) -> Verdict {
    let [result] = results else {
        return Verdict::Unavailable(format!(
            "testmempoolaccept returned {} results, expected 1",
            results.len()
        ));
    };
    if result.allowed {
        return Verdict::Accepted;
    }
    let reason = result.reject_reason.clone().unwrap_or_default();
    if is_script_failure(&reason) {
        Verdict::ScriptFailure {
            reason,
            details: result.reject_details.clone(),
        }
    } else {
        Verdict::RejectedOther { reason }
    }
}

fn is_script_failure(reason: &str) -> bool {
    fails_script_check(reason)
        || reason == "scriptsig-not-pushonly"
        || reason == "scriptsig-size"
        || reason == "bad-witness-nonstandard"
}

fn fails_script_check(reason: &str) -> bool {
    reason.contains("script-verify-flag")
}

fn spend_probe_result(results: &[MempoolAcceptance]) -> Probed {
    match classify(results) {
        Verdict::ScriptFailure { reason, .. } if fails_script_check(&reason) => Probed::Refused,
        Verdict::ScriptFailure { reason, .. } => Probed::Missed(format!(
            "bitcoind rejected the probe's standard spend as {reason}, so it refuses every withdrawal"
        )),
        Verdict::RejectedOther { reason } if reason == "max-fee-exceeded" => {
            Probed::Missed(format!(
                "bitcoind passed the scripts of a spend with invalid signatures, then answered {reason}"
            ))
        }
        Verdict::RejectedOther { reason } => Probed::Missed(format!(
            "bitcoind answered {reason} before checking the scripts of a spend with invalid signatures"
        )),
        Verdict::Accepted => {
            Probed::Missed("bitcoind accepted a spend with invalid signatures".into())
        }
        Verdict::Unavailable(error) => Probed::Unanswered(error),
    }
}

pub(crate) struct FinalizeBitcoinCheck {
    metrics: Arc<Metrics>,
    failures: Mutex<HashMap<Wtxid, (Instant, Verdict)>>,
    in_flight: Mutex<HashMap<Wtxid, watch::Receiver<Option<Verdict>>>>,
}

impl FinalizeBitcoinCheck {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            failures: Mutex::default(),
            in_flight: Mutex::default(),
        }
    }

    pub(crate) async fn check<F, Fut>(
        self: &Arc<Self>,
        withdrawal_id: Address,
        tx: bitcoin::Transaction,
        test_mempool_accept: F,
    ) -> Verdict
    where
        F: FnOnce(bitcoin::Transaction) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Vec<MempoolAcceptance>>> + Send + 'static,
    {
        let verdict = self
            .check_uncounted(withdrawal_id, tx, test_mempool_accept)
            .await;
        self.record(&verdict);
        verdict
    }

    pub(crate) fn unavailable(&self, withdrawal_id: Address, error: String) -> Verdict {
        debug!(%withdrawal_id, %error, "could not assemble the signed withdrawal to check it");
        let verdict = Verdict::Unavailable(error);
        self.record(&verdict);
        verdict
    }

    fn record(&self, verdict: &Verdict) {
        self.metrics
            .withdrawal_bitcoin_check_total
            .with_label_values(&[verdict.label()])
            .inc();
    }

    async fn check_uncounted<F, Fut>(
        self: &Arc<Self>,
        withdrawal_id: Address,
        tx: bitcoin::Transaction,
        test_mempool_accept: F,
    ) -> Verdict
    where
        F: FnOnce(bitcoin::Transaction) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<Vec<MempoolAcceptance>>> + Send + 'static,
    {
        let wtxid = tx.compute_wtxid();
        let mut receiver = {
            let mut in_flight = self.in_flight.lock().unwrap();
            if let Some(verdict) = self.cached_failure(&wtxid) {
                return verdict;
            }
            match in_flight.get(&wtxid) {
                Some(receiver) => receiver.clone(),
                None => {
                    let (sender, receiver) = watch::channel(None);
                    in_flight.insert(wtxid, receiver.clone());
                    tokio::spawn(self.clone().run(
                        withdrawal_id,
                        wtxid,
                        tx,
                        test_mempool_accept,
                        sender,
                    ));
                    receiver
                }
            }
        };
        match tokio::time::timeout(MEMBER_WAIT, receiver.wait_for(Option::is_some)).await {
            Ok(Ok(verdict)) => verdict.clone().expect("waited for a verdict"),
            Ok(Err(_)) => Verdict::Unavailable("the bitcoind check ended without an answer".into()),
            Err(_) => Verdict::Unavailable(format!(
                "testmempoolaccept did not answer within {}s",
                MEMBER_WAIT.as_secs()
            )),
        }
    }

    async fn run<F, Fut>(
        self: Arc<Self>,
        withdrawal_id: Address,
        wtxid: Wtxid,
        tx: bitcoin::Transaction,
        test_mempool_accept: F,
        sender: watch::Sender<Option<Verdict>>,
    ) where
        F: FnOnce(bitcoin::Transaction) -> Fut,
        Fut: Future<Output = anyhow::Result<Vec<MempoolAcceptance>>>,
    {
        let _entry = InFlightEntry {
            check: self.clone(),
            wtxid,
        };
        let txid = tx.compute_txid();
        let started = Instant::now();
        let answer = test_mempool_accept(tx).await;
        self.metrics
            .withdrawal_bitcoin_check_latency_seconds
            .observe(started.elapsed().as_secs_f64());
        let verdict = match answer {
            Ok(results) => classify(&results),
            Err(e) => Verdict::Unavailable(format!("{e:#}")),
        };
        match &verdict {
            Verdict::ScriptFailure { reason, details } => {
                warn!(
                    %withdrawal_id,
                    %txid,
                    %reason,
                    details = details.as_deref().unwrap_or_default(),
                    "bitcoind fails the signed withdrawal's scripts"
                );
                self.metrics
                    .withdrawal_bitcoin_check_script_failures_total
                    .inc();
                let mut failures = self.failures.lock().unwrap();
                failures.retain(|_, (at, _)| at.elapsed() < FAILURE_TTL);
                failures.insert(wtxid, (Instant::now(), verdict.clone()));
            }
            other => debug!(%withdrawal_id, %txid, verdict = ?other, "bitcoind check answered"),
        }
        sender.send_replace(Some(verdict));
    }

    fn cached_failure(&self, wtxid: &Wtxid) -> Option<Verdict> {
        self.failures
            .lock()
            .unwrap()
            .get(wtxid)
            .filter(|(at, _)| at.elapsed() < FAILURE_TTL)
            .map(|(_, verdict)| verdict.clone())
    }
}

struct InFlightEntry {
    check: Arc<FinalizeBitcoinCheck>,
    wtxid: Wtxid,
}

impl Drop for InFlightEntry {
    fn drop(&mut self) {
        self.check
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.wtxid);
    }
}

const PROBE_INTERVAL: Duration = Duration::from_secs(60 * 60);
const PROBE_POLL: Duration = Duration::from_secs(60);
const PROBE_OUTPUT_SATS: u64 = 1_000;
const PROBE_MIN_SATS: u64 = 30_000;

#[derive(Debug)]
enum Probed {
    Refused,
    Answered,
    Missed(String),
    Unanswered(String),
}

struct Probes {
    answers: Option<bool>,
    refuses_bad_spend: Option<bool>,
    blind: i64,
    logged: Option<(String, Instant)>,
}

impl Default for Probes {
    fn default() -> Self {
        Self {
            answers: None,
            refuses_bad_spend: None,
            blind: -1,
            logged: None,
        }
    }
}

impl Probes {
    fn record(&mut self, gauge: &IntGauge, probed: Probed) {
        let error = match probed {
            Probed::Refused => {
                self.answers = Some(true);
                self.refuses_bad_spend = Some(true);
                None
            }
            Probed::Answered => {
                self.answers = Some(true);
                None
            }
            Probed::Missed(error) => {
                self.answers = Some(true);
                self.refuses_bad_spend = Some(false);
                Some(error)
            }
            Probed::Unanswered(error) => {
                self.answers = Some(false);
                Some(error)
            }
        };
        let blind = match (self.answers, self.refuses_bad_spend) {
            (Some(false), _) | (_, Some(false)) => 1,
            (_, Some(true)) => 0,
            _ => -1,
        };
        if let Some(error) = error {
            if self
                .logged
                .as_ref()
                .is_none_or(|(last, at)| *last != error || at.elapsed() >= PROBE_INTERVAL)
            {
                error!("The withdrawal finalize check is blind on this node: {error}");
                self.logged = Some((error, Instant::now()));
            } else {
                debug!("The withdrawal finalize check is still blind on this node: {error}");
            }
        } else if blind == 1 {
            debug!(
                "testmempoolaccept answers, but the finalize check stays blind until a spend probe passes"
            );
        } else if self.blind == 1 {
            info!(
                blind,
                "testmempoolaccept answered the finalize check's probe after a failure"
            );
            self.logged = None;
        } else {
            debug!(blind, "The withdrawal finalize check's probe passed");
        }
        self.blind = blind;
        gauge.set(blind);
    }
}

impl crate::Hashi {
    pub(crate) fn start_finalize_bitcoin_check_probe(self: Arc<Self>) -> Service {
        Service::new().spawn_aborting(async move {
            let mut probes = Probes::default();
            loop {
                let probed = match self.probe_utxo().map(|utxo| self.probe_spend(&utxo)) {
                    Some(Ok(spend)) => self.probe_spend_answer(spend).await,
                    Some(Err(e)) => {
                        debug!("Cannot build the finalize check's probe spend yet: {e:#}");
                        tokio::time::sleep(PROBE_POLL).await;
                        continue;
                    }
                    None => self.probe_answers().await,
                };
                let refused = matches!(probed, Probed::Refused);
                let answered = matches!(probed, Probed::Answered);
                probes.record(&self.metrics.withdrawal_bitcoin_check_blind, probed);
                if refused {
                    tokio::time::sleep(PROBE_INTERVAL).await;
                } else if answered {
                    let deadline = Instant::now() + PROBE_INTERVAL;
                    while self.probe_utxo().is_none() && Instant::now() < deadline {
                        tokio::time::sleep(PROBE_POLL).await;
                    }
                } else {
                    tokio::time::sleep(PROBE_POLL).await;
                }
            }
        })
    }

    fn probe_utxo(&self) -> Option<Utxo> {
        let state = self.onchain_state().state();
        let bitcoin = state.hashi().bitcoin();
        let records = bitcoin.utxo_pool.utxo_records();
        confirmed_unlocked_utxo_ids(records, bitcoin.withdrawal_queue.withdrawal_txns())
            .iter()
            .filter_map(|id| records.get(id))
            .filter(|record| record.utxo.amount >= PROBE_MIN_SATS)
            .max_by_key(|record| record.utxo.amount)
            .map(|record| record.utxo.clone())
    }

    pub async fn probe_withdrawal_script_check(&self) -> anyhow::Result<()> {
        let utxo = self
            .probe_utxo()
            .ok_or_else(|| anyhow::anyhow!("the pool holds no free confirmed UTXO to probe"))?;
        match self.probe_spend_answer(self.probe_spend(&utxo)?).await {
            Probed::Refused => Ok(()),
            other => anyhow::bail!("{other:?}"),
        }
    }

    fn probe_spend(&self, utxo: &Utxo) -> anyhow::Result<bitcoin::Transaction> {
        let output = OutputUtxo {
            amount: PROBE_OUTPUT_SATS,
            bitcoin_address: hashi_types::bitcoin::witness_program_from_address(
                &self.get_deposit_address(None)?,
            )?,
        };
        let mut tx = self.build_unsigned_withdrawal_tx(std::slice::from_ref(utxo), &[output])?;
        tx.input[0].witness =
            self.withdrawal_input_witness(utxo.derivation_path.as_ref(), &[1; 64], &[2; 64])?;
        Ok(tx)
    }

    async fn probe_spend_answer(&self, spend: bitcoin::Transaction) -> Probed {
        match self.probe_test_mempool_accept(spend).await {
            Ok(results) => spend_probe_result(&results),
            Err(e) => Probed::Unanswered(format!("{e:#}")),
        }
    }

    async fn probe_answers(&self) -> Probed {
        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        match self
            .probe_test_mempool_accept(tx)
            .await
            .map(|results| classify(&results))
        {
            Ok(Verdict::Unavailable(error)) => Probed::Unanswered(error),
            Ok(_) => Probed::Answered,
            Err(e) => Probed::Unanswered(format!("{e:#}")),
        }
    }

    async fn probe_test_mempool_accept(
        &self,
        tx: bitcoin::Transaction,
    ) -> anyhow::Result<Vec<MempoolAcceptance>> {
        tokio::time::timeout(MEMBER_WAIT, self.btc_monitor().test_mempool_accept(tx))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "testmempoolaccept did not answer within {}s",
                    MEMBER_WAIT.as_secs()
                )
            })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering::SeqCst;

    fn checker() -> Arc<FinalizeBitcoinCheck> {
        Arc::new(FinalizeBitcoinCheck::new(Arc::new(Metrics::new(
            &prometheus::Registry::new(),
        ))))
    }

    fn tx(lock_time: u32) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(lock_time),
            input: Vec::new(),
            output: Vec::new(),
        }
    }

    fn acceptance(allowed: bool, reason: Option<&str>) -> MempoolAcceptance {
        let tx = tx(0);
        MempoolAcceptance {
            txid: tx.compute_txid(),
            wtxid: Some(tx.compute_wtxid()),
            allowed,
            vsize: None,
            fees: None,
            reject_reason: reason.map(str::to_owned),
            reject_details: reason.map(|_| "input 0 of the transaction".to_owned()),
        }
    }

    fn answering(
        calls: Arc<AtomicUsize>,
        delay: Duration,
        reason: &'static str,
    ) -> impl FnOnce(
        bitcoin::Transaction,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = anyhow::Result<Vec<MempoolAcceptance>>> + Send>,
    > + Send
    + 'static {
        move |_tx| {
            calls.fetch_add(1, SeqCst);
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(vec![acceptance(false, Some(reason))])
            })
        }
    }

    #[test]
    fn only_a_script_failure_refuses() {
        let id = Address::new([1; 32]);
        let txid = tx(0).compute_txid();
        let refusal = Verdict::ScriptFailure {
            reason: "mempool-script-verify-flag-failed (Invalid Schnorr signature)".into(),
            details: Some("input 0 of the transaction".into()),
        }
        .ensure_signable(id, txid)
        .unwrap_err()
        .to_string();
        assert!(refusal.contains("Invalid Schnorr signature"), "{refusal}");
        assert!(refusal.contains("input 0 of the transaction"), "{refusal}");
        for verdict in [
            Verdict::Accepted,
            Verdict::RejectedOther {
                reason: "missing-inputs".into(),
            },
            Verdict::Unavailable("testmempoolaccept did not answer within 10s".into()),
        ] {
            verdict.ensure_signable(id, txid).unwrap();
        }
    }

    #[test]
    fn only_a_passing_spend_probe_reads_healthy() {
        let gauge = IntGauge::new("blind", "blind").unwrap();
        let mut probes = Probes::default();
        let mut record = |probed| {
            probes.record(&gauge, probed);
            gauge.get()
        };
        assert_eq!(record(Probed::Answered), -1);
        assert_eq!(record(Probed::Refused), 0);
        assert_eq!(record(Probed::Missed("rejected_other".into())), 1);
        assert_eq!(record(Probed::Answered), 1);
        assert_eq!(record(Probed::Refused), 0);
        assert_eq!(record(Probed::Unanswered("timeout".into())), 1);
        assert_eq!(record(Probed::Answered), 0);
    }

    #[test]
    fn a_spend_probe_passes_only_on_a_failed_script_check() {
        assert!(matches!(
            spend_probe_result(&[acceptance(
                false,
                Some("mempool-script-verify-flag-failed (Invalid Schnorr signature)")
            )]),
            Probed::Refused
        ));
        for reason in [
            "bad-witness-nonstandard",
            "missing-inputs",
            "max-fee-exceeded",
        ] {
            assert!(
                matches!(
                    spend_probe_result(&[acceptance(false, Some(reason))]),
                    Probed::Missed(_)
                ),
                "{reason}"
            );
        }
        assert!(matches!(
            spend_probe_result(&[acceptance(true, None)]),
            Probed::Missed(_)
        ));
        assert!(matches!(spend_probe_result(&[]), Probed::Unanswered(_)));
    }

    #[test]
    fn classifies_every_core_wording_of_a_script_failure() {
        for reason in [
            "mandatory-script-verify-flag-failed (Invalid Schnorr signature)",
            "non-mandatory-script-verify-flag (Invalid Schnorr signature)",
            "mempool-script-verify-flag-failed (Invalid Schnorr signature)",
            "scriptsig-not-pushonly",
            "scriptsig-size",
            "bad-witness-nonstandard",
        ] {
            assert_eq!(
                classify(&[acceptance(false, Some(reason))]).label(),
                "script_failure",
                "{reason}"
            );
        }
        for reason in [
            "missing-inputs",
            "min relay fee not met",
            "mempool min fee not met",
        ] {
            assert_eq!(
                classify(&[acceptance(false, Some(reason))]).label(),
                "rejected_other",
                "{reason}"
            );
        }
        assert_eq!(classify(&[acceptance(true, None)]), Verdict::Accepted);
        assert_eq!(classify(&[]).label(), "unavailable");
        assert_eq!(
            classify(&[acceptance(true, None), acceptance(true, None)]).label(),
            "unavailable"
        );
    }

    #[tokio::test]
    async fn caches_script_failures_and_nothing_else() {
        let check = checker();
        let calls = Arc::new(AtomicUsize::new(0));
        let id = Address::new([1; 32]);
        for _ in 0..2 {
            let verdict = check
                .check(
                    id,
                    tx(1),
                    answering(
                        calls.clone(),
                        Duration::ZERO,
                        "mempool-script-verify-flag-failed (x)",
                    ),
                )
                .await;
            assert_eq!(verdict.label(), "script_failure");
        }
        assert_eq!(calls.load(SeqCst), 1);
        for _ in 0..2 {
            let verdict = check
                .check(
                    id,
                    tx(2),
                    answering(calls.clone(), Duration::ZERO, "missing-inputs"),
                )
                .await;
            assert_eq!(verdict.label(), "rejected_other");
        }
        assert_eq!(calls.load(SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn one_call_serves_every_waiter_and_outlives_their_bound() {
        let check = checker();
        let calls = Arc::new(AtomicUsize::new(0));
        let id = Address::new([1; 32]);
        let slow = Duration::from_secs(20);
        let reason = "mempool-script-verify-flag-failed (x)";
        let (first, second) = tokio::join!(
            check.check(id, tx(1), answering(calls.clone(), slow, reason)),
            check.check(id, tx(1), answering(calls.clone(), slow, reason)),
        );
        assert_eq!(first.label(), "unavailable");
        assert_eq!(second.label(), "unavailable");
        assert_eq!(calls.load(SeqCst), 1);

        tokio::time::sleep(slow).await;
        let failures = &check.metrics.withdrawal_bitcoin_check_script_failures_total;
        assert_eq!(failures.get(), 1);
        let third = check
            .check(id, tx(1), answering(calls.clone(), slow, reason))
            .await;
        assert_eq!(third.label(), "script_failure");
        assert_eq!(calls.load(SeqCst), 1);
        assert_eq!(failures.get(), 1);
    }
}
