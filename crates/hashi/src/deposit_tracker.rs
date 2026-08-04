// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use sui_sdk_types::Address;
use tokio::sync::watch;

use crate::metrics::CONFIRMATION_STATUS_LABELS;
use crate::metrics::Metrics;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DepositStatus {
    Unchecked,
    NotFound,
    InMempool,
    InBlock {
        checkpoint: kyoto::HashCheckpoint,
        txout: bitcoin::TxOut,
    },
    InvalidVout {
        checkpoint: kyoto::HashCheckpoint,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObservationToken {
    outpoint: bitcoin::OutPoint,
    bitcoin_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DepositDiscovery {
    Known(DepositStatus),
    Discover(ObservationToken),
    Untracked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryFinish {
    Recorded,
    Superseded(DepositStatus),
    Untracked,
}

#[derive(Clone)]
pub(crate) struct DepositTracker {
    inner: Arc<Mutex<TrackerState>>,
    work_tx: watch::Sender<()>,
}

struct Entry {
    requests: HashSet<Address>,
    status: DepositStatus,
}

#[derive(Default)]
struct StatusIndexes {
    unchecked: HashSet<bitcoin::OutPoint>,
    in_block: HashSet<bitcoin::OutPoint>,
    invalid_outpoint: HashSet<bitcoin::OutPoint>,
}

struct TrackerState {
    metrics: Option<Arc<Metrics>>,
    entries: HashMap<bitcoin::OutPoint, Entry>,
    scan_candidates_by_txid: HashMap<bitcoin::Txid, HashSet<bitcoin::OutPoint>>,
    request_outpoints: HashMap<Address, bitcoin::OutPoint>,
    indexes: StatusIndexes,
    tip: Option<kyoto::HashCheckpoint>,
    bitcoin_generation: u64,
}

impl DepositTracker {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Self {
        Self::new_inner(Some(metrics))
    }

    pub(crate) fn new_uninstrumented() -> Self {
        Self::new_inner(None)
    }

    fn new_inner(metrics: Option<Arc<Metrics>>) -> Self {
        if let Some(metrics) = &metrics {
            for label in CONFIRMATION_STATUS_LABELS {
                metrics
                    .deposit_request_confirmations
                    .with_label_values(&[label])
                    .set(0);
            }
        }
        let (work_tx, _) = watch::channel(());
        Self {
            inner: Arc::new(Mutex::new(TrackerState {
                metrics,
                entries: HashMap::new(),
                scan_candidates_by_txid: HashMap::new(),
                request_outpoints: HashMap::new(),
                indexes: StatusIndexes::default(),
                tip: None,
                bitcoin_generation: 0,
            })),
            work_tx,
        }
    }

    pub(crate) fn replace_requests<I>(&self, requests: I) -> bool
    where
        I: IntoIterator<Item = (Address, bitcoin::OutPoint)>,
    {
        let desired: HashMap<_, _> = requests.into_iter().collect();
        {
            let mut state = self.inner.lock().unwrap();
            if state.request_outpoints == desired {
                return false;
            }

            let mut desired_by_outpoint: HashMap<_, HashSet<_>> = HashMap::new();
            for (request, outpoint) in &desired {
                desired_by_outpoint
                    .entry(*outpoint)
                    .or_default()
                    .insert(*request);
            }

            let removed: Vec<_> = state
                .entries
                .keys()
                .filter(|outpoint| !desired_by_outpoint.contains_key(outpoint))
                .copied()
                .collect();
            for outpoint in removed {
                state.remove_entry(&outpoint);
            }

            for (outpoint, request_ids) in desired_by_outpoint {
                if state.entries.contains_key(&outpoint) {
                    state.entries.get_mut(&outpoint).unwrap().requests = request_ids;
                } else {
                    state.indexes.unchecked.insert(outpoint);
                    state.adjust_metric(&DepositStatus::Unchecked, 1);
                    state.entries.insert(
                        outpoint,
                        Entry {
                            requests: request_ids,
                            status: DepositStatus::Unchecked,
                        },
                    );
                }
            }
            state.request_outpoints = desired;
            state.rebuild_scan_candidate_index();
        }
        self.notify_work();
        true
    }

    pub(crate) fn upsert_request(&self, request: Address, outpoint: bitcoin::OutPoint) -> bool {
        {
            let mut state = self.inner.lock().unwrap();
            if state.request_outpoints.get(&request) == Some(&outpoint) {
                return false;
            }
            state.remove_request(&request);
            state.insert_request(request, outpoint);
        }
        self.notify_work();
        true
    }

    pub(crate) fn remove_request(&self, request: &Address) -> bool {
        {
            let mut state = self.inner.lock().unwrap();
            if !state.remove_request(request) {
                return false;
            }
        }
        self.notify_work();
        true
    }

    pub(crate) fn subscribe_work(&self) -> watch::Receiver<()> {
        self.work_tx.subscribe()
    }

    #[cfg(test)]
    fn status(&self, outpoint: &bitcoin::OutPoint) -> Option<DepositStatus> {
        self.inner
            .lock()
            .unwrap()
            .entries
            .get(outpoint)
            .map(|entry| entry.status.clone())
    }

    pub(crate) fn contains_request(&self, request: &Address) -> bool {
        self.inner
            .lock()
            .unwrap()
            .request_outpoints
            .contains_key(request)
    }

    pub(crate) fn discovery(&self, outpoint: &bitcoin::OutPoint) -> DepositDiscovery {
        let state = self.inner.lock().unwrap();
        match state.entries.get(outpoint) {
            Some(entry) if matches!(entry.status, DepositStatus::Unchecked) => {
                DepositDiscovery::Discover(ObservationToken {
                    outpoint: *outpoint,
                    bitcoin_generation: state.bitcoin_generation,
                })
            }
            Some(entry) => DepositDiscovery::Known(entry.status.clone()),
            None => DepositDiscovery::Untracked,
        }
    }

    pub(crate) fn finish_discovery(
        &self,
        token: ObservationToken,
        status: DepositStatus,
    ) -> DiscoveryFinish {
        assert!(!matches!(status, DepositStatus::Unchecked));
        let finish = {
            let mut state = self.inner.lock().unwrap();
            let Some(entry) = state.entries.get(&token.outpoint) else {
                return DiscoveryFinish::Untracked;
            };
            if state.bitcoin_generation == token.bitcoin_generation
                && matches!(entry.status, DepositStatus::Unchecked)
            {
                state.transition(token.outpoint, status);
                DiscoveryFinish::Recorded
            } else {
                DiscoveryFinish::Superseded(entry.status.clone())
            }
        };
        if matches!(finish, DiscoveryFinish::Recorded) {
            self.notify_work();
        }
        finish
    }

    pub(crate) fn bitcoin_generation(&self) -> u64 {
        self.inner.lock().unwrap().bitcoin_generation
    }

    pub(crate) fn apply_block_if_current(
        &self,
        generation: u64,
        checkpoint: kyoto::HashCheckpoint,
        block: &bitcoin::Block,
    ) -> Option<usize> {
        let promoted = {
            let mut state = self.inner.lock().unwrap();
            if state.bitcoin_generation != generation {
                return None;
            }
            state.apply_block(checkpoint, block)
        };
        if promoted > 0 {
            self.notify_work();
        }
        Some(promoted)
    }

    pub(crate) fn set_tip(&self, tip: kyoto::HashCheckpoint) {
        {
            let mut state = self.inner.lock().unwrap();
            if state.tip == Some(tip) {
                return;
            }
            let in_block: Vec<_> = state.indexes.in_block.iter().copied().collect();
            for outpoint in in_block {
                let entry = state.entries.get(&outpoint).unwrap();
                let DepositStatus::InBlock { checkpoint, .. } = &entry.status else {
                    unreachable!();
                };
                let old_bucket = status_bucket(&entry.status, state.tip.as_ref());
                let new_bucket = in_block_bucket(checkpoint.height, tip.height);
                if old_bucket != new_bucket {
                    state.adjust_metric_bucket(old_bucket, -1);
                    state.adjust_metric_bucket(new_bucket, 1);
                }
            }
            state.tip = Some(tip);
        }
        self.notify_work();
    }

    pub(crate) fn reset_bitcoin_state(&self) {
        {
            let mut state = self.inner.lock().unwrap();
            state.bump_bitcoin_generation();
            let outpoints: Vec<_> = state.entries.keys().copied().collect();
            for outpoint in outpoints {
                state.reset_entry(outpoint);
            }
            state.tip = None;
        }
        self.notify_work();
    }

    pub(crate) fn apply_reorg(&self, disconnected: &[kyoto::HashCheckpoint]) -> usize {
        let reset = {
            let mut state = self.inner.lock().unwrap();
            state.bump_bitcoin_generation();
            let candidates: Vec<_> = state
                .indexes
                .in_block
                .iter()
                .chain(&state.indexes.invalid_outpoint)
                .copied()
                .collect();
            let mut reset = 0;
            for outpoint in candidates {
                let checkpoint = match &state.entries.get(&outpoint).unwrap().status {
                    DepositStatus::InBlock { checkpoint, .. }
                    | DepositStatus::InvalidVout { checkpoint } => checkpoint,
                    _ => unreachable!(),
                };
                if disconnected.contains(checkpoint) {
                    state.reset_entry(outpoint);
                    reset += 1;
                }
            }
            reset
        };
        self.notify_work();
        reset
    }

    pub(crate) fn has_scan_candidates(&self) -> bool {
        !self
            .inner
            .lock()
            .unwrap()
            .scan_candidates_by_txid
            .is_empty()
    }

    pub(crate) fn actionable_requests(&self, threshold: u32) -> HashSet<Address> {
        let state = self.inner.lock().unwrap();
        let tip_height = state.tip.map(|tip| tip.height);
        let confirmed = state.indexes.in_block.iter().filter_map(|outpoint| {
            tip_height.and_then(|tip_height| {
                let DepositStatus::InBlock { checkpoint, .. } =
                    &state.entries.get(outpoint).unwrap().status
                else {
                    unreachable!();
                };
                (confirmations(checkpoint.height, tip_height) >= threshold).then_some(*outpoint)
            })
        });

        state
            .indexes
            .unchecked
            .iter()
            .copied()
            .chain(confirmed)
            .flat_map(|outpoint| state.entries[&outpoint].requests.iter().copied())
            .collect()
    }

    fn notify_work(&self) {
        self.work_tx.send_replace(());
    }
}

impl TrackerState {
    fn bump_bitcoin_generation(&mut self) {
        self.bitcoin_generation = self
            .bitcoin_generation
            .checked_add(1)
            .expect("Bitcoin state generation exhausted");
    }

    fn apply_block(&mut self, checkpoint: kyoto::HashCheckpoint, block: &bitcoin::Block) -> usize {
        let mut promoted = 0;
        for transaction in &block.txdata {
            let txid = transaction.compute_txid();
            let Some(outpoints) = self.scan_candidates_by_txid.get(&txid).cloned() else {
                continue;
            };
            for outpoint in outpoints {
                let status = transaction.output.get(outpoint.vout as usize).map_or(
                    DepositStatus::InvalidVout { checkpoint },
                    |txout| DepositStatus::InBlock {
                        checkpoint,
                        txout: txout.clone(),
                    },
                );
                if self.transition(outpoint, status) {
                    promoted += 1;
                }
            }
        }
        promoted
    }

    fn insert_request(&mut self, request: Address, outpoint: bitcoin::OutPoint) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.entries.entry(outpoint) {
            entry.insert(Entry {
                requests: HashSet::new(),
                status: DepositStatus::Unchecked,
            });
            self.indexes.unchecked.insert(outpoint);
            self.insert_scan_candidate(outpoint);
            self.adjust_metric(&DepositStatus::Unchecked, 1);
        }
        self.entries
            .get_mut(&outpoint)
            .unwrap()
            .requests
            .insert(request);
        self.request_outpoints.insert(request, outpoint);
    }

    fn remove_request(&mut self, request: &Address) -> bool {
        let Some(outpoint) = self.request_outpoints.remove(request) else {
            return false;
        };
        self.entries
            .get_mut(&outpoint)
            .unwrap()
            .requests
            .remove(request);
        if self.entries[&outpoint].requests.is_empty() {
            let status = self.entries[&outpoint].status.clone();
            self.adjust_metric(&status, -1);
            self.remove_status_index(&outpoint, &status);
            self.entries.remove(&outpoint);
            self.remove_scan_candidate(outpoint);
        }
        true
    }

    fn remove_entry(&mut self, outpoint: &bitcoin::OutPoint) {
        let entry = self.entries.remove(outpoint).unwrap();
        self.adjust_metric(&entry.status, -1);
        self.remove_status_index(outpoint, &entry.status);
        self.remove_scan_candidate(*outpoint);
    }

    fn rebuild_scan_candidate_index(&mut self) {
        self.scan_candidates_by_txid.clear();
        let outpoints: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(outpoint, entry)| is_scan_candidate(&entry.status).then_some(*outpoint))
            .collect();
        for outpoint in outpoints {
            self.insert_scan_candidate(outpoint);
        }
    }

    fn insert_scan_candidate(&mut self, outpoint: bitcoin::OutPoint) {
        self.scan_candidates_by_txid
            .entry(outpoint.txid)
            .or_default()
            .insert(outpoint);
    }

    fn remove_scan_candidate(&mut self, outpoint: bitcoin::OutPoint) {
        let Some(outpoints) = self.scan_candidates_by_txid.get_mut(&outpoint.txid) else {
            return;
        };
        outpoints.remove(&outpoint);
        if outpoints.is_empty() {
            self.scan_candidates_by_txid.remove(&outpoint.txid);
        }
    }

    fn transition(&mut self, outpoint: bitcoin::OutPoint, status: DepositStatus) -> bool {
        let old_status = self.entries[&outpoint].status.clone();
        if old_status == status {
            return false;
        }
        self.adjust_metric(&old_status, -1);
        self.adjust_metric(&status, 1);
        match (is_scan_candidate(&old_status), is_scan_candidate(&status)) {
            (true, false) => self.remove_scan_candidate(outpoint),
            (false, true) => self.insert_scan_candidate(outpoint),
            _ => {}
        }
        self.remove_status_index(&outpoint, &old_status);
        self.add_status_index(outpoint, &status);
        self.entries.get_mut(&outpoint).unwrap().status = status;
        true
    }

    fn reset_entry(&mut self, outpoint: bitcoin::OutPoint) {
        if !matches!(self.entries[&outpoint].status, DepositStatus::Unchecked) {
            self.transition(outpoint, DepositStatus::Unchecked);
        }
    }

    fn add_status_index(&mut self, outpoint: bitcoin::OutPoint, status: &DepositStatus) {
        match status {
            DepositStatus::Unchecked => &mut self.indexes.unchecked,
            DepositStatus::InBlock { .. } => &mut self.indexes.in_block,
            DepositStatus::InvalidVout { .. } => &mut self.indexes.invalid_outpoint,
            DepositStatus::NotFound | DepositStatus::InMempool => return,
        }
        .insert(outpoint);
    }

    fn remove_status_index(&mut self, outpoint: &bitcoin::OutPoint, status: &DepositStatus) {
        match status {
            DepositStatus::Unchecked => &mut self.indexes.unchecked,
            DepositStatus::InBlock { .. } => &mut self.indexes.in_block,
            DepositStatus::InvalidVout { .. } => &mut self.indexes.invalid_outpoint,
            DepositStatus::NotFound | DepositStatus::InMempool => return,
        }
        .remove(outpoint);
    }

    fn adjust_metric(&mut self, status: &DepositStatus, delta: i64) {
        self.adjust_metric_bucket(status_bucket(status, self.tip.as_ref()), delta);
    }

    fn adjust_metric_bucket(&mut self, bucket: usize, delta: i64) {
        if let Some(metrics) = &self.metrics {
            let metric = metrics
                .deposit_request_confirmations
                .with_label_values(&[CONFIRMATION_STATUS_LABELS[bucket]]);
            if delta > 0 {
                metric.add(delta);
            } else {
                metric.sub(-delta);
            }
        }
    }
}

fn status_bucket(status: &DepositStatus, tip: Option<&kyoto::HashCheckpoint>) -> usize {
    match status {
        DepositStatus::Unchecked => 0,
        DepositStatus::NotFound => 1,
        DepositStatus::InMempool => 2,
        DepositStatus::InvalidVout { .. } => 3,
        DepositStatus::InBlock { checkpoint, .. } => {
            in_block_bucket(checkpoint.height, tip.map_or(0, |tip| tip.height))
        }
    }
}

fn is_scan_candidate(status: &DepositStatus) -> bool {
    matches!(
        status,
        DepositStatus::Unchecked | DepositStatus::NotFound | DepositStatus::InMempool
    )
}

fn in_block_bucket(block_height: u32, tip_height: u32) -> usize {
    4 + confirmations(block_height, tip_height).min(6) as usize
}

fn confirmations(block_height: u32, tip_height: u32) -> u32 {
    tip_height.saturating_add(1).saturating_sub(block_height)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    fn tracker() -> (DepositTracker, Arc<Metrics>) {
        let metrics = Arc::new(Metrics::new(&prometheus::Registry::new()));
        (DepositTracker::new(metrics.clone()), metrics)
    }

    fn outpoint(seed: u8) -> bitcoin::OutPoint {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(bytes), 0)
    }

    fn request(seed: u8) -> Address {
        Address::new([seed; 32])
    }

    fn checkpoint(height: u32, seed: u8) -> kyoto::HashCheckpoint {
        let mut bytes = [0; 32];
        bytes[0] = seed;
        kyoto::HashCheckpoint::new(height, bitcoin::BlockHash::from_byte_array(bytes))
    }

    fn metric(metrics: &Metrics, label: &str) -> i64 {
        metrics
            .deposit_request_confirmations
            .with_label_values(&[label])
            .get()
    }

    fn txout() -> bitcoin::TxOut {
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }
    }

    fn start_discovery(tracker: &DepositTracker, outpoint: &bitcoin::OutPoint) -> ObservationToken {
        let DepositDiscovery::Discover(token) = tracker.discovery(outpoint) else {
            panic!("expected discovery token");
        };
        token
    }

    fn record_discovery(tracker: &DepositTracker, token: ObservationToken, status: DepositStatus) {
        assert_eq!(
            tracker.finish_discovery(token, status),
            DiscoveryFinish::Recorded
        );
    }

    #[test]
    fn duplicate_membership_is_counted_once_and_does_not_notify_work() {
        let (tracker, metrics) = tracker();
        let mut work = tracker.subscribe_work();
        assert!(tracker.upsert_request(request(1), outpoint(1)));
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();

        assert!(!tracker.upsert_request(request(1), outpoint(1)));
        assert!(!work.has_changed().unwrap());
        assert_eq!(metric(&metrics, "unchecked"), 1);
    }

    #[test]
    fn bitcoin_state_changes_notify_work() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let mut work = tracker.subscribe_work();

        let token = start_discovery(&tracker, &tracked);
        record_discovery(&tracker, token, DepositStatus::NotFound);
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();

        let tip = checkpoint(10, 1);
        tracker.set_tip(tip);
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();
        tracker.set_tip(tip);
        assert!(!work.has_changed().unwrap());

        tracker.reset_bitcoin_state();
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();
        tracker.apply_reorg(&[]);
        assert!(work.has_changed().unwrap());
    }

    #[test]
    fn exact_replacement_preserves_status_and_cleans_membership() {
        let (tracker, _) = tracker();
        let first = outpoint(1);
        tracker.upsert_request(request(1), first);
        let token = start_discovery(&tracker, &first);
        record_discovery(&tracker, token, DepositStatus::NotFound);

        tracker.replace_requests([(request(2), first), (request(3), outpoint(2))]);

        assert_eq!(
            tracker.discovery(&first),
            DepositDiscovery::Known(DepositStatus::NotFound)
        );
        assert!(tracker.remove_request(&request(2)));
        assert_eq!(tracker.discovery(&first), DepositDiscovery::Untracked);
        assert!(!tracker.remove_request(&request(1)));
    }

    #[test]
    fn finishing_discovery_reports_when_the_entry_was_removed() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let token = start_discovery(&tracker, &tracked);

        tracker.remove_request(&request(1));

        assert_eq!(
            tracker.finish_discovery(token, DepositStatus::NotFound),
            DiscoveryFinish::Untracked
        );
    }

    #[test]
    fn passive_and_underconfirmed_requests_are_not_actionable() {
        let (tracker, _) = tracker();
        for seed in 1..=4 {
            tracker.upsert_request(request(seed), outpoint(seed));
        }
        let statuses = [
            DepositStatus::NotFound,
            DepositStatus::InMempool,
            DepositStatus::InBlock {
                checkpoint: checkpoint(10, 1),
                txout: txout(),
            },
        ];
        for (seed, status) in (1..=3).zip(statuses) {
            let token = start_discovery(&tracker, &outpoint(seed));
            record_discovery(&tracker, token, status);
        }
        tracker.set_tip(checkpoint(10, 2));

        assert_eq!(tracker.actionable_requests(2), HashSet::from([request(4)]));
    }

    #[test]
    fn block_scan_promotes_passive_statuses_without_overwriting_terminal_statuses() {
        let (tracker, _) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let block_outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(request(1), block_outpoint);
        let token = start_discovery(&tracker, &block_outpoint);
        record_discovery(&tracker, token, DepositStatus::NotFound);
        let mut work = tracker.subscribe_work();
        let block_checkpoint = kyoto::HashCheckpoint::new(0, block.block_hash());

        assert_eq!(
            tracker
                .apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block)
                .unwrap(),
            1
        );
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();
        assert_eq!(
            tracker.status(&block_outpoint),
            Some(DepositStatus::InBlock {
                checkpoint: block_checkpoint,
                txout: block.txdata[0].output[0].clone(),
            })
        );
        assert_eq!(
            tracker
                .apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block)
                .unwrap(),
            0
        );
        assert!(!work.has_changed().unwrap());
    }

    #[test]
    fn block_scan_marks_a_known_transaction_with_an_invalid_outpoint() {
        let (tracker, _) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let invalid_outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 100);
        tracker.upsert_request(request(1), invalid_outpoint);
        let token = start_discovery(&tracker, &invalid_outpoint);
        record_discovery(&tracker, token, DepositStatus::NotFound);
        let block_checkpoint = kyoto::HashCheckpoint::new(0, block.block_hash());

        assert_eq!(
            tracker
                .apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block)
                .unwrap(),
            1
        );
        assert_eq!(
            tracker.status(&invalid_outpoint),
            Some(DepositStatus::InvalidVout {
                checkpoint: block_checkpoint,
            })
        );
        assert!(tracker.actionable_requests(1).is_empty());
    }

    #[test]
    fn concurrent_discovery_uses_the_first_result_and_cannot_overwrite_a_block_result() {
        let (tracker, _) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let block_outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(request(1), block_outpoint);
        let first = start_discovery(&tracker, &block_outpoint);
        let concurrent = start_discovery(&tracker, &block_outpoint);
        record_discovery(&tracker, first, DepositStatus::NotFound);
        assert_eq!(
            tracker.finish_discovery(concurrent, DepositStatus::InMempool),
            DiscoveryFinish::Superseded(DepositStatus::NotFound)
        );

        tracker.reset_bitcoin_state();
        let late = start_discovery(&tracker, &block_outpoint);
        tracker
            .apply_block_if_current(
                tracker.bitcoin_generation(),
                kyoto::HashCheckpoint::new(0, block.block_hash()),
                &block,
            )
            .unwrap();
        assert!(matches!(
            tracker.finish_discovery(late, DepositStatus::NotFound),
            DiscoveryFinish::Superseded(DepositStatus::InBlock { .. })
        ));
    }

    #[test]
    fn reorg_invalidates_discovery_for_an_unaffected_unchecked_entry() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let stale = start_discovery(&tracker, &tracked);

        assert_eq!(tracker.apply_reorg(&[checkpoint(10, 1)]), 0);
        assert_eq!(tracker.status(&tracked), Some(DepositStatus::Unchecked));
        assert_eq!(
            tracker.finish_discovery(stale, DepositStatus::NotFound),
            DiscoveryFinish::Superseded(DepositStatus::Unchecked)
        );
    }

    #[test]
    fn stale_bitcoin_generation_cannot_apply_a_block() {
        let (tracker, _) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let tracked = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(request(1), tracked);
        let token = start_discovery(&tracker, &tracked);
        record_discovery(&tracker, token, DepositStatus::NotFound);
        let stale = tracker.bitcoin_generation();
        let block_checkpoint = kyoto::HashCheckpoint::new(0, block.block_hash());

        assert_eq!(tracker.apply_reorg(&[]), 0);
        assert_eq!(
            tracker.apply_block_if_current(stale, block_checkpoint, &block),
            None
        );
        assert_eq!(tracker.status(&tracked), Some(DepositStatus::NotFound));

        assert_eq!(
            tracker.apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block,),
            Some(1)
        );
    }

    #[test]
    fn reorg_only_resets_entries_from_disconnected_blocks() {
        let (tracker, _) = tracker();
        let disconnected = checkpoint(10, 1);
        let retained = checkpoint(9, 2);
        for (seed, block) in [(1, disconnected), (2, retained)] {
            tracker.upsert_request(request(seed), outpoint(seed));
            let token = start_discovery(&tracker, &outpoint(seed));
            record_discovery(
                &tracker,
                token,
                DepositStatus::InBlock {
                    checkpoint: block,
                    txout: txout(),
                },
            );
        }

        assert_eq!(tracker.apply_reorg(&[disconnected]), 1);
        assert_eq!(tracker.status(&outpoint(1)), Some(DepositStatus::Unchecked));
        assert!(matches!(
            tracker.status(&outpoint(2)),
            Some(DepositStatus::InBlock { checkpoint, .. }) if checkpoint == retained
        ));
    }

    #[test]
    fn metrics_count_outpoints_and_rebucket_in_block_requests() {
        let (tracker, metrics) = tracker();
        let shared = outpoint(1);
        tracker.replace_requests([(request(1), shared), (request(2), shared)]);
        assert_eq!(metric(&metrics, "unchecked"), 1);
        let token = start_discovery(&tracker, &shared);
        record_discovery(
            &tracker,
            token,
            DepositStatus::InBlock {
                checkpoint: checkpoint(10, 1),
                txout: txout(),
            },
        );
        tracker.set_tip(checkpoint(10, 2));
        assert_eq!(metric(&metrics, "unchecked"), 0);
        assert_eq!(metric(&metrics, "1"), 1);

        tracker.set_tip(checkpoint(15, 3));
        assert_eq!(metric(&metrics, "1"), 0);
        assert_eq!(metric(&metrics, "6_plus"), 1);
    }
}
