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
        is_coinbase: bool,
        txout: bitcoin::TxOut,
    },
    InvalidVout {
        checkpoint: kyoto::HashCheckpoint,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ObservationToken {
    outpoint: bitcoin::OutPoint,
    discovery_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DepositDiscovery {
    Known(DepositStatus),
    Discover(ObservationToken),
    Pending,
    Untracked,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryResolution<E> {
    Complete(Result<DepositStatus, E>),
    Pending,
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
    discovery_id: Option<u64>,
}

struct TrackerState {
    metrics: Option<Arc<Metrics>>,
    entries: HashMap<bitcoin::OutPoint, Entry>,
    scan_candidates_by_txid: HashMap<bitcoin::Txid, HashSet<bitcoin::OutPoint>>,
    request_outpoints: HashMap<Address, bitcoin::OutPoint>,
    tip: Option<kyoto::HashCheckpoint>,
    bitcoin_generation: u64,
    next_discovery_id: u64,
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
                    .deposit_outpoint_confirmations
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
                tip: None,
                bitcoin_generation: 0,
                next_discovery_id: 0,
            })),
            work_tx,
        }
    }

    pub(crate) fn replace_requests<I>(&self, requests: I)
    where
        I: IntoIterator<Item = (Address, bitcoin::OutPoint)>,
    {
        let desired: HashMap<_, _> = requests.into_iter().collect();
        {
            let mut state = self.inner.lock().unwrap();
            if state.request_outpoints == desired {
                return;
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
                    state.adjust_metric(&DepositStatus::Unchecked, 1);
                    state.entries.insert(
                        outpoint,
                        Entry {
                            requests: request_ids,
                            status: DepositStatus::Unchecked,
                            discovery_id: None,
                        },
                    );
                }
            }
            state.request_outpoints = desired;
            state.rebuild_scan_candidate_index();
        }
        self.notify_work();
    }

    pub(crate) fn upsert_request(&self, request: Address, outpoint: bitcoin::OutPoint) {
        {
            let mut state = self.inner.lock().unwrap();
            if state.request_outpoints.get(&request) == Some(&outpoint) {
                return;
            }
            state.remove_request(&request);
            state.insert_request(request, outpoint);
        }
        self.notify_work();
    }

    pub(crate) fn remove_request(&self, request: &Address) {
        {
            let mut state = self.inner.lock().unwrap();
            if !state.remove_request(request) {
                return;
            }
        }
        self.notify_work();
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
        let mut state = self.inner.lock().unwrap();
        match state.entries.get(outpoint) {
            Some(entry)
                if matches!(entry.status, DepositStatus::Unchecked)
                    && entry.discovery_id.is_some() =>
            {
                DepositDiscovery::Pending
            }
            Some(entry) if matches!(entry.status, DepositStatus::Unchecked) => {
                let discovery_id = state.next_discovery_id;
                state.next_discovery_id = state
                    .next_discovery_id
                    .checked_add(1)
                    .expect("deposit discovery ID exhausted");
                state.entries.get_mut(outpoint).unwrap().discovery_id = Some(discovery_id);
                DepositDiscovery::Discover(ObservationToken {
                    outpoint: *outpoint,
                    discovery_id,
                })
            }
            Some(entry) => DepositDiscovery::Known(entry.status.clone()),
            None => DepositDiscovery::Untracked,
        }
    }

    pub(crate) fn resolve_discovery<E>(
        &self,
        token: ObservationToken,
        result: Result<DepositStatus, E>,
    ) -> DiscoveryResolution<E> {
        if let Ok(status) = &result {
            assert!(!matches!(status, DepositStatus::Unchecked));
        }
        let mut notify = false;
        let resolution = {
            let mut state = self.inner.lock().unwrap();
            let Some(entry) = state.entries.get(&token.outpoint) else {
                return DiscoveryResolution::Untracked;
            };
            if entry.discovery_id == Some(token.discovery_id) {
                match result {
                    Ok(status) => {
                        state.transition(token.outpoint, status.clone());
                        notify = true;
                        DiscoveryResolution::Complete(Ok(status))
                    }
                    Err(error) => {
                        state.entries.get_mut(&token.outpoint).unwrap().discovery_id = None;
                        DiscoveryResolution::Complete(Err(error))
                    }
                }
            } else if !matches!(entry.status, DepositStatus::Unchecked) {
                DiscoveryResolution::Complete(Ok(entry.status.clone()))
            } else if entry.discovery_id.is_some() {
                DiscoveryResolution::Pending
            } else {
                DiscoveryResolution::Complete(result)
            }
        };
        if notify {
            self.notify_work();
        }
        resolution
    }

    pub(crate) fn bitcoin_generation(&self) -> u64 {
        self.inner.lock().unwrap().bitcoin_generation
    }

    pub(crate) fn apply_block_if_current(
        &self,
        generation: u64,
        checkpoint: kyoto::HashCheckpoint,
        block: &bitcoin::Block,
    ) {
        // Hashing every transaction in the block is comparatively slow;
        // keep it off the lock the mirror and leader threads contend on.
        let txids: Vec<bitcoin::Txid> = block
            .txdata
            .iter()
            .map(|transaction| transaction.compute_txid())
            .collect();
        let changed = {
            let mut state = self.inner.lock().unwrap();
            if state.bitcoin_generation != generation {
                return;
            }
            state.apply_block(checkpoint, block, &txids)
        };
        if changed {
            self.notify_work();
        }
    }

    pub(crate) fn set_tip(&self, tip: kyoto::HashCheckpoint) {
        {
            let mut state = self.inner.lock().unwrap();
            if state.tip == Some(tip) {
                return;
            }
            let in_block: Vec<_> = state
                .entries
                .iter()
                .filter_map(|(outpoint, entry)| {
                    matches!(entry.status, DepositStatus::InBlock { .. }).then_some(*outpoint)
                })
                .collect();
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

    pub(crate) fn apply_reorg(&self, disconnected: &[kyoto::HashCheckpoint]) {
        {
            let mut state = self.inner.lock().unwrap();
            state.bump_bitcoin_generation();
            let candidates: Vec<_> = state
                .entries
                .iter()
                .filter_map(|(outpoint, entry)| {
                    matches!(
                        entry.status,
                        DepositStatus::InBlock { .. } | DepositStatus::InvalidVout { .. }
                    )
                    .then_some(*outpoint)
                })
                .collect();
            for outpoint in candidates {
                let checkpoint = match &state.entries.get(&outpoint).unwrap().status {
                    DepositStatus::InBlock { checkpoint, .. }
                    | DepositStatus::InvalidVout { checkpoint } => checkpoint,
                    _ => unreachable!(),
                };
                if disconnected.contains(checkpoint) {
                    state.reset_entry(outpoint);
                }
            }
        }
        self.notify_work();
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
        state
            .entries
            .values()
            .filter(|entry| match &entry.status {
                DepositStatus::Unchecked => true,
                DepositStatus::InBlock {
                    checkpoint,
                    is_coinbase,
                    ..
                } => tip_height.is_some_and(|tip_height| {
                    confirmations(checkpoint.height, tip_height)
                        >= effective_deposit_confirmation_threshold(threshold, *is_coinbase)
                }),
                DepositStatus::NotFound
                | DepositStatus::InMempool
                | DepositStatus::InvalidVout { .. } => false,
            })
            .flat_map(|entry| entry.requests.iter().copied())
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
        for entry in self.entries.values_mut() {
            entry.discovery_id = None;
        }
    }

    fn apply_block(
        &mut self,
        checkpoint: kyoto::HashCheckpoint,
        block: &bitcoin::Block,
        txids: &[bitcoin::Txid],
    ) -> bool {
        let mut changed = false;
        for (transaction, txid) in block.txdata.iter().zip(txids) {
            let Some(outpoints) = self.scan_candidates_by_txid.get(txid).cloned() else {
                continue;
            };
            let is_coinbase = transaction.is_coinbase();
            for outpoint in outpoints {
                let status = transaction.output.get(outpoint.vout as usize).map_or(
                    DepositStatus::InvalidVout { checkpoint },
                    |txout| DepositStatus::InBlock {
                        checkpoint,
                        is_coinbase,
                        txout: txout.clone(),
                    },
                );
                changed |= self.transition(outpoint, status);
            }
        }
        changed
    }

    fn insert_request(&mut self, request: Address, outpoint: bitcoin::OutPoint) {
        if let std::collections::hash_map::Entry::Vacant(entry) = self.entries.entry(outpoint) {
            entry.insert(Entry {
                requests: HashSet::new(),
                status: DepositStatus::Unchecked,
                discovery_id: None,
            });
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
            self.remove_entry(&outpoint);
        }
        true
    }

    fn remove_entry(&mut self, outpoint: &bitcoin::OutPoint) {
        let entry = self.entries.remove(outpoint).unwrap();
        self.adjust_metric(&entry.status, -1);
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
        if matches!(
            &status,
            DepositStatus::InBlock {
                is_coinbase: true,
                ..
            }
        ) && let Some(metrics) = &self.metrics
        {
            metrics
                .coinbase_deposit_observations_total
                .with_label_values(&[&outpoint.to_string()])
                .inc();
        }
        self.adjust_metric(&old_status, -1);
        self.adjust_metric(&status, 1);
        match (is_scan_candidate(&old_status), is_scan_candidate(&status)) {
            (true, false) => self.remove_scan_candidate(outpoint),
            (false, true) => self.insert_scan_candidate(outpoint),
            _ => {}
        }
        let entry = self.entries.get_mut(&outpoint).unwrap();
        entry.status = status;
        entry.discovery_id = None;
        true
    }

    fn reset_entry(&mut self, outpoint: bitcoin::OutPoint) {
        if matches!(self.entries[&outpoint].status, DepositStatus::Unchecked) {
            self.entries.get_mut(&outpoint).unwrap().discovery_id = None;
        } else {
            self.transition(outpoint, DepositStatus::Unchecked);
        }
    }

    fn adjust_metric(&mut self, status: &DepositStatus, delta: i64) {
        self.adjust_metric_bucket(status_bucket(status, self.tip.as_ref()), delta);
    }

    fn adjust_metric_bucket(&mut self, bucket: usize, delta: i64) {
        if let Some(metrics) = &self.metrics {
            let metric = metrics
                .deposit_outpoint_confirmations
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

pub(crate) fn effective_deposit_confirmation_threshold(configured: u32, is_coinbase: bool) -> u32 {
    if is_coinbase {
        configured.max(bitcoin::constants::COINBASE_MATURITY)
    } else {
        configured
    }
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
            .deposit_outpoint_confirmations
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
            tracker.resolve_discovery(token, Ok::<_, ()>(status.clone())),
            DiscoveryResolution::Complete(Ok(status))
        );
    }

    #[test]
    fn duplicate_membership_is_counted_once_and_does_not_notify_work() {
        let (tracker, metrics) = tracker();
        let mut work = tracker.subscribe_work();
        tracker.upsert_request(request(1), outpoint(1));
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();

        tracker.upsert_request(request(1), outpoint(1));
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
        tracker.remove_request(&request(2));
        assert_eq!(tracker.discovery(&first), DepositDiscovery::Untracked);
        tracker.remove_request(&request(1));
    }

    #[test]
    fn removed_entry_does_not_cache_a_discovery_result() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let token = start_discovery(&tracker, &tracked);

        tracker.remove_request(&request(1));

        assert_eq!(
            tracker.resolve_discovery(token, Ok::<_, ()>(DepositStatus::NotFound)),
            DiscoveryResolution::Untracked
        );
        assert_eq!(tracker.discovery(&tracked), DepositDiscovery::Untracked);
    }

    #[test]
    fn effective_deposit_confirmation_threshold_respects_coinbase_maturity() {
        assert_eq!(effective_deposit_confirmation_threshold(6, false), 6);
        assert_eq!(effective_deposit_confirmation_threshold(6, true), 100);
        assert_eq!(effective_deposit_confirmation_threshold(144, true), 144);
    }

    #[test]
    fn coinbase_request_becomes_actionable_at_maturity() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let token = start_discovery(&tracker, &tracked);
        record_discovery(
            &tracker,
            token,
            DepositStatus::InBlock {
                checkpoint: checkpoint(10, 1),
                is_coinbase: true,
                txout: txout(),
            },
        );

        tracker.set_tip(checkpoint(108, 2));
        assert!(tracker.actionable_requests(6).is_empty());

        tracker.set_tip(checkpoint(109, 3));
        assert_eq!(tracker.actionable_requests(6), HashSet::from([request(1)]));
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
                is_coinbase: false,
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
        let (tracker, metrics) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let block_outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(request(1), block_outpoint);
        let token = start_discovery(&tracker, &block_outpoint);
        record_discovery(&tracker, token, DepositStatus::NotFound);
        let mut work = tracker.subscribe_work();
        let block_checkpoint = kyoto::HashCheckpoint::new(0, block.block_hash());
        let outpoint_label = block_outpoint.to_string();
        let coinbase_observations = metrics
            .coinbase_deposit_observations_total
            .with_label_values(&[&outpoint_label]);

        tracker.apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block);
        assert!(work.has_changed().unwrap());
        work.borrow_and_update();
        assert_eq!(
            tracker.status(&block_outpoint),
            Some(DepositStatus::InBlock {
                checkpoint: block_checkpoint,
                is_coinbase: true,
                txout: block.txdata[0].output[0].clone(),
            })
        );
        assert_eq!(coinbase_observations.get(), 1);
        tracker.apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block);
        assert!(!work.has_changed().unwrap());
        assert_eq!(coinbase_observations.get(), 1);
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

        tracker.apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block);
        assert_eq!(
            tracker.status(&invalid_outpoint),
            Some(DepositStatus::InvalidVout {
                checkpoint: block_checkpoint,
            })
        );
        assert!(tracker.actionable_requests(1).is_empty());
    }

    #[test]
    fn discovery_is_single_flight_and_cannot_overwrite_a_block_result() {
        let (tracker, _) = tracker();
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
        let block_outpoint = bitcoin::OutPoint::new(block.txdata[0].compute_txid(), 0);
        tracker.upsert_request(request(1), block_outpoint);
        let first = start_discovery(&tracker, &block_outpoint);
        assert_eq!(
            tracker.discovery(&block_outpoint),
            DepositDiscovery::Pending
        );
        record_discovery(&tracker, first, DepositStatus::NotFound);

        tracker.reset_bitcoin_state();
        let late = start_discovery(&tracker, &block_outpoint);
        tracker.apply_block_if_current(
            tracker.bitcoin_generation(),
            kyoto::HashCheckpoint::new(0, block.block_hash()),
            &block,
        );
        assert!(matches!(
            tracker.resolve_discovery(late, Ok::<_, ()>(DepositStatus::NotFound)),
            DiscoveryResolution::Complete(Ok(DepositStatus::InBlock { .. }))
        ));
    }

    #[test]
    fn cancelled_discovery_can_be_retried_without_releasing_a_new_lease() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let cancelled = start_discovery(&tracker, &tracked);

        assert_eq!(
            tracker.resolve_discovery(cancelled, Err::<DepositStatus, _>(())),
            DiscoveryResolution::Complete(Err(()))
        );
        let current = start_discovery(&tracker, &tracked);
        assert_eq!(
            tracker.resolve_discovery(cancelled, Err::<DepositStatus, _>(())),
            DiscoveryResolution::Pending
        );

        assert_eq!(tracker.discovery(&tracked), DepositDiscovery::Pending);
        record_discovery(&tracker, current, DepositStatus::NotFound);
    }

    #[test]
    fn reorg_invalidates_discovery_for_an_unaffected_unchecked_entry() {
        let (tracker, _) = tracker();
        let tracked = outpoint(1);
        tracker.upsert_request(request(1), tracked);
        let stale = start_discovery(&tracker, &tracked);

        tracker.apply_reorg(&[checkpoint(10, 1)]);
        assert_eq!(tracker.status(&tracked), Some(DepositStatus::Unchecked));
        assert_eq!(
            tracker.resolve_discovery(stale, Ok::<_, ()>(DepositStatus::NotFound)),
            DiscoveryResolution::Complete(Ok(DepositStatus::NotFound))
        );
        assert_eq!(tracker.status(&tracked), Some(DepositStatus::Unchecked));
        assert!(matches!(
            tracker.discovery(&tracked),
            DepositDiscovery::Discover(_)
        ));
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

        tracker.apply_reorg(&[]);
        tracker.apply_block_if_current(stale, block_checkpoint, &block);
        assert_eq!(tracker.status(&tracked), Some(DepositStatus::NotFound));

        tracker.apply_block_if_current(tracker.bitcoin_generation(), block_checkpoint, &block);
        assert!(matches!(
            tracker.status(&tracked),
            Some(DepositStatus::InBlock { checkpoint, .. }) if checkpoint == block_checkpoint
        ));
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
                    is_coinbase: false,
                    txout: txout(),
                },
            );
        }

        tracker.apply_reorg(&[disconnected]);
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
                is_coinbase: false,
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
