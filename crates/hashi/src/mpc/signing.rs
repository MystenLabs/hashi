// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
use fastcrypto::groups::secp256k1::POINT_SIZE_IN_BYTES;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::Address as DerivationAddress;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::presigning::Presignatures;
use fastcrypto_tbls::threshold_schnorr::reed_solomon::RSDecoder;
use fastcrypto_tbls::threshold_schnorr::signing::aggregate_signatures;
use fastcrypto_tbls::threshold_schnorr::signing::finalize_schnorr_signature;
use fastcrypto_tbls::threshold_schnorr::signing::generate_partial_signatures;
use fastcrypto_tbls::types::ShareIndex;
use futures::stream::FuturesUnordered;
use futures::stream::StreamExt;
use hashi_types::committee::Committee;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::communication::ChannelError;
use crate::communication::P2PChannel;
use crate::communication::with_timeout_and_retry_budget;
use crate::metrics::MPC_LABEL_SIGNING;
use crate::metrics::Metrics;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::PartialSigningOutput;
use crate::mpc::types::SigningError;
use crate::mpc::types::SigningResult;
use crate::mpc::types::signing_nonce_bytes;
use crate::mpc::types::signing_request_digest;

const PARTIAL_SIGS_COLLECTION_POLL_BACKOFF: Duration = Duration::from_millis(100);
const PARTIAL_SIGS_COLLECTION_MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Per-attempt timeout for one `get_partial_signatures` poll. Deliberately
/// small: the collection loop in [`SigningManager::sign`] is itself the retry
/// mechanism, so a slow peer costs at most one bounded probe per round instead
/// of the default 10 x 30 s transport-retry budget.
const PARTIAL_SIGS_CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Transport retries within one round's poll of a single peer (on top of the
/// first attempt). Kept minimal for the same reason as the call timeout.
const PARTIAL_SIGS_CALL_RETRIES: usize = 1;

/// How long a peer whose poll failed is skipped before being probed again.
const PARTIAL_SIGS_PEER_COOLDOWN: Duration = Duration::from_secs(10);

/// A single contiguous batch of presignatures.
struct PresigBatch {
    /// Each presig is wrapped in `Option` so it can be taken exactly once,
    /// preventing nonce reuse even if the same index is assigned twice.
    pool: Vec<Option<(Vec<S>, G)>>,
    /// Global index of the first presig in this batch.
    start_index: u64,
    /// Monotonically increasing batch sequence number.
    batch_index: u32,
}

impl PresigBatch {
    fn end_index(&self) -> u64 {
        self.start_index + self.pool.len() as u64
    }

    fn contains(&self, global_index: u64) -> bool {
        global_index >= self.start_index && global_index < self.end_index()
    }

    fn is_fully_consumed(&self) -> bool {
        self.pool.iter().all(|s| s.is_none())
    }

    fn remaining(&self) -> usize {
        self.pool.iter().filter(|s| s.is_some()).count()
    }
}

struct SigningEpochConfig {
    address: Address,
    committee: Committee,
    threshold: u16,
    key_shares: avss::SharesForNode,
    verifying_key: G,
    share_owners: HashMap<ShareIndex, Address>,
    owned_counts: HashMap<Address, usize>,
    refill_divisor: usize,
}

impl SigningEpochConfig {
    fn over_owned_count(&self, peer: &Address, sigs: &[Eval<S>]) -> Option<(usize, usize)> {
        let owned = self.owned_counts.get(peer).copied().unwrap_or(0);
        (sigs.len() > owned).then_some((sigs.len(), owned))
    }

    fn retain_owned(&self, peer: &Address, sigs: Vec<Eval<S>>) -> (Vec<Eval<S>>, u64) {
        let mut seen = HashSet::with_capacity(sigs.len());
        let mut dropped = 0u64;
        let kept = sigs
            .into_iter()
            .filter(|e| {
                let ok = self.share_owners.get(&e.index) == Some(peer) && seen.insert(e.index);
                dropped += u64::from(!ok);
                ok
            })
            .collect();
        (kept, dropped)
    }
}

fn owned_counts_by_member(share_owners: &HashMap<ShareIndex, Address>) -> HashMap<Address, usize> {
    share_owners
        .values()
        .fold(HashMap::new(), |mut counts, owner| {
            *counts.entry(*owner).or_default() += 1;
            counts
        })
}

enum CacheOrPresig {
    Cached(G, Vec<Eval<S>>),
    Presig((Vec<S>, G)),
}

struct SigningPoolState {
    /// Active presig batches, ordered by `start_index`. Older batches are
    /// retained until all their presigs have been consumed so that
    /// out-of-order signing (e.g., withdrawal A allocated from batch 0 signs
    /// after withdrawal B advanced to batch 1) still works.
    batches: Vec<PresigBatch>,
    partial_signing_outputs: HashMap<Address, PartialSigningOutput>,
    next_batch: Option<PrefetchedBatch>,
}

/// A refill result staged for installation, tagged with the batch index it
/// was generated for. The tag lets the install path refuse a stale or
/// duplicated generation result: relabeling one under a later batch's index
/// range would make this node evaluate different nonces than its peers at
/// the same global presig indices (breaking aggregation), and reusing
/// already-consumed nonces for new messages leaks this node's key shares.
struct PrefetchedBatch {
    batch_index: u32,
    pool: Vec<Option<(Vec<S>, G)>>,
    identity: PresigBatchIdentity,
}

pub struct SigningManager {
    config: Arc<SigningEpochConfig>,
    state: RwLock<SigningPoolState>,
    refill_tx: Arc<watch::Sender<u32>>,
    peer_cooldowns: PeerCooldowns,
}

/// Peers whose `get_partial_signatures` poll recently failed and when each may be probed again.
struct PeerCooldowns {
    until: Mutex<HashMap<Address, Instant>>,
}

impl PeerCooldowns {
    fn new() -> Self {
        Self {
            until: Mutex::new(HashMap::new()),
        }
    }

    fn is_cooling(&self, peer: &Address, now: Instant) -> bool {
        self.until
            .lock()
            .unwrap()
            .get(peer)
            .is_some_and(|&until| until > now)
    }

    fn record_failure(&self, peer: Address) {
        self.until
            .lock()
            .unwrap()
            .insert(peer, Instant::now() + PARTIAL_SIGS_PEER_COOLDOWN);
    }

    fn record_success(&self, peer: &Address) {
        self.until.lock().unwrap().remove(peer);
    }

    /// The earliest moment any of `peers` comes off cooldown, if one is
    /// cooling.
    fn earliest_expiry<'a>(&self, peers: impl IntoIterator<Item = &'a Address>) -> Option<Instant> {
        let until = self.until.lock().unwrap();
        peers
            .into_iter()
            .filter_map(|peer| until.get(peer).copied())
            .min()
    }
}

#[derive(Debug, Clone)]
pub struct PresigBatchIdentity {
    pub epoch: u64,
    pub batch_index: u32,
    pub fingerprint: [u8; 32],
    pub size: u32,
    pub batch_size_per_weight: u16,
}

impl PresigBatchIdentity {
    pub fn short(&self) -> String {
        hex::encode(&self.fingerprint[..8])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IdentityInputs {
    pub epoch: u64,
    pub batch_size_per_weight: u16,
}

#[cfg(test)]
impl PresigBatchIdentity {
    fn for_test() -> Self {
        Self {
            epoch: 0,
            batch_index: 0,
            fingerprint: [0u8; 32],
            size: 0,
            batch_size_per_weight: 1,
        }
    }
}

#[cfg(test)]
impl IdentityInputs {
    fn for_test() -> Self {
        Self {
            epoch: 0,
            batch_size_per_weight: 1,
        }
    }
}

impl IdentityInputs {
    fn identity_for<'a>(
        &self,
        batch_index: u32,
        nonces: impl ExactSizeIterator<Item = &'a G>,
    ) -> PresigBatchIdentity {
        let size = nonces.len() as u32;
        PresigBatchIdentity {
            epoch: self.epoch,
            batch_index,
            fingerprint: presig_batch_fingerprint(self.epoch, nonces),
            size,
            batch_size_per_weight: self.batch_size_per_weight,
        }
    }
}

fn presig_batch_fingerprint<'a>(
    epoch: u64,
    nonces: impl ExactSizeIterator<Item = &'a G>,
) -> [u8; 32] {
    use fastcrypto::hash::HashFunction;
    let mut hasher = fastcrypto::hash::Blake2b256::default();
    hasher.update(b"hashi/presig-batch-identity/v1");
    hasher.update(epoch.to_le_bytes());
    hasher.update((nonces.len() as u32).to_le_bytes());
    for nonce in nonces {
        hasher.update(bcs::to_bytes(nonce).expect("serialization should always succeed"));
    }
    hasher.finalize().digest
}

impl SigningManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        share_owners: HashMap<ShareIndex, Address>,
        presignatures: Presignatures,
        batch_index: u32,
        batch_start_index: u64,
        refill_divisor: usize,
        refill_tx: Arc<watch::Sender<u32>>,
        identity_inputs: IdentityInputs,
    ) -> (Self, PresigBatchIdentity) {
        let generated: Vec<(Vec<S>, G)> = presignatures.collect();
        let identity = identity_inputs.identity_for(batch_index, generated.iter().map(|(_, n)| n));
        let pool: Vec<Option<(Vec<S>, G)>> = generated.into_iter().map(Some).collect();
        tracing::info!(
            "Presig batch installed: address={address}, epoch={}, batch_index={batch_index}, \
             start_index={batch_start_index}, size={}, fingerprint={}",
            identity.epoch,
            pool.len(),
            identity.short(),
        );
        let batch = PresigBatch {
            pool,
            start_index: batch_start_index,
            batch_index,
        };
        let manager = Self {
            config: Arc::new(SigningEpochConfig {
                address,
                committee,
                threshold,
                key_shares,
                verifying_key,
                owned_counts: owned_counts_by_member(&share_owners),
                share_owners,
                refill_divisor,
            }),
            state: RwLock::new(SigningPoolState {
                batches: vec![batch],
                partial_signing_outputs: HashMap::new(),
                next_batch: None,
            }),
            refill_tx,
            peer_cooldowns: PeerCooldowns::new(),
        };
        (manager, identity)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_recovered(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        share_owners: HashMap<ShareIndex, Address>,
        retained: Vec<(Presignatures, u32, u64)>,
        num_consumed: u64,
        pending: &HashSet<u64>,
        refill_divisor: usize,
        refill_tx: Arc<watch::Sender<u32>>,
        identity_inputs: IdentityInputs,
    ) -> anyhow::Result<(Self, Vec<(u32, PresigBatchIdentity)>)> {
        let mut batches = Vec::with_capacity(retained.len());
        let mut identities = Vec::with_capacity(retained.len());
        let mut covered_pending = 0usize;
        for (presignatures, batch_index, start_index) in retained {
            let generated: Vec<(Vec<S>, G)> = presignatures.collect();
            let identity =
                identity_inputs.identity_for(batch_index, generated.iter().map(|(_, n)| n));
            let pool: Vec<Option<(Vec<S>, G)>> = generated
                .into_iter()
                .enumerate()
                .map(|(i, presig)| {
                    let global = start_index + i as u64;
                    let is_pending = pending.contains(&global);
                    if global >= num_consumed || is_pending {
                        if is_pending {
                            covered_pending += 1;
                        }
                        Some(presig)
                    } else {
                        None
                    }
                })
                .collect();
            tracing::info!(
                "Recovered presig batch installed: address={address}, epoch={}, \
                 batch_index={batch_index}, start_index={start_index}, size={}, \
                 enabled={}, fingerprint={}",
                identity.epoch,
                pool.len(),
                pool.iter().filter(|s| s.is_some()).count(),
                identity.short(),
            );
            identities.push((batch_index, identity));
            batches.push(PresigBatch {
                pool,
                start_index,
                batch_index,
            });
        }
        anyhow::ensure!(
            covered_pending == pending.len(),
            "recovered signing manager covers {covered_pending} of {} pending presig indices",
            pending.len(),
        );
        Ok((
            Self {
                config: Arc::new(SigningEpochConfig {
                    address,
                    committee,
                    threshold,
                    key_shares,
                    verifying_key,
                    owned_counts: owned_counts_by_member(&share_owners),
                    share_owners,
                    refill_divisor,
                }),
                state: RwLock::new(SigningPoolState {
                    batches,
                    partial_signing_outputs: HashMap::new(),
                    next_batch: None,
                }),
                refill_tx,
                peer_cooldowns: PeerCooldowns::new(),
            },
            identities,
        ))
    }

    pub fn set_next_batch(
        &self,
        batch_index: u32,
        presignatures: Presignatures,
        identity_inputs: IdentityInputs,
    ) -> Option<PresigBatchIdentity> {
        let generated: Vec<(Vec<S>, G)> = presignatures.collect();
        let identity = identity_inputs.identity_for(batch_index, generated.iter().map(|(_, n)| n));
        let fingerprint = identity.short();
        let pool: Vec<Option<(Vec<S>, G)>> = generated.into_iter().map(Some).collect();
        let mut state = self.state.write().unwrap();
        if let Some(latest) = state.batches.last()
            && batch_index <= latest.batch_index
        {
            tracing::error!(
                "Discarding stale presig refill result: batch_index={batch_index} is not \
                 newer than the latest installed batch {} (size={}, fingerprint={fingerprint})",
                latest.batch_index,
                pool.len(),
            );
            return None;
        }
        if let Some(existing) = &state.next_batch {
            tracing::warn!(
                "Replacing prefetched presig batch {} with batch {batch_index}",
                existing.batch_index,
            );
        }
        tracing::info!(
            "Presig batch prefetched: address={}, epoch={}, batch_index={batch_index}, \
             size={}, fingerprint={fingerprint}",
            self.config.address,
            identity.epoch,
            pool.len(),
        );
        state.next_batch = Some(PrefetchedBatch {
            batch_index,
            pool,
            identity: identity.clone(),
        });
        Some(identity)
    }

    pub fn has_next_batch(&self) -> bool {
        self.state.read().unwrap().next_batch.is_some()
    }

    /// The batch index of the currently staged refill result, if any.
    pub fn prefetched_batch_index(&self) -> Option<u32> {
        self.state
            .read()
            .unwrap()
            .next_batch
            .as_ref()
            .map(|next| next.batch_index)
    }

    /// Size of the latest (most recent) batch.
    pub fn initial_presig_count(&self) -> usize {
        self.state
            .read()
            .unwrap()
            .batches
            .last()
            .map_or(0, |b| b.pool.len())
    }

    /// Remaining presignatures in the latest batch (used for refill checks).
    pub fn presignatures_remaining(&self) -> usize {
        self.state
            .read()
            .unwrap()
            .batches
            .last()
            .map_or(0, |b| b.remaining())
    }

    /// The batch index of the latest (most recent) batch.
    pub fn batch_index(&self) -> u32 {
        self.state
            .read()
            .unwrap()
            .batches
            .last()
            .map_or(0, |b| b.batch_index)
    }

    pub fn available_presig_end_index(&self) -> u64 {
        let state = self.state.read().unwrap();
        let batch_end = state.batches.last().map_or(0, |b| b.end_index());
        let next_index = state.batches.last().map_or(0, |b| b.batch_index) + 1;
        match &state.next_batch {
            // Only a prefetch that will install as the immediately-next
            // batch extends the contiguous index range; counting a
            // future-tagged one would report capacity across a coverage
            // gap and suppress the proactive refill.
            Some(next) if next.batch_index == next_index => batch_end + next.pool.len() as u64,
            _ => batch_end,
        }
    }

    pub fn trigger_refill(&self) {
        let next = self.batch_index() + 1;
        let _ = self.refill_tx.send(next);
    }

    pub fn epoch(&self) -> u64 {
        self.config.committee.epoch()
    }

    pub fn threshold(&self) -> u16 {
        self.config.threshold
    }

    pub fn key_shares(&self) -> &avss::SharesForNode {
        &self.config.key_shares
    }

    pub fn verifying_key(&self) -> G {
        self.config.verifying_key
    }

    /// The most share indices any single member owns this epoch.
    pub fn max_owned_count(&self) -> usize {
        self.config
            .owned_counts
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }

    pub fn handle_get_partial_signatures_request(
        &self,
        request: &GetPartialSignaturesRequest,
    ) -> SigningResult<GetPartialSignaturesResponse> {
        let state = self.state.read().unwrap();
        let mut partial_sigs = BTreeMap::new();
        let mut signing_nonces = BTreeMap::new();
        for id in &request.signing_ids {
            if let Some(output) = state.partial_signing_outputs.get(id) {
                partial_sigs.insert(*id, output.partial_sigs.clone());
                signing_nonces.insert(*id, output.signing_nonce_bytes().to_vec());
            }
        }
        Ok(GetPartialSignaturesResponse {
            partial_sigs,
            signing_nonces,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(level = "info", skip_all, fields(num_inputs = inputs.len()))]
    pub async fn sign(
        &self,
        p2p_channel: &impl P2PChannel,
        inputs: Vec<SignInput>,
        beacon_value: &S,
        timeout: Duration,
        metrics: &Metrics,
        result_tx: tokio::sync::mpsc::UnboundedSender<(Address, SigningResult<SchnorrSignature>)>,
    ) {
        let threshold = self.config.threshold;
        let verifying_key = self.config.verifying_key;
        let self_address = self.config.address;
        let all_peers: HashSet<Address> = self
            .config
            .committee
            .members()
            .iter()
            .map(|m| m.validator_address())
            .filter(|addr| *addr != self_address)
            .collect();
        let deadline = Instant::now() + timeout;
        let mut pending: Vec<InputSigningState> = Vec::with_capacity(inputs.len());
        let mut request_changed: Vec<Address> = Vec::new();
        for input in inputs {
            match self
                .prepare_local_partial_signatures(
                    input.signing_id,
                    &input.message,
                    input.global_presig_index,
                    beacon_value,
                    input.derivation_address.as_ref(),
                    metrics,
                )
                .await
            {
                Ok((public_nonce, partials)) => pending.push(InputSigningState::new(
                    input.signing_id,
                    input.message,
                    public_nonce,
                    beacon_value,
                    input.derivation_address,
                    partials,
                    threshold as usize,
                    all_peers.clone(),
                )),
                Err(e) => {
                    if matches!(e, SigningError::RequestChanged { .. }) {
                        request_changed.push(input.signing_id);
                    }
                    let _ = result_tx.send((input.signing_id, Err(e)));
                }
            }
        }
        if !request_changed.is_empty() {
            tracing::error!(
                "Refused {} input(s) whose cached partials were computed under a \
                 different message, derivation address or beacon: {:?}",
                request_changed.len(),
                &request_changed[..request_changed.len().min(8)],
            );
        }
        let _collection_timer = metrics
            .mpc_sign_collection_duration_seconds
            .with_label_values(&[MPC_LABEL_SIGNING])
            .start_timer();
        let mut flagged: HashSet<ShareIndex> = HashSet::new();
        let mut backoff = PARTIAL_SIGS_COLLECTION_POLL_BACKOFF;
        while !pending.is_empty() {
            self.finalize_sweep(
                &mut pending,
                &mut flagged,
                threshold,
                &verifying_key,
                metrics,
                &result_tx,
            )
            .await;
            if pending.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                for st in pending.drain(..) {
                    let _ = result_tx.send((
                        st.signing_id,
                        Err(SigningError::Timeout {
                            collected: st.partials.len(),
                            threshold,
                        }),
                    ));
                }
                break;
            }
            let progressed = self
                .collect_partial_sigs_from_peers(
                    p2p_channel,
                    &mut pending,
                    deadline,
                    &flagged,
                    metrics,
                )
                .await;
            if progressed {
                backoff = PARTIAL_SIGS_COLLECTION_POLL_BACKOFF;
            } else {
                // Clamp to the remaining time so a backed-off round never
                // overshoots the deadline before the next deadline check.
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(backoff.min(remaining)).await;
                backoff = backoff
                    .saturating_mul(2)
                    .min(PARTIAL_SIGS_COLLECTION_MAX_BACKOFF);
            }
        }
        drop(_collection_timer);
    }

    async fn finalize_sweep(
        &self,
        pending: &mut Vec<InputSigningState>,
        flagged: &mut HashSet<ShareIndex>,
        threshold: u16,
        verifying_key: &G,
        metrics: &Metrics,
        result_tx: &tokio::sync::mpsc::UnboundedSender<(Address, SigningResult<SchnorrSignature>)>,
    ) {
        loop {
            let mut grew = false;
            let mut exhausted: Vec<Address> = Vec::new();
            let mut i = 0;
            while i < pending.len() {
                let peers_exhausted = pending[i].peers_remaining.is_empty();
                let outcome = try_finalize_signature(
                    &mut pending[i],
                    threshold,
                    verifying_key,
                    peers_exhausted,
                    flagged,
                    metrics,
                )
                .await;
                match outcome {
                    FinalizeOutcome::NeedMore => i += 1,
                    FinalizeOutcome::Exhausted => {
                        exhausted.push(pending[i].signing_id);
                        i += 1;
                    }
                    FinalizeOutcome::Done(sig, mismatched) => {
                        let st = pending.swap_remove(i);
                        let _ = result_tx.send((st.signing_id, Ok(sig)));
                        grew |= self.flag_mismatched(&mismatched, flagged, metrics);
                    }
                    FinalizeOutcome::Failed(e) => {
                        let st = pending.swap_remove(i);
                        let _ = result_tx.send((st.signing_id, Err(e)));
                    }
                }
            }
            if grew {
                continue;
            }
            pending.retain(|st| {
                if !exhausted.contains(&st.signing_id) {
                    return true;
                }
                let _ = result_tx.send((
                    st.signing_id,
                    Err(SigningError::TooManyInvalidSignatures {
                        collected: st.partials.len(),
                        threshold,
                    }),
                ));
                false
            });
            return;
        }
    }

    fn flag_mismatched(
        &self,
        mismatched: &[ShareIndex],
        flagged: &mut HashSet<ShareIndex>,
        metrics: &Metrics,
    ) -> bool {
        if mismatched.is_empty() {
            return false;
        }
        let share_owners = &self.config.share_owners;
        let mut per_owner: HashMap<Address, u64> = HashMap::new();
        for idx in mismatched {
            if let Some(owner) = share_owners.get(idx) {
                *per_owner.entry(*owner).or_default() += 1;
            }
        }
        for (owner, count) in &per_owner {
            metrics
                .mpc_partial_sig_mismatch_total
                .with_label_values(&[&owner.to_string()])
                .inc_by(*count);
        }
        let local: Vec<ShareIndex> = mismatched
            .iter()
            .copied()
            .filter(|idx| share_owners.get(idx) == Some(&self.config.address))
            .collect();
        if !local.is_empty() {
            tracing::warn!(
                "Locally generated partial signatures at share indices {local:?} disagree with \
                 the RS-recovered polynomial: local presig/key state may be corrupt, or the \
                 decode was steered by other contributions"
            );
        }
        let owners: HashSet<Address> = per_owner.into_keys().collect();
        let before = flagged.len();
        flagged.extend(
            share_owners
                .iter()
                .filter(|(_, owner)| owners.contains(*owner))
                .map(|(idx, _)| *idx),
        );
        let grew = flagged.len() > before;
        if grew {
            tracing::debug!(
                "Flagged {} share index(es) after RS recovery; the other pending inputs are \
                 also tried without their owners' partials for the rest of this call",
                flagged.len() - before,
            );
        }
        grew
    }

    #[tracing::instrument(
        level = "info",
        skip_all,
        fields(signing_id = %signing_id, global_presig_index),
    )]
    async fn prepare_local_partial_signatures(
        &self,
        signing_id: Address,
        message: &[u8],
        global_presig_index: u64,
        beacon_value: &S,
        derivation_address: Option<&DerivationAddress>,
        metrics: &Metrics,
    ) -> SigningResult<(G, Vec<Eval<S>>)> {
        let config = &self.config;
        // Splitting the lock is safe because a given `signing_id` is never signed concurrently
        // on a node (distinct id per withdrawal input, retries sequential), and the presig is already
        // removed from the pool under the first lock section.
        let taken = {
            let mut state = self.state.write().unwrap();
            if let Some(existing) = state.partial_signing_outputs.get(&signing_id) {
                let digest = signing_request_digest(message, derivation_address);
                let nonce = signing_nonce_bytes(&existing.public_nonce(), beacon_value);
                if existing.request_digest() != &digest || existing.signing_nonce_bytes() != &nonce
                {
                    return Err(SigningError::RequestChanged { signing_id });
                }
                tracing::info!(
                    "Cache hit for {signing_id} (global_presig_index={global_presig_index}), \
                     reusing cached partial sigs (batch_index={})",
                    state.batches.last().map_or(0, |b| b.batch_index),
                );
                CacheOrPresig::Cached(existing.public_nonce(), existing.partial_sigs.clone())
            } else {
                // Find the batch containing this presig index, advancing
                // into the next batch if needed.
                let batch = if let Some(b) = state
                    .batches
                    .iter()
                    .position(|b| b.contains(global_presig_index))
                {
                    &mut state.batches[b]
                } else {
                    if let Some(latest) = state.batches.last() {
                        let next_start = latest.end_index();
                        let next_batch_index = latest.batch_index + 1;
                        match &state.next_batch {
                            Some(next) if next.batch_index == next_batch_index => {
                                let next = state.next_batch.take().expect("checked above");
                                tracing::info!(
                                    "Presig batch installed: address={}, epoch={}, \
                                     batch_index={next_batch_index}, start_index={next_start}, \
                                     size={}, fingerprint={}",
                                    config.address,
                                    next.identity.epoch,
                                    next.pool.len(),
                                    next.identity.short(),
                                );
                                state.batches.push(PresigBatch {
                                    pool: next.pool,
                                    start_index: next_start,
                                    batch_index: next_batch_index,
                                });
                            }
                            Some(next) => {
                                tracing::error!(
                                    "Prefetched presig batch {} does not match the expected \
                                     next batch {next_batch_index}; refusing to install it",
                                    next.batch_index,
                                );
                                if next.batch_index < next_batch_index {
                                    state.next_batch = None;
                                } else {
                                    let _ = self.refill_tx.send(next_batch_index);
                                }
                            }
                            None => {}
                        }
                    }
                    // Check if the index is now covered.
                    if let Some(b) = state
                        .batches
                        .iter()
                        .position(|b| b.contains(global_presig_index))
                    {
                        &mut state.batches[b]
                    } else {
                        if state.next_batch.is_none() {
                            let next = state.batches.last().map_or(0, |b| b.batch_index) + 1;
                            let _ = self.refill_tx.send(next);
                        }
                        tracing::error!(
                            "Presig index {global_presig_index} not found in any \
                             batch ({} batch(es) active).",
                            state.batches.len(),
                        );
                        return Err(SigningError::PoolExhausted);
                    }
                };
                let target_position = (global_presig_index - batch.start_index) as usize;
                let presig = batch
                    .pool
                    .get_mut(target_position)
                    .and_then(|slot| slot.take())
                    .ok_or_else(|| {
                        tracing::error!(
                            "Presig at position {target_position} unavailable for \
                             batch {} (already consumed or out of range).",
                            batch.batch_index,
                        );
                        SigningError::PoolExhausted
                    })?;
                let used_batch_index = batch.batch_index;
                tracing::info!(
                    "Cache miss for {signing_id}, using presig \
                     (address={}, global_presig_index={global_presig_index}, \
                     batch_index={used_batch_index}, \
                     position={target_position})",
                    config.address,
                );
                // Trigger refill based on the latest batch's consumption.
                if let Some(latest) = state.batches.last() {
                    let remaining = latest.remaining();
                    let refill_at = latest.pool.len() / config.refill_divisor;
                    if remaining <= refill_at {
                        let _ = self.refill_tx.send(latest.batch_index + 1);
                    }
                }
                // Prune fully-consumed batches, but always keep the last
                // one so its `end_index()` can anchor the next batch's
                // start.
                while state.batches.len() > 1 && state.batches[0].is_fully_consumed() {
                    state.batches.remove(0);
                }
                CacheOrPresig::Presig(presig)
            }
        }; // state write lock released
        let (public_nonce, partial_sigs) = match taken {
            CacheOrPresig::Cached(nonce, sigs) => (nonce, sigs),
            CacheOrPresig::Presig(presig) => {
                let _timer = metrics
                    .mpc_sign_partial_gen_duration_seconds
                    .with_label_values(&[MPC_LABEL_SIGNING])
                    .start_timer();
                let result = generate_partial_signatures(
                    message,
                    presig,
                    beacon_value,
                    &config.key_shares,
                    &config.verifying_key,
                    derivation_address,
                )
                .map_err(|e| SigningError::CryptoError(e.to_string()))?;
                drop(_timer);
                self.state.write().unwrap().partial_signing_outputs.insert(
                    signing_id,
                    PartialSigningOutput::new(
                        result.0,
                        beacon_value,
                        message,
                        derivation_address,
                        result.1.clone(),
                    ),
                );
                result
            }
        };
        Ok((public_nonce, partial_sigs))
    }
}

pub struct SignInput {
    pub signing_id: Address,
    pub message: Vec<u8>,
    pub global_presig_index: u64,
    pub derivation_address: Option<DerivationAddress>,
}

struct InputSigningState {
    signing_id: Address,
    message: Vec<u8>,
    public_nonce: G,
    derivation_address: Option<DerivationAddress>,
    signing_nonce_bytes: [u8; POINT_SIZE_IN_BYTES],
    beacon: S,
    partials: Vec<Eval<S>>,
    /// Floor on the partial count before a poll round may early-exit for
    /// this input; the real predicate is [`Self::can_attempt`]. Tests raise
    /// it to force full rounds.
    early_exit_floor: usize,
    /// Peers not yet merged for this input
    peers_remaining: HashSet<Address>,
    clean_attempted: bool,
    unflagged_prefix_attempted: Option<Vec<ShareIndex>>,
    erased_attempted: Option<Vec<ShareIndex>>,
    /// Partial counts the next full and erased recovery attempts wait for.
    required_full: usize,
    required_erased: usize,
}

impl InputSigningState {
    #[allow(clippy::too_many_arguments)]
    fn new(
        signing_id: Address,
        message: Vec<u8>,
        public_nonce: G,
        beacon: &S,
        derivation_address: Option<DerivationAddress>,
        partials: Vec<Eval<S>>,
        early_exit_floor: usize,
        peers_remaining: HashSet<Address>,
    ) -> Self {
        Self {
            signing_id,
            message,
            public_nonce,
            derivation_address,
            signing_nonce_bytes: signing_nonce_bytes(&public_nonce, beacon),
            beacon: *beacon,
            early_exit_floor,
            partials,
            peers_remaining,
            clean_attempted: false,
            unflagged_prefix_attempted: None,
            erased_attempted: None,
            required_full: 0,
            required_erased: 0,
        }
    }

    fn unflagged(&self, flagged: &HashSet<ShareIndex>) -> Vec<Eval<S>> {
        self.partials
            .iter()
            .filter(|e| !flagged.contains(&e.index))
            .cloned()
            .collect()
    }

    fn unflagged_prefix_key(
        &self,
        t: usize,
        unflagged: &[Eval<S>],
        flagged: &HashSet<ShareIndex>,
    ) -> Option<Vec<ShareIndex>> {
        if self.partials.len() < t
            || unflagged.len() < t
            || !self.partials[..t]
                .iter()
                .any(|e| flagged.contains(&e.index))
        {
            return None;
        }
        let key: Vec<ShareIndex> = unflagged[..t].iter().map(|e| e.index).collect();
        (self.unflagged_prefix_attempted.as_ref() != Some(&key)).then_some(key)
    }

    fn recovery_attemptable(&self, t: usize) -> bool {
        self.partials.len() >= (t + 2).max(self.required_full)
    }

    fn erased_key(&self, t: usize, unflagged: &[Eval<S>]) -> Option<Vec<ShareIndex>> {
        if unflagged.len() >= self.partials.len() {
            return None;
        }
        let key: Vec<ShareIndex> = unflagged.iter().map(|e| e.index).collect();
        let prev = self.erased_attempted.as_ref();
        let gate = match prev {
            Some(prev) if prev.iter().any(|idx| !key.contains(idx)) => 0,
            _ => self.required_erased,
        };
        (unflagged.len() >= (t + 2).max(gate) && prev != Some(&key)).then_some(key)
    }

    fn can_attempt(&self, t: usize, flagged: &HashSet<ShareIndex>) -> bool {
        let n = self.partials.len();
        if n < self.early_exit_floor || n < t {
            return false;
        }
        if !self.clean_attempted {
            return true;
        }
        let unflagged = self.unflagged(flagged);
        self.unflagged_prefix_key(t, &unflagged, flagged).is_some()
            || self.recovery_attemptable(t)
            || self.erased_key(t, &unflagged).is_some()
    }
}

enum FinalizeOutcome {
    /// Aggregation succeeded. The second field lists the share indices whose
    /// contributed values disagree with the recovered polynomial.
    Done(SchnorrSignature, Vec<ShareIndex>),
    NeedMore,
    /// No peer can still contribute and no attemptable candidate succeeded.
    Exhausted,
    Failed(SigningError),
}

fn next_rs_attempt_at(threshold: usize, n: usize) -> usize {
    threshold + 2 * (n.saturating_sub(threshold) / 2 + 1)
}

struct AggregationContext {
    message: Vec<u8>,
    nonce: G,
    beacon: S,
    vk: G,
    deriv: Option<DerivationAddress>,
    threshold: u16,
}

impl AggregationContext {
    async fn aggregate(
        &self,
        sigs: Vec<Eval<S>>,
        metrics: &Metrics,
    ) -> Result<SchnorrSignature, FastCryptoError> {
        let _timer = metrics
            .mpc_sign_aggregation_duration_seconds
            .with_label_values(&[MPC_LABEL_SIGNING])
            .start_timer();
        let (message, nonce, beacon, vk, deriv, threshold) = (
            self.message.clone(),
            self.nonce,
            self.beacon,
            self.vk,
            self.deriv,
            self.threshold,
        );
        super::spawn_blocking(move || {
            aggregate_signatures(
                &message,
                &nonce,
                &beacon,
                &sigs,
                threshold,
                &vk,
                deriv.as_ref(),
            )
        })
        .await
    }

    async fn recover(
        &self,
        sigs: Vec<Eval<S>>,
        metrics: &Metrics,
    ) -> Result<(SchnorrSignature, Vec<ShareIndex>), FastCryptoError> {
        let _timer = metrics
            .mpc_sign_aggregation_duration_seconds
            .with_label_values(&[MPC_LABEL_SIGNING])
            .start_timer();
        let (message, nonce, beacon, vk, deriv, threshold) = (
            self.message.clone(),
            self.nonce,
            self.beacon,
            self.vk,
            self.deriv,
            self.threshold,
        );
        super::spawn_blocking(move || {
            aggregate_signatures_with_recovery(
                &message,
                &nonce,
                &beacon,
                &sigs,
                threshold,
                &vk,
                deriv.as_ref(),
            )
        })
        .await
    }
}

async fn try_finalize_signature(
    st: &mut InputSigningState,
    threshold: u16,
    verifying_key: &G,
    peers_exhausted: bool,
    flagged: &HashSet<ShareIndex>,
    metrics: &Metrics,
) -> FinalizeOutcome {
    let t = threshold as usize;
    let n = st.partials.len();
    let need_more_or_fail = || {
        if peers_exhausted {
            FinalizeOutcome::Exhausted
        } else {
            FinalizeOutcome::NeedMore
        }
    };
    if n < t {
        return need_more_or_fail();
    }
    let ctx = AggregationContext {
        message: st.message.clone(),
        nonce: st.public_nonce,
        beacon: st.beacon,
        vk: *verifying_key,
        deriv: st.derivation_address,
        threshold,
    };
    let crypto_error =
        |e: FastCryptoError| FinalizeOutcome::Failed(SigningError::CryptoError(e.to_string()));
    if !st.clean_attempted {
        st.clean_attempted = true;
        match ctx.aggregate(st.partials[..t].to_vec(), metrics).await {
            Ok(sig) => return FinalizeOutcome::Done(sig, Vec::new()),
            Err(FastCryptoError::InvalidSignature) => {}
            Err(e) => return crypto_error(e),
        }
    }
    let unflagged = st.unflagged(flagged);
    if let Some(key) = st.unflagged_prefix_key(t, &unflagged, flagged) {
        st.unflagged_prefix_attempted = Some(key);
        match ctx.aggregate(unflagged[..t].to_vec(), metrics).await {
            Ok(sig) => return FinalizeOutcome::Done(sig, Vec::new()),
            Err(FastCryptoError::InvalidSignature) => {}
            Err(e) => return crypto_error(e),
        }
    }
    if st.recovery_attemptable(t) {
        match ctx.recover(st.partials.clone(), metrics).await {
            Ok((sig, mismatched)) => return FinalizeOutcome::Done(sig, mismatched),
            Err(FastCryptoError::TooManyErrors(_) | FastCryptoError::InvalidSignature) => {}
            Err(e) => return crypto_error(e),
        }
        st.required_full = next_rs_attempt_at(t, n);
    }
    if let Some(key) = st.erased_key(t, &unflagged) {
        let n_unflagged = unflagged.len();
        st.erased_attempted = Some(key);
        match ctx.recover(unflagged, metrics).await {
            Ok((sig, mismatched)) => return FinalizeOutcome::Done(sig, mismatched),
            Err(FastCryptoError::TooManyErrors(_) | FastCryptoError::InvalidSignature) => {}
            Err(e) => return crypto_error(e),
        }
        st.required_erased = next_rs_attempt_at(t, n_unflagged);
    }
    need_more_or_fail()
}

impl SigningManager {
    /// Runs one poll round against the peers that still owe partial
    /// signatures.
    ///
    /// The round is bounded twice over: each peer poll gets a small
    /// timeout-and-retry budget (the outer loop in [`SigningManager::sign`]
    /// is the real retry mechanism), and the round as a whole stops at
    /// `deadline` rather than draining slow peers' probes — otherwise one
    /// black-holed peer makes the deadline check in `sign` unreachable for
    /// its duration. Peers in cooldown are skipped for the round entirely.
    ///
    /// Returns whether any new partials were merged.
    async fn collect_partial_sigs_from_peers(
        &self,
        p2p_channel: &impl P2PChannel,
        pending: &mut [InputSigningState],
        deadline: Instant,
        flagged: &HashSet<ShareIndex>,
        metrics: &Metrics,
    ) -> bool {
        let t = self.config.threshold as usize;
        let now = Instant::now();
        let mut peer_ids: HashMap<Address, Vec<Address>> = HashMap::new();
        for st in pending.iter_mut() {
            for peer in &st.peers_remaining {
                if !self.peer_cooldowns.is_cooling(peer, now) {
                    peer_ids.entry(*peer).or_default().push(st.signing_id);
                }
            }
        }
        if peer_ids.is_empty() {
            // Every remaining peer is cooling from a failed poll (explicit
            // not-ready answers are never cooled). Storming a struggling
            // fleet with more polls helps nobody: sleep until the first
            // cooldown lapses (clamped to the deadline) and let the next
            // round retry at cooldown cadence.
            let remaining = pending.iter().flat_map(|st| st.peers_remaining.iter());
            if let Some(expiry) = self.peer_cooldowns.earliest_expiry(remaining) {
                let _ = tokio::time::timeout_at(deadline, tokio::time::sleep_until(expiry)).await;
            }
            return false;
        }
        let mut in_flight: FuturesUnordered<_> = peer_ids
            .into_iter()
            .map(|(peer, signing_ids)| {
                let request = GetPartialSignaturesRequest { signing_ids };
                async move {
                    let result = with_timeout_and_retry_budget(
                        || p2p_channel.get_partial_signatures(&peer, &request),
                        PARTIAL_SIGS_CALL_TIMEOUT,
                        PARTIAL_SIGS_CALL_RETRIES,
                    )
                    .await;
                    (peer, result)
                }
            })
            .collect();
        let index: HashMap<Address, usize> = pending
            .iter()
            .enumerate()
            .map(|(i, st)| (st.signing_id, i))
            .collect();
        let mut progressed = false;
        loop {
            let (peer, result) = match tokio::time::timeout_at(deadline, in_flight.next()).await {
                Ok(Some(item)) => item,
                Ok(None) => break,
                Err(_) => {
                    tracing::debug!(
                        "Partial-signature poll round hit the signing deadline with {} peer(s) \
                         still in flight",
                        in_flight.len(),
                    );
                    break;
                }
            };
            match result {
                Ok(response) => {
                    self.peer_cooldowns.record_success(&peer);
                    let mut nonce_mismatches = 0u64;
                    let mut unusable_reports = 0u64;
                    let mut rejected_lists = 0u64;
                    let mut dropped_evals = 0u64;
                    let mut violation_sample: Vec<String> = Vec::new();
                    let peer_reports_nonces = !response.signing_nonces.is_empty();
                    for (signing_id, sigs) in response.partial_sigs {
                        let asked = index
                            .get(&signing_id)
                            .filter(|&&i| pending[i].peers_remaining.remove(&peer));
                        let Some(&i) = asked else {
                            rejected_lists += 1;
                            if violation_sample.len() < 8 {
                                violation_sample
                                    .push(format!("{signing_id} not outstanding for this peer"));
                            }
                            continue;
                        };
                        {
                            let st = &mut pending[i];
                            let reported = match response.signing_nonces.get(&signing_id) {
                                Some(n) if n.len() == POINT_SIZE_IN_BYTES => Some(n),
                                Some(_) => {
                                    unusable_reports += 1;
                                    continue;
                                }
                                None if peer_reports_nonces => {
                                    unusable_reports += 1;
                                    continue;
                                }
                                None => None,
                            };
                            if let Some(nonce) = reported
                                && nonce[..] != st.signing_nonce_bytes[..]
                            {
                                nonce_mismatches += 1;
                                continue;
                            }
                            if let Some((len, owned)) = self.config.over_owned_count(&peer, &sigs) {
                                rejected_lists += 1;
                                if violation_sample.len() < 8 {
                                    violation_sample.push(format!("{len} evals, owns {owned}"));
                                }
                                continue;
                            }
                            let (sigs, dropped) = self.config.retain_owned(&peer, sigs);
                            dropped_evals += dropped;
                            for eval in sigs {
                                st.partials.push(eval);
                                progressed = true;
                            }
                        }
                    }
                    if unusable_reports > 0 {
                        tracing::warn!(
                            "Dropped partials from {peer} for {unusable_reports} input(s): it \
                             reports signing nonces but the entry was missing or wrong-length, \
                             which no correct peer produces"
                        );
                    }
                    if nonce_mismatches > 0 {
                        metrics
                            .mpc_partial_sig_nonce_mismatch_total
                            .with_label_values(&[&peer.to_string()])
                            .inc_by(nonce_mismatches);
                        tracing::warn!(
                            "Signing-nonce disagreement with {peer} on {nonce_mismatches} \
                             input(s); dropped its partials. Does not establish which side \
                             diverged"
                        );
                    }
                    if rejected_lists > 0 {
                        self.peer_cooldowns.record_failure(peer);
                        let labels = [&peer.to_string()];
                        metrics
                            .mpc_partial_sig_lists_rejected_total
                            .with_label_values(&labels)
                            .inc_by(rejected_lists);
                        metrics
                            .mpc_partial_sig_poll_failures_total
                            .with_label_values(&labels)
                            .inc();
                        tracing::warn!(
                            "Rejected {rejected_lists} partial-signature list(s) from {peer} \
                             (cooling down for {PARTIAL_SIGS_PEER_COOLDOWN:?}): {}",
                            violation_sample.join("; "),
                        );
                    }
                    if dropped_evals > 0 {
                        metrics
                            .mpc_partial_sig_evals_dropped_total
                            .with_label_values(&[&peer.to_string()])
                            .inc_by(dropped_evals);
                        tracing::warn!(
                            "Dropped {dropped_evals} partial signature(s) from {peer}: share \
                             index not owned, or repeated within its list"
                        );
                    }
                    if pending
                        .iter()
                        .all(|st| st.peers_remaining.is_empty() || st.can_attempt(t, flagged))
                    {
                        break;
                    }
                }
                Err(ChannelError::NotReady(e)) => {
                    // The peer said explicitly that it is up but not ready to
                    // serve yet (e.g. still reconciling its signing manager
                    // after an epoch flip) — common across much of the fleet
                    // right after reconfig. Keep polling it instead of
                    // cooling it down.
                    tracing::debug!(
                        "Peer {peer} not ready for get_partial_signatures; will re-poll: {e}"
                    );
                }
                Err(e) => {
                    self.peer_cooldowns.record_failure(peer);
                    metrics
                        .mpc_partial_sig_poll_failures_total
                        .with_label_values(&[&peer.to_string()])
                        .inc();
                    // Warn, not info: an under-sized response limit would
                    // also surface here, and there it fires for every honest
                    // peer at once.
                    tracing::warn!(
                        "Batched get_partial_signatures from {peer} failed \
                         (cooling down for {PARTIAL_SIGS_PEER_COOLDOWN:?}): {e}"
                    );
                }
            }
        }
        progressed
    }
}

fn aggregate_signatures_with_recovery(
    message: &[u8],
    public_presig: &G,
    beacon_value: &S,
    partial_signatures: &[Eval<S>],
    threshold: u16,
    verifying_key: &G,
    derivation_address: Option<&DerivationAddress>,
) -> Result<(SchnorrSignature, Vec<ShareIndex>), FastCryptoError> {
    let indices: Vec<_> = partial_signatures.iter().map(|e| e.index).collect();
    let values: Vec<_> = partial_signatures.iter().map(|e| e.value).collect();
    let poly = RSDecoder::new(indices, threshold as usize).compute_message_polynomial(&values)?;
    let sig = finalize_schnorr_signature(
        message,
        public_presig,
        beacon_value,
        poly.c0(),
        verifying_key,
        derivation_address,
    )?;
    let mismatched = partial_signatures
        .iter()
        .filter(|e| poly.eval(e.index).value != e.value)
        .map(|e| e.index)
        .collect();
    Ok((sig, mismatched))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::ChannelResult;
    use crate::mpc::types::ComplainRequest;
    use crate::mpc::types::ComplaintResponse;
    use crate::mpc::types::GetPublicMpcOutputRequest;
    use crate::mpc::types::GetPublicMpcOutputResponse;
    use crate::mpc::types::RetrieveMessagesRequest;
    use crate::mpc::types::RetrieveMessagesResponse;
    use crate::mpc::types::SendMessagesRequest;
    use crate::mpc::types::SendMessagesResponse;
    use fastcrypto::groups::GroupElement;
    use fastcrypto::groups::Scalar;
    use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use fastcrypto::traits::AllowedRng;
    use fastcrypto_tbls::polynomial::Poly;
    use fastcrypto_tbls::threshold_schnorr::Parameters;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use fastcrypto_tbls::types::ShareIndex;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_metrics() -> Metrics {
        Metrics::new(&prometheus::Registry::new())
    }

    fn mock_shares(rng: &mut impl AllowedRng, secret: S, t: u16, n: u16) -> Vec<Eval<S>> {
        let p = Poly::rand_fixed_c0(t - 1, secret, rng);
        (1..=n)
            .map(|i| p.eval(ShareIndex::new(i).unwrap()))
            .collect()
    }

    fn test_address(i: usize) -> Address {
        Address::new([i as u8; 32])
    }

    /// Ownership map matching the mock setup: member `i` owns share `i + 1`.
    fn test_share_owners(n: u16) -> HashMap<ShareIndex, Address> {
        (0..n as usize)
            .map(|i| (ShareIndex::new(i as u16 + 1).unwrap(), test_address(i)))
            .collect()
    }

    fn test_request_id() -> Address {
        Address::new([0xAA; 32])
    }

    fn verify_schnorr(vk: &G, message: &[u8], sig: &SchnorrSignature) {
        SchnorrPublicKey::try_from(vk)
            .unwrap()
            .verify(message, sig)
            .unwrap();
    }

    struct MockSigningP2PChannel {
        managers: HashMap<Address, Arc<SigningManager>>,
    }

    impl SigningManager {
        #[allow(clippy::too_many_arguments)]
        async fn sign_one(
            &self,
            p2p_channel: &impl P2PChannel,
            signing_id: Address,
            message: &[u8],
            global_presig_index: u64,
            beacon_value: &S,
            derivation_address: Option<&DerivationAddress>,
            timeout: Duration,
            metrics: &Metrics,
        ) -> SigningResult<SchnorrSignature> {
            let (result_tx, mut result_rx) = tokio::sync::mpsc::unbounded_channel();
            self.sign(
                p2p_channel,
                vec![SignInput {
                    signing_id,
                    message: message.to_vec(),
                    global_presig_index,
                    derivation_address: derivation_address.copied(),
                }],
                beacon_value,
                timeout,
                metrics,
                result_tx,
            )
            .await;
            match result_rx.recv().await {
                Some((_, result)) => result,
                None => Err(SigningError::CryptoError(
                    "sign produced no result for the request".to_string(),
                )),
            }
        }
    }

    #[async_trait::async_trait]
    impl P2PChannel for MockSigningP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }

        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponse> {
            unimplemented!()
        }
        async fn get_public_mpc_output(
            &self,
            _: &Address,
            _: &GetPublicMpcOutputRequest,
        ) -> ChannelResult<GetPublicMpcOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            let mgr = self
                .managers
                .get(party)
                .ok_or(ChannelError::ClientNotFound(*party))?;
            mgr.handle_get_partial_signatures_request(request)
                .map_err(|e| ChannelError::RequestFailed(e.to_string()))
        }
    }

    #[derive(Default)]
    struct CannedP2PChannel {
        responses: HashMap<Address, ChannelResult<Vec<Eval<S>>>>,
        nonces: HashMap<Address, G>,
        nonce_overrides: HashMap<(Address, Address), Vec<u8>>,
        nonce_omissions: HashSet<(Address, Address)>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for CannedP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }

        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponse> {
            unimplemented!()
        }
        async fn get_public_mpc_output(
            &self,
            _: &Address,
            _: &GetPublicMpcOutputRequest,
        ) -> ChannelResult<GetPublicMpcOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            match self.responses.get(party) {
                Some(Ok(evals)) => Ok(GetPartialSignaturesResponse {
                    partial_sigs: request
                        .signing_ids
                        .iter()
                        .map(|id| (*id, evals.clone()))
                        .collect(),
                    signing_nonces: request
                        .signing_ids
                        .iter()
                        .filter_map(|id| {
                            if self.nonce_omissions.contains(&(*party, *id)) {
                                return None;
                            }
                            self.nonce_overrides
                                .get(&(*party, *id))
                                .cloned()
                                .or_else(|| {
                                    self.nonces.get(party).map(|n| n.to_byte_array().to_vec())
                                })
                                .map(|n| (*id, n))
                        })
                        .collect(),
                }),
                Some(Err(_)) => Err(ChannelError::RequestFailed(format!(
                    "canned error for {}",
                    party
                ))),
                None => Err(ChannelError::ClientNotFound(*party)),
            }
        }
    }

    fn canned_p2p_with_corruptions(
        all_sigs: &[Vec<Eval<S>>],
        corrupt_indices: &[usize],
        rng: &mut impl AllowedRng,
    ) -> CannedP2PChannel {
        let mut responses = HashMap::new();
        for (i, peer_sigs) in all_sigs.iter().enumerate().skip(1) {
            let sigs = if corrupt_indices.contains(&i) {
                peer_sigs
                    .iter()
                    .map(|e| Eval {
                        index: e.index,
                        value: S::rand(rng),
                    })
                    .collect()
            } else {
                peer_sigs.clone()
            };
            responses.insert(test_address(i), Ok(sigs));
        }
        CannedP2PChannel {
            responses,
            ..Default::default()
        }
    }

    struct HangingP2PChannel {
        responses: HashMap<Address, Vec<Eval<S>>>,
        hanging: HashSet<Address>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for HangingP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }
        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponse> {
            unimplemented!()
        }
        async fn get_public_mpc_output(
            &self,
            _: &Address,
            _: &GetPublicMpcOutputRequest,
        ) -> ChannelResult<GetPublicMpcOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            if self.hanging.contains(party) {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                return Err(ChannelError::RequestFailed("hung".into()));
            }
            self.responses
                .get(party)
                .map(|evals| GetPartialSignaturesResponse {
                    partial_sigs: request
                        .signing_ids
                        .iter()
                        .map(|id| (*id, evals.clone()))
                        .collect(),
                    signing_nonces: BTreeMap::new(),
                })
                .map(Ok)
                .unwrap_or_else(|| Err(ChannelError::ClientNotFound(*party)))
        }
    }

    /// Counts polls per peer; `fail` peers error, the rest return an empty
    /// response (as a peer that has not signed yet would).
    struct CountingP2PChannel {
        fail: HashSet<Address>,
        not_ready: HashSet<Address>,
        calls: Mutex<HashMap<Address, usize>>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for CountingP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }
        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponse> {
            unimplemented!()
        }
        async fn get_public_mpc_output(
            &self,
            _: &Address,
            _: &GetPublicMpcOutputRequest,
        ) -> ChannelResult<GetPublicMpcOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            _: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            *self.calls.lock().unwrap().entry(*party).or_insert(0) += 1;
            if self.fail.contains(party) {
                Err(ChannelError::RequestFailed("down".into()))
            } else if self.not_ready.contains(party) {
                Err(ChannelError::NotReady("reconciling".into()))
            } else {
                Ok(GetPartialSignaturesResponse {
                    partial_sigs: std::collections::BTreeMap::new(),
                    signing_nonces: std::collections::BTreeMap::new(),
                })
            }
        }
    }

    /// Canned responses with a per-peer artificial delay, for
    /// ordering-sensitive tests under a paused clock.
    struct DelayedP2PChannel {
        responses: HashMap<Address, (Duration, Vec<Eval<S>>)>,
    }

    #[async_trait::async_trait]
    impl P2PChannel for DelayedP2PChannel {
        async fn send_messages(
            &self,
            _: &Address,
            _: &SendMessagesRequest,
        ) -> ChannelResult<SendMessagesResponse> {
            unimplemented!()
        }
        async fn retrieve_messages(
            &self,
            _: &Address,
            _: &RetrieveMessagesRequest,
        ) -> ChannelResult<RetrieveMessagesResponse> {
            unimplemented!()
        }
        async fn complain(
            &self,
            _: &Address,
            _: &ComplainRequest,
        ) -> ChannelResult<ComplaintResponse> {
            unimplemented!()
        }
        async fn get_public_mpc_output(
            &self,
            _: &Address,
            _: &GetPublicMpcOutputRequest,
        ) -> ChannelResult<GetPublicMpcOutputResponse> {
            unimplemented!()
        }
        async fn get_partial_signatures(
            &self,
            party: &Address,
            request: &GetPartialSignaturesRequest,
        ) -> ChannelResult<GetPartialSignaturesResponse> {
            let Some((delay, evals)) = self.responses.get(party) else {
                return Err(ChannelError::ClientNotFound(*party));
            };
            tokio::time::sleep(*delay).await;
            Ok(GetPartialSignaturesResponse {
                partial_sigs: request
                    .signing_ids
                    .iter()
                    .map(|id| (*id, evals.clone()))
                    .collect(),
                signing_nonces: BTreeMap::new(),
            })
        }
    }

    struct SigningTestSetup {
        managers: Vec<Arc<SigningManager>>,
        verifying_key: G,
        refill_rx: watch::Receiver<u32>,
        n: u16,
        f: u16,
        t: u16,
    }

    impl SigningTestSetup {
        fn new(n: u16) -> Self {
            let f = (n - 1) / 3;
            let t = f + 1;
            let mut rng = StdRng::seed_from_u64(42);

            // Committee
            let encryption_keys: Vec<_> = (0..n)
                .map(|_| EncryptionPrivateKey::new(&mut rng))
                .collect();
            let members: Vec<_> = (0..n as usize)
                .map(|i| {
                    CommitteeMember::new(
                        test_address(i),
                        hashi_types::committee::Bls12381PrivateKey::generate(&mut rng).public_key(),
                        EncryptionPublicKey::from_private_key(&encryption_keys[i]),
                        1,
                    )
                })
                .collect();
            let committee = Committee::new(members, 100, 0u16, 3333u16, 0);

            // Fake DKG
            let sk = S::rand(&mut rng);
            let vk = G::generator() * sk;
            let sk_shares = mock_shares(&mut rng, sk, t, n);

            // Fake presigning (same as fastcrypto test_signing)
            let batch_size_per_weight: u16 = 10;
            let nonces_for_dealer: Vec<_> = (0..n)
                .map(|_| {
                    let nonces: Vec<S> = (0..batch_size_per_weight)
                        .map(|_| S::rand(&mut rng))
                        .collect();
                    let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                    let nonce_shares: Vec<Vec<S>> = nonces
                        .iter()
                        .map(|&nonce| {
                            mock_shares(&mut rng, nonce, t, n)
                                .iter()
                                .map(|e| e.value)
                                .collect()
                        })
                        .collect();
                    (public_keys, nonce_shares)
                })
                .collect();

            let (refill_tx, refill_rx) = watch::channel(0u32);
            let refill_tx = Arc::new(refill_tx);

            let managers: Vec<_> = (0..n as usize)
                .map(|i| {
                    let index = ShareIndex::new(i as u16 + 1).unwrap();
                    let key_shares = avss::SharesForNode {
                        shares: vec![sk_shares[i].clone()],
                    };
                    let outputs: Vec<batch_avss::ReceiverOutput> = (0..n as usize)
                        .map(|j| batch_avss::ReceiverOutput {
                            my_shares: batch_avss::SharesForNode {
                                shares: vec![batch_avss::ShareBatch {
                                    index,
                                    batch: (0..batch_size_per_weight as usize)
                                        .map(|l| nonces_for_dealer[j].1[l][i])
                                        .collect(),
                                    blinding_share: S::zero(),
                                }],
                            },
                            public_keys: nonces_for_dealer[j].0.clone(),
                        })
                        .collect();
                    let presignatures = Presignatures::new(
                        outputs,
                        batch_size_per_weight,
                        Parameters { t, f },
                        true,
                    )
                    .unwrap();
                    let mgr = SigningManager::new(
                        test_address(i),
                        committee.clone(),
                        t,
                        key_shares,
                        vk,
                        test_share_owners(n),
                        presignatures,
                        0, // batch_index
                        0, // batch_start_index
                        crate::constants::PRESIG_REFILL_DIVISOR,
                        refill_tx.clone(),
                        IdentityInputs::for_test(),
                    )
                    .0;
                    Arc::new(mgr)
                })
                .collect();

            Self {
                managers,
                verifying_key: vk,
                refill_rx,
                n,
                f,
                t,
            }
        }

        fn prepare_all(
            &self,
            message: &[u8],
            beacon_value: &S,
            request_id: Address,
            global_presig_index: u64,
            skip: Option<usize>,
        ) -> (G, Vec<Vec<Eval<S>>>) {
            let mut public_nonce = None;
            let mut all_sigs = Vec::new();
            for (idx, mgr) in self.managers.iter().enumerate() {
                if skip == Some(idx) {
                    all_sigs.push(Vec::new());
                    continue;
                }
                let presig = {
                    let state = mgr.state.read().unwrap();
                    state
                        .batches
                        .iter()
                        .find(|b| b.contains(global_presig_index))
                        .and_then(|b| {
                            let pos = (global_presig_index - b.start_index) as usize;
                            b.pool.get(pos).and_then(|s| s.clone())
                        })
                        .unwrap()
                };
                let (pn, sigs) = generate_partial_signatures(
                    message,
                    presig,
                    beacon_value,
                    &mgr.config.key_shares,
                    &mgr.config.verifying_key,
                    None,
                )
                .unwrap();
                mgr.state.write().unwrap().partial_signing_outputs.insert(
                    request_id,
                    PartialSigningOutput::new(pn, beacon_value, message, None, sigs.clone()),
                );
                if public_nonce.is_none() {
                    public_nonce = Some(pn);
                }
                all_sigs.push(sigs);
            }
            (public_nonce.unwrap(), all_sigs)
        }

        /// Build a MockSigningP2PChannel containing all peers except `caller_index`.
        fn mock_p2p_for(&self, caller_index: usize) -> MockSigningP2PChannel {
            let managers = self
                .managers
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != caller_index)
                .map(|(i, m)| (test_address(i), m.clone()))
                .collect();
            MockSigningP2PChannel { managers }
        }

        /// Exhaust all presignatures on all managers by taking every slot.
        fn exhaust_pool(&self) {
            for mgr in &self.managers {
                let mut state = mgr.state.write().unwrap();
                for batch in &mut state.batches {
                    for slot in &mut batch.pool {
                        slot.take();
                    }
                }
            }
        }

        /// Build one fresh batch of presignatures per manager.
        fn build_presignatures(&self) -> Vec<Presignatures> {
            let batch_size_per_weight: u16 = 10;
            let mut rng = StdRng::seed_from_u64(99);
            let nonces_for_dealer: Vec<_> = (0..self.n)
                .map(|_| {
                    let nonces: Vec<S> = (0..batch_size_per_weight)
                        .map(|_| S::rand(&mut rng))
                        .collect();
                    let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                    let nonce_shares: Vec<Vec<S>> = nonces
                        .iter()
                        .map(|&nonce| {
                            mock_shares(&mut rng, nonce, self.t, self.n)
                                .iter()
                                .map(|e| e.value)
                                .collect()
                        })
                        .collect();
                    (public_keys, nonce_shares)
                })
                .collect();
            (0..self.managers.len())
                .map(|i| {
                    let index = ShareIndex::new(i as u16 + 1).unwrap();
                    let outputs: Vec<batch_avss::ReceiverOutput> = (0..self.n as usize)
                        .map(|j| batch_avss::ReceiverOutput {
                            my_shares: batch_avss::SharesForNode {
                                shares: vec![batch_avss::ShareBatch {
                                    index,
                                    batch: (0..batch_size_per_weight as usize)
                                        .map(|l| nonces_for_dealer[j].1[l][i])
                                        .collect(),
                                    blinding_share: S::zero(),
                                }],
                            },
                            public_keys: nonces_for_dealer[j].0.clone(),
                        })
                        .collect();
                    Presignatures::new(
                        outputs,
                        batch_size_per_weight,
                        Parameters {
                            t: self.t,
                            f: self.f,
                        },
                        true,
                    )
                    .unwrap()
                })
                .collect()
        }

        /// Build fresh presignatures and set as next_batch on all managers.
        fn set_next_batch_on_all(&self) {
            for (mgr, presignatures) in self.managers.iter().zip(self.build_presignatures()) {
                let next_index = mgr.batch_index() + 1;
                mgr.set_next_batch(next_index, presignatures, IdentityInputs::for_test());
            }
        }

        /// Manually advance peers (skip manager at `caller_index`) by
        /// pushing the next_batch onto their batch list. Needed because
        /// `prepare_all` calls `generate_partial_signatures` directly (not
        /// `sign()`), so it doesn't trigger the batch-advance logic.
        fn advance_peers_to_next_batch(&self, caller_index: usize) {
            for (i, mgr) in self.managers.iter().enumerate() {
                if i == caller_index {
                    continue;
                }
                let mut state = mgr.state.write().unwrap();
                let latest = state.batches.last().unwrap();
                let next_start = latest.end_index();
                let next_batch_index = latest.batch_index + 1;
                let next = state.next_batch.take().unwrap();
                state.batches.push(PresigBatch {
                    pool: next.pool,
                    start_index: next_start,
                    batch_index: next_batch_index,
                });
            }
        }
    }

    /// Pre-built partial sigs for aggregate_signatures_with_recovery tests.
    struct AggregateTestData {
        partial_sigs: Vec<Eval<S>>,
        public_nonce: G,
        vk: G,
        beacon: S,
        t: u16,
        rng: StdRng,
    }

    /// Build 6 partial sigs from a (n=7, t=3, f=2) setup for RS recovery tests.
    fn build_aggregate_test_data(seed: u64, message: &[u8]) -> AggregateTestData {
        let mut rng = StdRng::seed_from_u64(seed);
        let f: u16 = 2;
        let t: u16 = f + 1;
        let n: u16 = 7;

        let sk = S::rand(&mut rng);
        let vk = G::generator() * sk;
        let sk_shares = mock_shares(&mut rng, sk, t, n);

        let batch_size_per_weight: u16 = 2;
        let nonces_for_dealer: Vec<_> = (0..n)
            .map(|_| {
                let nonces: Vec<S> = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect();
                let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(&mut rng, nonce, t, n)
                            .iter()
                            .map(|e| e.value)
                            .collect()
                    })
                    .collect();
                (public_keys, nonce_shares)
            })
            .collect();

        let beacon = S::rand(&mut rng);

        let mut public_nonce = None;
        let mut partial_sigs: Vec<Eval<S>> = Vec::new();
        for (i, sk_share) in sk_shares.iter().enumerate().take(6) {
            let index = ShareIndex::new(i as u16 + 1).unwrap();
            let key_shares = avss::SharesForNode {
                shares: vec![sk_share.clone()],
            };
            let outputs: Vec<batch_avss::ReceiverOutput> = (0..n as usize)
                .map(|j| batch_avss::ReceiverOutput {
                    my_shares: batch_avss::SharesForNode {
                        shares: vec![batch_avss::ShareBatch {
                            index,
                            batch: (0..batch_size_per_weight as usize)
                                .map(|l| nonces_for_dealer[j].1[l][i])
                                .collect(),
                            blinding_share: S::zero(),
                        }],
                    },
                    public_keys: nonces_for_dealer[j].0.clone(),
                })
                .collect();
            let presigs: Vec<(Vec<S>, G)> =
                Presignatures::new(outputs, batch_size_per_weight, Parameters { t, f }, true)
                    .unwrap()
                    .collect();
            let (pn, sigs) = generate_partial_signatures(
                message,
                presigs[0].clone(),
                &beacon,
                &key_shares,
                &vk,
                None,
            )
            .unwrap();
            if public_nonce.is_none() {
                public_nonce = Some(pn);
            }
            partial_sigs.extend(sigs);
        }

        AggregateTestData {
            partial_sigs,
            public_nonce: public_nonce.unwrap(),
            vk,
            beacon,
            t,
            rng,
        }
    }

    #[test]
    fn test_new_recovered_retains_pending_batch_and_gates_slots() {
        let n: u16 = 4;
        let f = (n - 1) / 3;
        let t = f + 1;
        let mut rng = StdRng::seed_from_u64(7);

        let encryption_keys: Vec<_> = (0..n)
            .map(|_| EncryptionPrivateKey::new(&mut rng))
            .collect();
        let members: Vec<_> = (0..n as usize)
            .map(|i| {
                CommitteeMember::new(
                    test_address(i),
                    hashi_types::committee::Bls12381PrivateKey::generate(&mut rng).public_key(),
                    EncryptionPublicKey::from_private_key(&encryption_keys[i]),
                    1,
                )
            })
            .collect();
        let committee = Committee::new(members, 100, 0u16, 3333u16, 0);

        let sk = S::rand(&mut rng);
        let vk = G::generator() * sk;
        let sk_shares = mock_shares(&mut rng, sk, t, n);

        let batch_size_per_weight: u16 = 10;
        let nonces_for_dealer: Vec<(Vec<G>, Vec<Vec<S>>)> = (0..n)
            .map(|_| {
                let nonces: Vec<S> = (0..batch_size_per_weight)
                    .map(|_| S::rand(&mut rng))
                    .collect();
                let public_keys: Vec<G> = nonces.iter().map(|s| G::generator() * *s).collect();
                let nonce_shares: Vec<Vec<S>> = nonces
                    .iter()
                    .map(|&nonce| {
                        mock_shares(&mut rng, nonce, t, n)
                            .iter()
                            .map(|e| e.value)
                            .collect()
                    })
                    .collect();
                (public_keys, nonce_shares)
            })
            .collect();

        let index = ShareIndex::new(1).unwrap();
        let outputs: Vec<batch_avss::ReceiverOutput> = (0..n as usize)
            .map(|j| batch_avss::ReceiverOutput {
                my_shares: batch_avss::SharesForNode {
                    shares: vec![batch_avss::ShareBatch {
                        index,
                        batch: (0..batch_size_per_weight as usize)
                            .map(|l| nonces_for_dealer[j].1[l][0])
                            .collect(),
                        blinding_share: S::zero(),
                    }],
                },
                public_keys: nonces_for_dealer[j].0.clone(),
            })
            .collect();
        let params = Parameters { t, f };
        let new_batch =
            || Presignatures::new(outputs.clone(), batch_size_per_weight, params, true).unwrap();
        let size0 = new_batch().len() as u64;
        assert!(size0 > 6, "batch must be large enough for the index math");

        let num_consumed = size0 + 5;
        let pending: HashSet<u64> = HashSet::from([3u64]);
        let (refill_tx, _rx) = watch::channel(0u32);
        let mgr = SigningManager::new_recovered(
            test_address(0),
            committee.clone(),
            t,
            avss::SharesForNode {
                shares: vec![sk_shares[0].clone()],
            },
            vk,
            test_share_owners(4),
            vec![(new_batch(), 0, 0), (new_batch(), 1, size0)],
            num_consumed,
            &pending,
            crate::constants::PRESIG_REFILL_DIVISOR,
            Arc::new(refill_tx),
            IdentityInputs::for_test(),
        )
        .unwrap();
        let (mgr, identities) = (mgr.0, mgr.1);

        let (fresh_refill_tx, _fresh_rx) = watch::channel(0u32);
        let (_, unmasked) = SigningManager::new_recovered(
            test_address(0),
            committee.clone(),
            t,
            avss::SharesForNode {
                shares: vec![sk_shares[0].clone()],
            },
            vk,
            test_share_owners(4),
            vec![(new_batch(), 0, 0), (new_batch(), 1, size0)],
            0,
            &HashSet::new(),
            crate::constants::PRESIG_REFILL_DIVISOR,
            Arc::new(fresh_refill_tx),
            IdentityInputs::for_test(),
        )
        .unwrap();
        assert_eq!(
            identities.len(),
            2,
            "both retained batches must yield an identity"
        );
        assert_eq!(
            unmasked.len(),
            2,
            "both retained batches must yield an identity"
        );
        for ((_, consumed_run), (_, fresh_run)) in identities.iter().zip(unmasked.iter()) {
            assert_eq!(
                consumed_run.fingerprint, fresh_run.fingerprint,
                "identity must cover the generated sequence, so masking consumed slots \
                 must not change it; a digest taken after the mask would differ on \
                 every restart that had spent part of the batch"
            );
            assert_eq!(
                consumed_run.size, fresh_run.size,
                "recorded size must be the generated length, not the enabled count"
            );
        }

        {
            let state = mgr.state.read().unwrap();
            assert_eq!(
                state.batches.len(),
                2,
                "batch 0 (referenced by pending) must be retained, not dropped"
            );
            let b0 = &state.batches[0];
            assert!(b0.pool[3].is_some(), "pending index 3 stays enabled");
            assert!(
                b0.pool[0].is_none(),
                "consumed non-pending index 0 is disabled (reuse guard)"
            );
            let b1 = &state.batches[1];
            assert!(
                b1.pool[5].is_some(),
                "slot at the cursor (size0 + 5) is enabled"
            );
            assert!(
                b1.pool[0].is_none(),
                "consumed non-pending slot in batch 1 is disabled"
            );
        }

        let (refill_tx2, _rx2) = watch::channel(0u32);
        let err = SigningManager::new_recovered(
            test_address(0),
            committee,
            t,
            avss::SharesForNode {
                shares: vec![sk_shares[0].clone()],
            },
            vk,
            test_share_owners(4),
            vec![(new_batch(), 1, size0)], // batch 0 dropped
            num_consumed,
            &pending, // pending {3} lives in the dropped batch 0
            crate::constants::PRESIG_REFILL_DIVISOR,
            Arc::new(refill_tx2),
            IdentityInputs::for_test(),
        );
        assert!(
            err.is_err(),
            "must reject a rebuild that fails to cover a pending index"
        );
    }

    #[test]
    fn test_handle_get_partial_signatures_found() {
        let setup = SigningTestSetup::new(4);
        let message = b"test";
        let mut rng = StdRng::seed_from_u64(6501);
        let beacon = S::rand(&mut rng);
        let req_id = test_request_id();

        setup.prepare_all(message, &beacon, req_id, 0, None);

        let resp = setup.managers[0]
            .handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
                signing_ids: vec![req_id, Address::new([0xDD; 32])],
            })
            .unwrap();
        assert!(resp.partial_sigs.contains_key(&req_id));
        let cached = setup.managers[0]
            .state
            .read()
            .unwrap()
            .partial_signing_outputs
            .get(&req_id)
            .unwrap()
            .public_nonce();
        assert_eq!(
            resp.signing_nonces.get(&req_id).map(Vec::as_slice),
            Some(signing_nonce_bytes(&cached, &beacon).as_slice()),
            "must report the nonce the returned partials were derived against"
        );
        assert_eq!(
            resp.partial_sigs.keys().collect::<Vec<_>>(),
            vec![&req_id],
            "an id with no local output is absent from both maps, not present in one"
        );
        assert_eq!(
            resp.partial_sigs.keys().collect::<Vec<_>>(),
            resp.signing_nonces.keys().collect::<Vec<_>>(),
            "the merge side rejects a partially filled map, so the key sets must match"
        );
        assert_ne!(
            resp.signing_nonces.get(&req_id).map(Vec::as_slice),
            Some(cached.to_byte_array().as_slice()),
        );
    }

    #[test]
    fn test_partial_signatures_response_survives_a_proto_round_trip() {
        let setup = SigningTestSetup::new(4);
        let req_id = test_request_id();
        let mut rng = StdRng::seed_from_u64(6502);
        let beacon = S::rand(&mut rng);
        setup.prepare_all(b"test", &beacon, req_id, 0, None);

        let resp = setup.managers[0]
            .handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
                signing_ids: vec![req_id],
            })
            .unwrap();
        let round_tripped = GetPartialSignaturesResponse::try_from(
            &hashi_types::proto::GetPartialSignaturesResponse::from(&resp),
        )
        .unwrap();

        assert_eq!(round_tripped.signing_nonces, resp.signing_nonces);
        assert_eq!(
            round_tripped.signing_nonces.get(&req_id).map(Vec::as_slice),
            Some(
                signing_nonce_bytes(
                    &setup.managers[0]
                        .state
                        .read()
                        .unwrap()
                        .partial_signing_outputs
                        .get(&req_id)
                        .unwrap()
                        .public_nonce(),
                    &beacon,
                )
                .as_slice()
            ),
        );
    }

    #[test]
    fn test_handle_get_partial_signatures_absent_returns_empty() {
        let setup = SigningTestSetup::new(4);
        let resp = setup.managers[0]
            .handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
                signing_ids: vec![test_request_id()],
            })
            .unwrap();
        assert!(resp.partial_sigs.is_empty());
        assert!(
            resp.signing_nonces.is_empty(),
            "an id we have no output for is absent from both maps, not present and empty"
        );
    }

    #[test]
    fn test_the_reported_nonce_encoding_is_its_bcs_encoding() {
        let nonce = G::generator() + G::generator();
        assert_eq!(
            bcs::to_bytes(&nonce).unwrap(),
            nonce.to_byte_array().to_vec()
        );
    }

    #[tokio::test]
    async fn test_sign_happy_path() {
        let setup = SigningTestSetup::new(7); // n=7, t=3, f=2
        let message = b"hello world";
        let beacon = S::zero();
        let req_id = test_request_id();

        // All peers (except caller) prepare their partial sigs first.
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_multi_input_all_succeed() {
        let setup = SigningTestSetup::new(7); // n=7, t=3, f=2
        let beacon = S::zero();
        let inputs: Vec<(Address, Vec<u8>, u64)> = (0..3u8)
            .map(|j| {
                (
                    Address::new([0xB0 + j; 32]),
                    format!("input-{j}").into_bytes(),
                    j as u64,
                )
            })
            .collect();
        for (sid, msg, pidx) in &inputs {
            setup.prepare_all(msg, &beacon, *sid, *pidx, Some(0));
        }
        let requests: Vec<SignInput> = inputs
            .iter()
            .map(|(sid, msg, pidx)| SignInput {
                signing_id: *sid,
                message: msg.clone(),
                global_presig_index: *pidx,
                derivation_address: None,
            })
            .collect();

        let p2p = setup.mock_p2p_for(0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup.managers[0]
            .sign(
                &p2p,
                requests,
                &beacon,
                Duration::from_secs(30),
                &test_metrics(),
                tx,
            )
            .await;

        let mut results = HashMap::new();
        while let Some((sid, res)) = rx.recv().await {
            results.insert(sid, res);
        }
        assert_eq!(results.len(), inputs.len());
        for (sid, msg, _) in &inputs {
            let sig = results.get(sid).unwrap().as_ref().unwrap();
            verify_schnorr(&setup.verifying_key, msg, sig);
        }
    }

    #[tokio::test]
    async fn test_sign_multi_input_one_fails_others_succeed() {
        let setup = SigningTestSetup::new(7); // n=7, t=3, f=2
        let beacon = S::zero();
        let good: Vec<(Address, Vec<u8>, u64)> = (0..2u8)
            .map(|j| {
                (
                    Address::new([0xB0 + j; 32]),
                    format!("good-{j}").into_bytes(),
                    j as u64,
                )
            })
            .collect();
        let bad_id = Address::new([0xBF; 32]);

        for (sid, msg, pidx) in &good {
            setup.prepare_all(msg, &beacon, *sid, *pidx, Some(0));
        }
        // Deliberately do NOT prepare peers for the bad input: they return no
        // partial for it, so it can never reach threshold.

        let mut requests: Vec<SignInput> = good
            .iter()
            .map(|(sid, msg, pidx)| SignInput {
                signing_id: *sid,
                message: msg.clone(),
                global_presig_index: *pidx,
                derivation_address: None,
            })
            .collect();
        requests.push(SignInput {
            signing_id: bad_id,
            message: b"bad".to_vec(),
            global_presig_index: 2,
            derivation_address: None,
        });

        let p2p = setup.mock_p2p_for(0);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        setup.managers[0]
            .sign(
                &p2p,
                requests,
                &beacon,
                Duration::from_secs(2),
                &test_metrics(),
                tx,
            )
            .await;

        let mut results = HashMap::new();
        while let Some((sid, res)) = rx.recv().await {
            results.insert(sid, res);
        }
        for (sid, msg, _) in &good {
            let sig = results.get(sid).unwrap().as_ref().unwrap();
            verify_schnorr(&setup.verifying_key, msg, sig);
        }
        assert!(matches!(
            results.get(&bad_id),
            Some(Err(SigningError::Timeout { .. }))
        ));
    }

    #[tokio::test]
    async fn test_sign_with_empty_local_partial_sigs() {
        use tracing_subscriber::util::SubscriberInitExt;
        let _guard = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .set_default();

        let setup = SigningTestSetup::new(7); // n=7, t=3, f=2
        let message = b"empty local sigs";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (public_nonce, _) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        // Pre-populate manager[0]'s cache with empty `partial_sigs` to simulate a
        // `w' = 0` party that produced no local sigs from `generate_partial_signatures`.
        setup.managers[0]
            .state
            .write()
            .unwrap()
            .partial_signing_outputs
            .insert(
                req_id,
                PartialSigningOutput::new(public_nonce, &beacon, message, None, vec![]),
            );

        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_threshold_exact() {
        // n=7, t=3, f=2. Caller has 1 share, needs 2 more from peers.
        // Give exactly 2 peers partial sigs, rest return errors.
        let setup = SigningTestSetup::new(7);
        let message = b"threshold";
        let beacon = S::zero();
        let req_id = test_request_id();

        // Only peers 1 and 2 prepare partial sigs.
        for i in [1, 2] {
            let mgr = &setup.managers[i];
            let presig = {
                let state = mgr.state.read().unwrap();
                state.batches[0].pool[0].clone().unwrap()
            };
            let (pn, sigs) = generate_partial_signatures(
                message,
                presig,
                &beacon,
                &mgr.config.key_shares,
                &mgr.config.verifying_key,
                None,
            )
            .unwrap();
            mgr.state.write().unwrap().partial_signing_outputs.insert(
                req_id,
                PartialSigningOutput::new(pn, &beacon, message, None, sigs),
            );
        }

        // Peers 3-6 are in the mock but have no stored sigs → NotFound → ChannelError
        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_one_corrupted_rs_recovery() {
        // n=7, t=3, f=2. One peer returns corrupted partial sig.
        // Caller's 1 + 6 peers = 7 total, 1 bad → RS capacity (7-3)/2=2 → corrects 1.
        let setup = SigningTestSetup::new(7);
        let message = b"recovery";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = canned_p2p_with_corruptions(&all_sigs, &[1], &mut StdRng::seed_from_u64(999));

        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_multiple_corrupted_rs_recovery() {
        // n=10, t=4, f=3. Two peers return corrupted sigs.
        // Caller's 1 + 9 peers = 10 total, 2 bad → RS capacity (10-4)/2=3 → corrects 2.
        let setup = SigningTestSetup::new(10);
        let message = b"multi-recovery";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = canned_p2p_with_corruptions(&all_sigs, &[1, 2], &mut StdRng::seed_from_u64(888));

        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    fn share_index(i: u16) -> ShareIndex {
        ShareIndex::new(i).unwrap()
    }

    fn eval_at(i: u16, value: S) -> Eval<S> {
        Eval {
            index: share_index(i),
            value,
        }
    }

    fn test_input_state(
        signing_id: Address,
        partials: Vec<Eval<S>>,
        peers_remaining: Vec<Address>,
    ) -> InputSigningState {
        InputSigningState::new(
            signing_id,
            b"m".to_vec(),
            G::generator(),
            &S::zero(),
            None,
            partials,
            // Helper-driven collect tests exercise full rounds; the
            // early-exit is covered by dedicated tests.
            usize::MAX,
            peers_remaining.into_iter().collect(),
        )
    }

    #[tokio::test]
    async fn test_a_dropped_peer_still_leaves_a_verifiable_signature() {
        let setup = SigningTestSetup::new(7);
        let message = b"drop-and-aggregate";
        let mut rng = StdRng::seed_from_u64(6503);
        let beacon = S::rand(&mut rng);
        let req_id = test_request_id();
        let diverged = test_address(6);

        let (public_nonce, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, None);
        let honest_nonce = public_nonce + G::generator() * beacon;

        let mut responses = HashMap::new();
        let mut nonces = HashMap::new();
        for (i, sigs) in all_sigs.iter().enumerate().skip(1) {
            let peer = test_address(i);
            responses.insert(peer, Ok(sigs.clone()));
            nonces.insert(
                peer,
                if peer == diverged {
                    G::generator() + G::generator()
                } else {
                    honest_nonce
                },
            );
        }
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            ..Default::default()
        };

        let metrics = test_metrics();
        let mut pending = vec![InputSigningState::new(
            req_id,
            message.to_vec(),
            public_nonce,
            &beacon,
            None,
            all_sigs[0].clone(),
            usize::MAX,
            (1..7usize).map(test_address).collect(),
        )];
        let deadline = Instant::now() + Duration::from_secs(5);
        setup.managers[0]
            .collect_partial_sigs_from_peers(
                &p2p,
                &mut pending,
                deadline,
                &HashSet::new(),
                &metrics,
            )
            .await;

        let mismatches = |peer: &Address| {
            metrics
                .mpc_partial_sig_nonce_mismatch_total
                .with_label_values(&[&peer.to_string()])
                .get()
        };
        assert_eq!(mismatches(&diverged), 1);
        for i in 1..6usize {
            assert_eq!(
                mismatches(&test_address(i)),
                0,
                "a peer reporting our nonce must not be dropped"
            );
        }

        let outcome = try_finalize_signature(
            &mut pending[0],
            setup.managers[0].config.threshold,
            &setup.verifying_key,
            true,
            &HashSet::new(),
            &metrics,
        )
        .await;
        match outcome {
            FinalizeOutcome::Done(sig, mismatched) => {
                assert!(mismatched.is_empty(), "no share should mismatch");
                verify_schnorr(&setup.verifying_key, message, &sig);
                let reported = G::from_byte_array(&signing_nonce_bytes(&public_nonce, &beacon))
                    .unwrap()
                    .x_as_be_bytes()
                    .unwrap();
                assert_eq!(
                    reported, sig.r,
                    "the nonce we report must be the one fastcrypto signed under"
                );
            }
            _ => panic!("the surviving shares must still aggregate"),
        }
    }

    #[tokio::test]
    async fn test_a_cache_hit_under_a_changed_message_is_refused() {
        let setup = SigningTestSetup::new(7);
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(b"first sighash", &beacon, req_id, 0, None);

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            b"second sighash",
            0,
            &beacon,
            None,
            Duration::from_secs(5),
            &test_metrics(),
        )
        .await;

        assert!(
            matches!(result, Err(SigningError::RequestChanged { .. })),
            "expected RequestChanged, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_sign_fast_fails_when_every_peer_is_on_a_different_nonce() {
        let setup = SigningTestSetup::new(4);
        let message = b"nonce-fast-fail";
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let mut rng = StdRng::seed_from_u64(9090);
        let elsewhere = G::generator() + G::generator();
        let mut responses = HashMap::new();
        let mut nonces = HashMap::new();
        for i in 1..4usize {
            responses.insert(
                test_address(i),
                Ok(vec![eval_at(i as u16 + 1, S::rand(&mut rng))]),
            );
            nonces.insert(test_address(i), elsewhere);
        }
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            ..Default::default()
        };

        let started = Instant::now();
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(SigningError::TooManyInvalidSignatures { .. })),
            "expected fast TooManyInvalidSignatures, got: {:?}",
            result.err()
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "fast-fail should not wait out the deadline: {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_round_does_not_exit_while_no_candidate_is_attemptable() {
        let setup = SigningTestSetup::new(7);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let fast_empty = test_address(3);
        // Owns share 5 in the mock setup (member i owns share i + 1).
        let slow_useful = test_address(4);
        let mut rng = StdRng::seed_from_u64(99);

        let responses = HashMap::from([
            (fast_empty, (Duration::ZERO, Vec::new())),
            (
                slow_useful,
                (
                    Duration::from_millis(200),
                    vec![eval_at(5, S::rand(&mut rng))],
                ),
            ),
        ]);
        let p2p = DelayedP2PChannel { responses };

        let mut pending = vec![InputSigningState::new(
            test_request_id(),
            b"m".to_vec(),
            G::generator(),
            &S::zero(),
            None,
            vec![
                eval_at(1, S::zero()),
                eval_at(2, S::zero()),
                eval_at(3, S::zero()),
            ],
            3,
            [fast_empty, slow_useful].into_iter().collect(),
        )];
        pending[0].clean_attempted = true;

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        assert!(
            pending[0]
                .partials
                .iter()
                .any(|e| e.index == share_index(5)),
            "the slow peer's share must be merged; a fast empty response \
             must not end the round at the stale threshold"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_round_exits_once_a_flag_leaves_a_usable_unflagged_prefix() {
        let setup = SigningTestSetup::new(7);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let fast_useful = test_address(2);
        let slow = test_address(4);
        let mut rng = StdRng::seed_from_u64(7);

        let responses = HashMap::from([
            (
                fast_useful,
                (Duration::ZERO, vec![eval_at(3, S::rand(&mut rng))]),
            ),
            (
                slow,
                (
                    Duration::from_millis(200),
                    vec![eval_at(5, S::rand(&mut rng))],
                ),
            ),
        ]);
        let p2p = DelayedP2PChannel { responses };

        let mut pending = vec![InputSigningState::new(
            test_request_id(),
            b"m".to_vec(),
            G::generator(),
            &S::zero(),
            None,
            vec![
                eval_at(4, S::rand(&mut rng)),
                eval_at(1, S::zero()),
                eval_at(2, S::zero()),
            ],
            3,
            [fast_useful, slow].into_iter().collect(),
        )];
        pending[0].clean_attempted = true;
        let flagged: HashSet<ShareIndex> = [share_index(4)].into_iter().collect();

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(&p2p, &mut pending, deadline, &flagged, &metrics)
            .await;

        let has = |i: u16| {
            pending[0]
                .partials
                .iter()
                .any(|e| e.index == share_index(i))
        };
        assert!(has(3));
        assert!(
            !has(5),
            "the round must end once the unflagged prefix is usable instead of waiting \
             for the slow peer"
        );
    }

    #[tokio::test]
    async fn test_collect_drops_an_unowned_eval_without_penalising_the_peer() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let diverged = test_address(1);
        let mut rng = StdRng::seed_from_u64(8181);

        let responses = HashMap::from([(diverged, Ok(vec![eval_at(3, S::rand(&mut rng))]))]);
        let p2p = CannedP2PChannel {
            responses,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![diverged],
        )];

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let indices: Vec<u16> = pending[0].partials.iter().map(|e| e.index.get()).collect();
        assert_eq!(indices, vec![1], "an unowned eval must not enter the pool");
        assert!(
            !mgr.peer_cooldowns.is_cooling(&diverged, Instant::now()),
            "dropping one eval must not cool the peer"
        );
        assert_eq!(
            metrics
                .mpc_partial_sig_evals_dropped_total
                .with_label_values(&[&diverged.to_string()])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn test_collect_rejects_a_list_longer_than_the_peer_owns() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let flooder = test_address(1);
        let honest = test_address(2);
        let mut rng = StdRng::seed_from_u64(4242);

        let responses = HashMap::from([
            (
                flooder,
                Ok(vec![
                    eval_at(1, S::rand(&mut rng)), // caller's share
                    eval_at(2, S::rand(&mut rng)), // flooder's own share
                    eval_at(3, S::rand(&mut rng)), // another member's share
                    eval_at(4, S::rand(&mut rng)), // another member's share
                    eval_at(9, S::rand(&mut rng)), // nonexistent share
                ]),
            ),
            (honest, Ok(vec![eval_at(3, S::rand(&mut rng))])),
        ]);
        let p2p = CannedP2PChannel {
            responses,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![flooder, honest],
        )];

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let st = &pending[0];
        let mut indices: Vec<u16> = st.partials.iter().map(|e| e.index.get()).collect();
        indices.sort_unstable();
        assert_eq!(
            indices,
            vec![1, 3],
            "nothing from the flooder may enter the pool, and the honest peer is unaffected"
        );
        assert!(mgr.peer_cooldowns.is_cooling(&flooder, Instant::now()));
        assert!(!mgr.peer_cooldowns.is_cooling(&honest, Instant::now()));
        assert_eq!(
            metrics
                .mpc_partial_sig_lists_rejected_total
                .with_label_values(&[&flooder.to_string()])
                .get(),
            1
        );
        let share_1_values: Vec<&S> = st
            .partials
            .iter()
            .filter(|e| e.index == share_index(1))
            .map(|e| &e.value)
            .collect();
        assert_eq!(
            share_1_values,
            vec![&S::zero()],
            "the local value for share 1 must be untouched"
        );
    }

    #[tokio::test]
    async fn test_sign_succeeds_despite_a_garbage_flooder() {
        let setup = SigningTestSetup::new(4);
        let message = b"garbage-flood";
        let beacon = S::zero();
        let req_id = test_request_id();
        let mut rng = StdRng::seed_from_u64(1717);

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let flood: Vec<Eval<S>> = (1..=4u16).map(|i| eval_at(i, S::rand(&mut rng))).collect();
        let mut responses = HashMap::new();
        responses.insert(test_address(1), Ok(flood));
        responses.insert(test_address(2), Ok(all_sigs[2].clone()));
        responses.insert(test_address(3), Ok(all_sigs[3].clone()));
        let p2p = CannedP2PChannel {
            responses,
            ..Default::default()
        };

        let metrics = test_metrics();
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &metrics,
        )
        .await
        .expect("a single flooder must not block signing");

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_a_peer_that_reports_some_nonces_may_not_omit_others() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let mut rng = StdRng::seed_from_u64(4714);
        let peer = test_address(1);
        let reported = test_request_id();
        let omitted = Address::new([0xCC; 32]);

        let responses = HashMap::from([(peer, Ok(vec![eval_at(2, S::rand(&mut rng))]))]);
        let nonces = HashMap::from([(peer, G::generator())]);
        let nonce_omissions = HashSet::from([(peer, omitted)]);
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            nonce_omissions,
            ..Default::default()
        };

        let mut pending = vec![
            test_input_state(reported, vec![eval_at(1, S::zero())], vec![peer]),
            test_input_state(omitted, vec![eval_at(1, S::zero())], vec![peer]),
        ];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let merged: Vec<u16> = pending[0].partials.iter().map(|e| e.index.get()).collect();
        assert!(
            merged.contains(&2),
            "the input it did report for is unaffected"
        );
        let dropped: Vec<u16> = pending[1].partials.iter().map(|e| e.index.get()).collect();
        assert_eq!(
            dropped,
            vec![1],
            "a peer that reports nonces cannot selectively omit one"
        );
    }

    #[tokio::test]
    async fn test_a_malformed_reported_nonce_is_rejected() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let mut rng = StdRng::seed_from_u64(4713);
        let peer = test_address(1);
        let short = test_address(2);

        let responses = HashMap::from([
            (peer, Ok(vec![eval_at(2, S::rand(&mut rng))])),
            (short, Ok(vec![eval_at(3, S::rand(&mut rng))])),
        ]);
        let nonce_overrides = HashMap::from([
            ((peer, test_request_id()), Vec::new()),
            (
                (short, test_request_id()),
                vec![0u8; POINT_SIZE_IN_BYTES - 1],
            ),
        ]);
        let p2p = CannedP2PChannel {
            responses,
            nonce_overrides,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![peer, short],
        )];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let mut indices: Vec<u16> = pending[0].partials.iter().map(|e| e.index.get()).collect();
        indices.sort_unstable();
        assert_eq!(
            indices,
            vec![1],
            "a wrong-length nonce is not producible honestly, so its partials are dropped"
        );
        for p in [peer, short] {
            assert_eq!(
                metrics
                    .mpc_partial_sig_nonce_mismatch_total
                    .with_label_values(&[&p.to_string()])
                    .get(),
                0,
            );
        }
    }

    #[tokio::test]
    async fn test_a_peer_may_diverge_on_one_input_and_not_another() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let mut rng = StdRng::seed_from_u64(4712);
        let agreed = test_request_id();
        let disputed = Address::new([0xBB; 32]);

        let responses = HashMap::from([
            (test_address(1), Ok(vec![eval_at(2, S::rand(&mut rng))])),
            (test_address(2), Ok(vec![eval_at(3, S::rand(&mut rng))])),
        ]);
        let elsewhere = G::generator() + G::generator();
        let nonces = HashMap::from([
            (test_address(1), G::generator()),
            (test_address(2), G::generator()),
        ]);
        let nonce_overrides = HashMap::from([
            (
                (test_address(1), disputed),
                elsewhere.to_byte_array().to_vec(),
            ),
            (
                (test_address(2), disputed),
                elsewhere.to_byte_array().to_vec(),
            ),
        ]);
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            nonce_overrides,
            ..Default::default()
        };

        let peers = vec![test_address(1), test_address(2)];
        let mut pending = vec![
            test_input_state(agreed, vec![eval_at(1, S::zero())], peers.clone()),
            test_input_state(disputed, vec![eval_at(1, S::zero())], peers),
        ];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let merged: Vec<u16> = pending[0].partials.iter().map(|e| e.index.get()).collect();
        assert!(
            merged.contains(&2),
            "the agreed input keeps the shares of a peer that diverged elsewhere"
        );
        assert_eq!(
            pending[1]
                .partials
                .iter()
                .map(|e| e.index.get())
                .collect::<Vec<_>>(),
            vec![1],
            "while the disputed input drops them"
        );
        assert_eq!(
            metrics
                .mpc_partial_sig_nonce_mismatch_total
                .with_label_values(&[&test_address(1).to_string()])
                .get(),
            1,
            "the disputed input alone is dropped"
        );
    }

    #[tokio::test]
    async fn test_collect_keeps_partials_from_a_peer_on_our_nonce() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let peer = test_address(1);
        let mut rng = StdRng::seed_from_u64(4242);

        let responses = HashMap::from([(peer, Ok(vec![eval_at(2, S::rand(&mut rng))]))]);
        let nonces = HashMap::from([(peer, G::generator())]);
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![peer],
        )];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let st = &pending[0];
        let mut indices: Vec<u16> = st.partials.iter().map(|e| e.index.get()).collect();
        indices.sort_unstable();
        assert_eq!(
            indices,
            vec![1, 2],
            "an agreeing peer's shares must be used"
        );
        assert_eq!(
            metrics
                .mpc_partial_sig_nonce_mismatch_total
                .with_label_values(&[&peer.to_string()])
                .get(),
            0,
        );
    }

    #[tokio::test]
    async fn test_collect_drops_partials_from_a_peer_on_a_different_nonce() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let diverged = test_address(1);
        let mut rng = StdRng::seed_from_u64(90210);

        let responses = HashMap::from([(diverged, Ok(vec![eval_at(2, S::rand(&mut rng))]))]);
        let nonces = HashMap::from([(diverged, G::generator() + G::generator())]);
        let p2p = CannedP2PChannel {
            responses,
            nonces,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![diverged],
        )];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let st = &pending[0];
        assert_eq!(
            st.partials
                .iter()
                .map(|e| e.index.get())
                .collect::<Vec<_>>(),
            vec![1],
            "only the caller's own share may remain"
        );
        assert_eq!(
            metrics
                .mpc_partial_sig_nonce_mismatch_total
                .with_label_values(&[&diverged.to_string()])
                .get(),
            1,
        );
    }

    #[tokio::test]
    async fn test_collect_keeps_partials_from_a_peer_reporting_no_nonce() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let old_peer = test_address(1);
        let mut rng = StdRng::seed_from_u64(31337);

        let responses = HashMap::from([(old_peer, Ok(vec![eval_at(2, S::rand(&mut rng))]))]);
        let p2p = CannedP2PChannel {
            responses,
            ..Default::default()
        };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![old_peer],
        )];
        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(
            &p2p,
            &mut pending,
            deadline,
            &HashSet::new(),
            &metrics,
        )
        .await;

        let st = &pending[0];
        let mut indices: Vec<u16> = st.partials.iter().map(|e| e.index.get()).collect();
        indices.sort_unstable();
        assert_eq!(indices, vec![1, 2], "an unreported nonce is not a mismatch");
        assert_eq!(
            metrics
                .mpc_partial_sig_nonce_mismatch_total
                .with_label_values(&[&old_peer.to_string()])
                .get(),
            0,
        );
    }

    #[tokio::test]
    async fn test_sign_recovers_from_corrupt_local_share() {
        let setup = SigningTestSetup::new(7);
        let message = b"self-corrupt";
        let beacon = S::zero();
        let req_id = test_request_id();
        let mut rng = StdRng::seed_from_u64(31337);

        let (public_nonce, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, None);
        let mut corrupted = all_sigs[0].clone();
        corrupted[0].value = S::rand(&mut rng);
        setup.managers[0]
            .state
            .write()
            .unwrap()
            .partial_signing_outputs
            .insert(
                req_id,
                PartialSigningOutput::new(public_nonce, &beacon, message, None, corrupted),
            );

        let p2p = setup.mock_p2p_for(0);
        let metrics = test_metrics();
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &metrics,
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_early_exits_at_threshold_ignoring_hung_peers() {
        let setup = SigningTestSetup::new(7);
        let message = b"hung-peers";
        let beacon = S::zero();
        let req_id = test_request_id();
        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let mut responses = HashMap::new();
        responses.insert(test_address(1), all_sigs[1].clone());
        responses.insert(test_address(2), all_sigs[2].clone());
        let hanging: HashSet<Address> = [3usize, 4, 5, 6].into_iter().map(test_address).collect();
        let p2p = HangingP2PChannel { responses, hanging };

        let sig = tokio::time::timeout(
            Duration::from_secs(5),
            SigningManager::sign_one(
                &setup.managers[0],
                &p2p,
                req_id,
                message,
                0,
                &beacon,
                None,
                Duration::from_secs(30),
                &test_metrics(),
            ),
        )
        .await
        .expect("sign blocked on a hung peer instead of early-exiting at threshold")
        .unwrap();

        verify_schnorr(&setup.verifying_key, message, &sig);
    }

    #[tokio::test]
    async fn test_sign_too_many_invalid() {
        // n=4, t=2, f=1. All 3 peers return corrupt sigs.
        // aggregate_signatures uses first `threshold` sigs, so caller(valid) +
        // any_peer(corrupted) → InvalidSignature.
        // RS: 4 sigs, 3 bad, capacity=(4-2)/2=1 → TooManyErrors.
        // No remaining peers → TooManyInvalidSignatures.
        let setup = SigningTestSetup::new(4);
        let message = b"too-many";
        let beacon = S::zero();
        let req_id = test_request_id();

        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p =
            canned_p2p_with_corruptions(&all_sigs, &[1, 2, 3], &mut StdRng::seed_from_u64(777));

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(
            matches!(result, Err(SigningError::TooManyInvalidSignatures { .. })),
            "expected TooManyInvalidSignatures, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_sign_timeout() {
        // All peers fail → never reach threshold → timeout.
        let setup = SigningTestSetup::new(4);
        let message = b"timeout";
        let beacon = S::zero();
        let req_id = test_request_id();

        let mut responses = HashMap::new();
        for i in 1..4usize {
            responses.insert(
                test_address(i),
                Err(ChannelError::RequestFailed("unavailable".into())),
            );
        }
        let p2p = CannedP2PChannel {
            responses,
            ..Default::default()
        };

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_millis(1), // very short timeout
            &test_metrics(),
        )
        .await;

        assert!(
            matches!(result, Err(SigningError::Timeout { .. })),
            "expected Timeout, got: {:?}",
            result.err()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_sign_deadline_bounds_collection_round_with_hung_peers() {
        // Below threshold (caller + 1 healthy peer < t = 3), the poll round is
        // dominated by hung peers. The round must stop at the signing deadline
        // instead of draining the hung peers' per-probe budgets, so the total
        // time is the deadline, not PARTIAL_SIGS_CALL_TIMEOUT x attempts.
        let setup = SigningTestSetup::new(7);
        let message = b"hung-below-threshold";
        let beacon = S::zero();
        let req_id = test_request_id();
        let (_, all_sigs) = setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let mut responses = HashMap::new();
        responses.insert(test_address(1), all_sigs[1].clone());
        let hanging: HashSet<Address> =
            [2usize, 3, 4, 5, 6].into_iter().map(test_address).collect();
        let p2p = HangingP2PChannel { responses, hanging };

        let deadline = Duration::from_secs(2);
        let started = Instant::now();
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            deadline,
            &test_metrics(),
        )
        .await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(SigningError::Timeout { .. })),
            "expected Timeout, got: {:?}",
            result.err()
        );
        assert!(
            elapsed < PARTIAL_SIGS_CALL_TIMEOUT,
            "collection round was not bounded by the deadline: {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_sign_cools_down_failing_peer() {
        // A peer whose poll hard-fails must not be re-polled every round for
        // the duration of the cooldown, while healthy-but-empty peers keep
        // being polled each round.
        let setup = SigningTestSetup::new(4);
        let message = b"cooldown";
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let failing = test_address(1);
        let p2p = CountingP2PChannel {
            fail: [failing].into_iter().collect(),
            not_ready: HashSet::new(),
            calls: Mutex::new(HashMap::new()),
        };

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(5),
            &test_metrics(),
        )
        .await;
        assert!(
            matches!(result, Err(SigningError::Timeout { .. })),
            "expected Timeout, got: {:?}",
            result.err()
        );

        let calls = p2p.calls.lock().unwrap();
        let failing_calls = calls.get(&failing).copied().unwrap_or(0);
        let healthy_calls = calls.get(&test_address(2)).copied().unwrap_or(0);
        // One round's attempts (first try + retries), then cooldown.
        assert!(
            failing_calls <= 1 + PARTIAL_SIGS_CALL_RETRIES,
            "failing peer was polled {failing_calls} times despite the cooldown"
        );
        assert!(
            healthy_calls > failing_calls,
            "healthy peer ({healthy_calls} polls) should be polled across rounds, \
             failing peer ({failing_calls} polls) should not"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_sign_keeps_polling_not_ready_peers() {
        // An explicit not-ready answer means "up but still reconciling"
        // (e.g. right after an epoch flip) — the peer must be re-polled
        // every round, not cooled down.
        let setup = SigningTestSetup::new(4);
        let message = b"unavailable";
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let reconciling = test_address(1);
        let p2p = CountingP2PChannel {
            fail: HashSet::new(),
            not_ready: [reconciling].into_iter().collect(),
            calls: Mutex::new(HashMap::new()),
        };

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(5),
            &test_metrics(),
        )
        .await;
        assert!(result.is_err());

        let calls = p2p.calls.lock().unwrap();
        let reconciling_calls = calls.get(&reconciling).copied().unwrap_or(0);
        assert!(
            reconciling_calls > 1 + PARTIAL_SIGS_CALL_RETRIES,
            "an unavailable peer must keep being polled across rounds, \
             got {reconciling_calls} poll(s)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_sign_waits_out_cooldowns_instead_of_storming_a_down_fleet() {
        // With every peer hard-failing and the deadline shorter than the
        // cooldown, each peer gets exactly one round of polls; the call then
        // sleeps rather than re-polling the down fleet every backoff cycle.
        let setup = SigningTestSetup::new(4);
        let message = b"all-cooling";
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let p2p = CountingP2PChannel {
            fail: (1..4usize).map(test_address).collect(),
            not_ready: HashSet::new(),
            calls: Mutex::new(HashMap::new()),
        };

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            PARTIAL_SIGS_PEER_COOLDOWN / 2,
            &test_metrics(),
        )
        .await;
        assert!(result.is_err());

        let calls = p2p.calls.lock().unwrap();
        for i in 1..4usize {
            let peer_calls = calls.get(&test_address(i)).copied().unwrap_or(0);
            assert_eq!(
                peer_calls,
                1 + PARTIAL_SIGS_CALL_RETRIES,
                "peer {i} must be polled exactly one round, not stormed"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_sign_retries_cooled_peers_once_their_cooldown_lapses() {
        // With a deadline longer than the cooldown, the call sleeps to the
        // cooldown expiry and then re-polls the fleet at cooldown cadence.
        let setup = SigningTestSetup::new(4);
        let message = b"cooldown-cadence";
        let beacon = S::zero();
        let req_id = test_request_id();
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));

        let p2p = CountingP2PChannel {
            fail: (1..4usize).map(test_address).collect(),
            not_ready: HashSet::new(),
            calls: Mutex::new(HashMap::new()),
        };

        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            PARTIAL_SIGS_PEER_COOLDOWN * 2 + Duration::from_secs(1),
            &test_metrics(),
        )
        .await;
        assert!(result.is_err());

        let calls = p2p.calls.lock().unwrap();
        for i in 1..4usize {
            let peer_calls = calls.get(&test_address(i)).copied().unwrap_or(0);
            assert!(
                peer_calls > 1 + PARTIAL_SIGS_CALL_RETRIES,
                "peer {i} must be re-polled after its cooldown lapsed, \
                 got {peer_calls} poll(s)"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_peer_cooldown_expires_and_clears_on_success() {
        let cooldowns = PeerCooldowns::new();
        let peer = test_address(1);

        cooldowns.record_failure(peer);
        assert!(cooldowns.is_cooling(&peer, Instant::now()));

        tokio::time::advance(PARTIAL_SIGS_PEER_COOLDOWN + Duration::from_millis(1)).await;
        assert!(!cooldowns.is_cooling(&peer, Instant::now()));

        cooldowns.record_failure(peer);
        cooldowns.record_success(&peer);
        assert!(!cooldowns.is_cooling(&peer, Instant::now()));
    }

    async fn finalize_with(
        data: &AggregateTestData,
        message: &[u8],
        partials: Vec<Eval<S>>,
        flagged: &HashSet<ShareIndex>,
    ) -> FinalizeOutcome {
        let mut st = InputSigningState::new(
            test_request_id(),
            message.to_vec(),
            data.public_nonce,
            &data.beacon,
            None,
            partials,
            data.t as usize,
            HashSet::new(),
        );
        try_finalize_signature(&mut st, data.t, &data.vk, true, flagged, &test_metrics()).await
    }

    #[tokio::test]
    async fn test_flagged_indices_only_add_aggregation_candidates() {
        let message = b"flagged";
        let mut data = build_aggregate_test_data(77, message);
        let honest = data.partial_sigs[..3].to_vec();
        let garbage: Vec<Eval<S>> = data.partial_sigs[3..5]
            .iter()
            .map(|e| eval_at(e.index.get(), S::rand(&mut data.rng)))
            .collect();
        let late_honest = data.partial_sigs[5].clone();
        let garbage_first: Vec<Eval<S>> = garbage.iter().chain(&honest).cloned().collect();
        let honest_first: Vec<Eval<S>> = honest.iter().chain(&garbage).cloned().collect();
        let flags = |indices: &[u16]| -> HashSet<ShareIndex> {
            indices.iter().map(|&i| share_index(i)).collect()
        };

        assert!(matches!(
            finalize_with(&data, message, garbage_first.clone(), &flags(&[])).await,
            FinalizeOutcome::Exhausted
        ));
        match finalize_with(&data, message, garbage_first.clone(), &flags(&[4, 5])).await {
            FinalizeOutcome::Done(sig, mismatched) => {
                verify_schnorr(&data.vk, message, &sig);
                assert!(mismatched.is_empty());
            }
            _ => panic!("flagging the garbage indices must complete the input"),
        }
        for wrong in [flags(&[1]), flags(&[1, 2, 3])] {
            match finalize_with(&data, message, honest_first.clone(), &wrong).await {
                FinalizeOutcome::Done(sig, _) => verify_schnorr(&data.vk, message, &sig),
                _ => panic!("a wrong flag must never remove a candidate"),
            }
        }
        let one_flagged: Vec<Eval<S>> = garbage_first
            .iter()
            .cloned()
            .chain(std::iter::once(late_honest))
            .collect();
        match finalize_with(&data, message, one_flagged, &flags(&[4])).await {
            FinalizeOutcome::Done(sig, mismatched) => {
                verify_schnorr(&data.vk, message, &sig);
                assert_eq!(mismatched, vec![share_index(5)]);
            }
            _ => panic!("erasing the flagged index must let recovery correct the other"),
        }
    }

    #[test]
    fn test_aggregate_with_recovery_correctable() {
        // t=3, 6 sigs with 1 corrupted → RS corrects and names the mismatching index.
        let message = b"rs-test";
        let mut data = build_aggregate_test_data(123, message);

        data.partial_sigs[0].value = S::rand(&mut data.rng);
        let corrupted_index = data.partial_sigs[0].index;

        let (sig, mismatched) = aggregate_signatures_with_recovery(
            message,
            &data.public_nonce,
            &data.beacon,
            &data.partial_sigs,
            data.t,
            &data.vk,
            None,
        )
        .unwrap();

        verify_schnorr(&data.vk, message, &sig);
        assert_eq!(
            mismatched,
            vec![corrupted_index],
            "recovery must identify exactly the corrupted share index"
        );
    }

    #[test]
    fn test_aggregate_with_recovery_too_many_errors() {
        // t=3, 6 sigs with 2 corrupted → RS capacity (6-3)/2=1, can't correct 2.
        let message = b"rs-fail";
        let mut data = build_aggregate_test_data(456, message);

        data.partial_sigs[0].value = S::rand(&mut data.rng);
        data.partial_sigs[1].value = S::rand(&mut data.rng);

        let result = aggregate_signatures_with_recovery(
            message,
            &data.public_nonce,
            &data.beacon,
            &data.partial_sigs,
            data.t,
            &data.vk,
            None,
        );

        assert!(
            matches!(result, Err(FastCryptoError::TooManyErrors(_))),
            "expected TooManyErrors, got: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_sign_pool_exhausted_with_next_batch() {
        // Exhaust batch 0, set next_batch, verify sign() advances to batch 1.
        let setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        setup.exhaust_pool();
        setup.set_next_batch_on_all();
        setup.advance_peers_to_next_batch(0);

        let req_id = Address::new([0xFF; 32]);
        // Use the first global index of batch 1.
        setup.prepare_all(b"swap", &S::zero(), req_id, batch_size, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let sig = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            b"swap",
            batch_size, // first presig of batch 1
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        verify_schnorr(&setup.verifying_key, b"swap", &sig);
        assert_eq!(setup.managers[0].batch_index(), 1);
        assert!(!setup.managers[0].has_next_batch());
    }

    /// `set_next_batch` discards a refill result that is not newer than the
    /// latest installed batch, so a duplicated generation of an old batch
    /// can never be staged for installation.
    #[tokio::test]
    async fn test_stale_refill_result_is_discarded() {
        let setup = SigningTestSetup::new(4);

        // Batch 0 is already installed, so a refill result for batch 0 is
        // stale and must be dropped.
        let presigs = setup.build_presignatures().swap_remove(0);
        setup.managers[0].set_next_batch(0, presigs, IdentityInputs::for_test());
        assert!(!setup.managers[0].has_next_batch());

        // A result for the actual next batch is accepted.
        let presigs = setup.build_presignatures().swap_remove(0);
        setup.managers[0].set_next_batch(1, presigs, IdentityInputs::for_test());
        assert!(setup.managers[0].has_next_batch());
    }

    #[tokio::test]
    async fn test_stale_prefetch_is_not_relabeled_as_next_batch() {
        let mut setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        setup.refill_rx.borrow_and_update();

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 0,
            pool: vec![],
            identity: PresigBatchIdentity::for_test(),
        });

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"stale",
            batch_size, // first index of the not-yet-generated batch 1
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        // The stale prefetch is dropped rather than installed: signing
        // fails safe and a refill for the right batch is requested.
        assert!(matches!(result, Err(SigningError::PoolExhausted)));
        assert!(!setup.managers[0].has_next_batch());
        assert!(setup.refill_rx.has_changed().unwrap());
        assert_eq!(*setup.refill_rx.borrow(), 1);
    }

    #[tokio::test]
    async fn test_future_prefetch_is_kept_but_not_installed() {
        let mut setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        setup.refill_rx.borrow_and_update();

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 2,
            pool: vec![],
            identity: PresigBatchIdentity::for_test(),
        });

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"future",
            batch_size, // first index of the missing batch 1
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
        assert!(setup.managers[0].has_next_batch());
        assert!(setup.refill_rx.has_changed().unwrap());
        assert_eq!(*setup.refill_rx.borrow(), 1);
    }

    #[test]
    fn test_available_end_index_ignores_non_contiguous_prefetch() {
        let setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        assert_eq!(setup.managers[0].available_presig_end_index(), batch_size);

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 2,
            pool: vec![None; 5],
            identity: PresigBatchIdentity::for_test(),
        });
        assert_eq!(setup.managers[0].available_presig_end_index(), batch_size);

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 1,
            pool: vec![None; 5],
            identity: PresigBatchIdentity::for_test(),
        });
        assert_eq!(
            setup.managers[0].available_presig_end_index(),
            batch_size + 5
        );
    }

    #[tokio::test]
    async fn test_sign_pool_exhausted_no_next_batch() {
        // Exhaust pool without setting next_batch → PoolExhausted.
        let setup = SigningTestSetup::new(4);
        setup.exhaust_pool();

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"fail",
            0,
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_pool_miss_triggers_refill_signal() {
        let mut setup = SigningTestSetup::new(4);
        let pool_size = setup.managers[0].initial_presig_count() as u64;

        // Mark the refill_rx as seen so we can detect the next change.
        setup.refill_rx.borrow_and_update();

        // Request a presig index beyond the pool (no next_batch set).
        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"beyond",
            pool_size + 100, // beyond all batches
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
        assert!(
            setup.refill_rx.has_changed().unwrap(),
            "refill signal should have been sent on pool miss"
        );
        assert_eq!(*setup.refill_rx.borrow(), 1); // batch_index 0 + 1
    }

    #[test]
    fn test_refill_threshold_triggers_signal() {
        // Consuming past 50% threshold sends refill signal via watch channel.
        let setup = SigningTestSetup::new(4);
        let pool_size = setup.managers[0].initial_presig_count();
        let refill_at = pool_size / crate::constants::PRESIG_REFILL_DIVISOR;
        let beacon = S::zero();

        // Consume presignatures on manager 0 until we cross the threshold.
        for i in 0..(pool_size - refill_at) {
            let mgr = &setup.managers[0];
            let mut state = mgr.state.write().unwrap();
            let batch = state.batches.last_mut().unwrap();
            let presig = batch.pool[i].take().unwrap();
            let _ = generate_partial_signatures(
                b"msg",
                presig,
                &beacon,
                &mgr.config.key_shares,
                &mgr.config.verifying_key,
                None,
            )
            .unwrap();
            // Simulate the threshold check that sign() does.
            let latest = state.batches.last().unwrap();
            let remaining = latest.remaining();
            let threshold = latest.pool.len() / mgr.config.refill_divisor;
            if remaining <= threshold {
                let _ = mgr.refill_tx.send(latest.batch_index + 1);
            }
        }

        assert!(setup.refill_rx.has_changed().unwrap());
        assert_eq!(*setup.refill_rx.borrow(), 1);
    }

    #[tokio::test]
    async fn test_pool_exhausted() {
        let setup = SigningTestSetup::new(4);
        setup.exhaust_pool();

        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"fail",
            0,
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    /// Consume every presig through `sign()` so that the natural prune
    /// path fires, then verify the next call returns `PoolExhausted`
    /// instead of panicking.
    #[tokio::test]
    async fn test_sign_prunes_batch_then_pool_exhausted() {
        let setup = SigningTestSetup::new(4);
        let pool_size = setup.managers[0].initial_presig_count();
        let beacon = S::zero();
        let p2p = setup.mock_p2p_for(0);

        // Sign every presig in the batch through the normal sign() path.
        for i in 0..pool_size {
            let req = Address::new([i as u8; 32]);
            setup.prepare_all(b"drain", &beacon, req, i as u64, Some(0));
            let result = SigningManager::sign_one(
                &setup.managers[0],
                &p2p,
                req,
                b"drain",
                i as u64,
                &beacon,
                None,
                Duration::from_secs(30),
                &test_metrics(),
            )
            .await;
            assert!(result.is_ok(), "sign {i} should succeed");
        }

        // The last batch is always retained (as an anchor for computing the
        // next batch's start index), but all its presigs should be consumed.
        assert_eq!(
            setup.managers[0].state.read().unwrap().batches.len(),
            1,
            "last batch should be retained"
        );
        assert_eq!(setup.managers[0].presignatures_remaining(), 0);

        // The next sign should return PoolExhausted, not panic.
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0xFF; 32]),
            b"one-more",
            pool_size as u64,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    /// Signing with an index from a previous batch should succeed as long
    /// as the batch hasn't been fully consumed and pruned.
    #[tokio::test]
    async fn test_sign_from_previous_batch_succeeds() {
        let setup = SigningTestSetup::new(4);

        // Advance all managers to batch 1 (batch 0 is retained).
        setup.set_next_batch_on_all();
        setup.advance_peers_to_next_batch(0);
        {
            let mut state = setup.managers[0].state.write().unwrap();
            let latest = state.batches.last().unwrap();
            let next_start = latest.end_index();
            let next_batch_index = latest.batch_index + 1;
            let next = state.next_batch.take().unwrap();
            state.batches.push(PresigBatch {
                pool: next.pool,
                start_index: next_start,
                batch_index: next_batch_index,
            });
        }

        // Sign with an index from batch 0 — should succeed because batch 0
        // is still retained with unconsumed presigs.
        let beacon = S::zero();
        let req = Address::new([0x01; 32]);
        setup.prepare_all(b"old-batch", &beacon, req, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req,
            b"old-batch",
            0, // batch 0, manager has both batch 0 and 1
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(
            result.is_ok(),
            "signing from a retained previous batch should succeed"
        );
    }

    #[tokio::test]
    async fn test_sign_presig_already_consumed() {
        let setup = SigningTestSetup::new(4);
        let beacon = S::zero();

        // First sign with presig 0 — succeeds.
        let req1 = Address::new([0x01; 32]);
        setup.prepare_all(b"msg1", &beacon, req1, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let result1 = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req1,
            b"msg1",
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;
        assert!(result1.is_ok());

        // Second sign with same presig index 0 but different request ID.
        // Presig was already taken — should fail.
        let req2 = Address::new([0x02; 32]);
        let result2 = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req2,
            b"msg2",
            0, // same index, already consumed
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;
        assert!(matches!(result2, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_sign_batch_too_far_ahead() {
        let setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;

        // Target index maps to batch 2, but manager is on batch 0 with no next_batch.
        let p2p = setup.mock_p2p_for(0);
        let result = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            Address::new([0x01; 32]),
            b"far-ahead",
            batch_size * 2, // batch 2
            &S::zero(),
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await;

        assert!(matches!(result, Err(SigningError::PoolExhausted)));
    }

    #[tokio::test]
    async fn test_sign_retry_reuses_cached_partial_sigs() {
        let setup = SigningTestSetup::new(4);
        let message = b"retry-test";
        let beacon = S::zero();
        let req_id = test_request_id();

        // Record presig pool size before first sign.
        let pool_before = setup.managers[0].presignatures_remaining();

        // First sign — consumes one presig, caches partial sigs.
        setup.prepare_all(message, &beacon, req_id, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        let sig1 = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        let pool_after_first = setup.managers[0].presignatures_remaining();
        assert_eq!(
            pool_after_first,
            pool_before - 1,
            "first sign should consume one presig"
        );

        // Second sign with SAME request_id — should reuse cached partial sigs.
        let sig2 = SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req_id,
            message,
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        let pool_after_second = setup.managers[0].presignatures_remaining();
        assert_eq!(
            pool_after_second, pool_after_first,
            "retry should NOT consume another presig"
        );

        // Both calls produce the same signature.
        assert_eq!(
            sig1.to_byte_array(),
            sig2.to_byte_array(),
            "retry should produce identical signature"
        );

        // Verify the signature is valid.
        verify_schnorr(&setup.verifying_key, message, &sig1);
    }

    #[tokio::test]
    async fn test_sign_different_request_consumes_new_presig() {
        let setup = SigningTestSetup::new(4);
        let beacon = S::zero();

        let req1 = Address::new([0x10; 32]);
        let req2 = Address::new([0x20; 32]);

        let pool_before = setup.managers[0].presignatures_remaining();

        // First request.
        setup.prepare_all(b"msg1", &beacon, req1, 0, Some(0));
        let p2p = setup.mock_p2p_for(0);
        SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req1,
            b"msg1",
            0,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        // Second request with different ID.
        setup.prepare_all(b"msg2", &beacon, req2, 1, Some(0));
        SigningManager::sign_one(
            &setup.managers[0],
            &p2p,
            req2,
            b"msg2",
            1,
            &beacon,
            None,
            Duration::from_secs(30),
            &test_metrics(),
        )
        .await
        .unwrap();

        let pool_after = setup.managers[0].presignatures_remaining();
        assert_eq!(
            pool_after,
            pool_before - 2,
            "two different requests should consume two presigs"
        );
    }
}
