// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::error::FastCryptoError;
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
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::communication::P2PChannel;
use crate::communication::with_timeout_and_retry_budget;
use crate::metrics::MPC_LABEL_SIGNING;
use crate::metrics::Metrics;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::PartialSigningOutput;
use crate::mpc::types::SigningError;
use crate::mpc::types::SigningResult;

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

/// How long a peer whose poll hard-failed (connect/TLS/timeout) is skipped
/// before being probed again. Bounds the cost of dead peers to one probe per
/// cooldown window instead of one per round per concurrent signing task.
const PARTIAL_SIGS_PEER_COOLDOWN: Duration = Duration::from_secs(30);

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
    refill_divisor: usize,
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
}

pub struct SigningManager {
    config: Arc<SigningEpochConfig>,
    state: RwLock<SigningPoolState>,
    refill_tx: Arc<watch::Sender<u32>>,
    peer_cooldowns: PeerCooldowns,
    /// Peers that contributed a provably bad partial signature this epoch
    /// (identified against the RS-recovered polynomial in
    /// [`try_finalize_signature`]). Their partials are excluded from polling
    /// and merging for the rest of the epoch: one bad share inside the first
    /// `threshold` slots fails plain aggregation for every input, so a
    /// misbehaving peer would otherwise force every signature through the
    /// (more partials, more rounds) recovery path indefinitely. The set
    /// resets on reconfig with the manager itself.
    bad_share_peers: Mutex<HashSet<Address>>,
}

/// Peers whose `get_partial_signatures` poll recently hard-failed
/// (connect/TLS/timeout), and when each may be probed again.
///
/// Shared across all concurrent signing tasks of an epoch so a dead peer
/// detected by one task is skipped by all of them instead of being
/// rediscovered per task per round. A cooling peer is only excluded from
/// polling; it stays in each input's `peers_remaining`, so it contributes
/// again as soon as a post-cooldown probe succeeds.
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
}

fn presig_pool_fingerprint<'a>(nonces: impl Iterator<Item = &'a G>) -> String {
    use fastcrypto::hash::HashFunction;
    let mut hasher = fastcrypto::hash::Blake2b256::default();
    for nonce in nonces {
        hasher.update(bcs::to_bytes(nonce).expect("serialization should always succeed"));
    }
    hex::encode(&hasher.finalize().digest[..8])
}

impl SigningManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        presignatures: Presignatures,
        batch_index: u32,
        batch_start_index: u64,
        refill_divisor: usize,
        refill_tx: Arc<watch::Sender<u32>>,
    ) -> Self {
        let pool: Vec<Option<(Vec<S>, G)>> = presignatures.map(Some).collect();
        tracing::info!(
            "Presig batch installed: address={address}, batch_index={batch_index}, \
             start_index={batch_start_index}, size={}, fingerprint={}",
            pool.len(),
            presig_pool_fingerprint(pool.iter().flatten().map(|(_, nonce)| nonce)),
        );
        let batch = PresigBatch {
            pool,
            start_index: batch_start_index,
            batch_index,
        };
        Self {
            config: Arc::new(SigningEpochConfig {
                address,
                committee,
                threshold,
                key_shares,
                verifying_key,
                refill_divisor,
            }),
            state: RwLock::new(SigningPoolState {
                batches: vec![batch],
                partial_signing_outputs: HashMap::new(),
                next_batch: None,
            }),
            refill_tx,
            peer_cooldowns: PeerCooldowns::new(),
            bad_share_peers: Mutex::new(HashSet::new()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_recovered(
        address: Address,
        committee: Committee,
        threshold: u16,
        key_shares: avss::SharesForNode,
        verifying_key: G,
        retained: Vec<(Presignatures, u32, u64)>,
        num_consumed: u64,
        pending: &HashSet<u64>,
        refill_divisor: usize,
        refill_tx: Arc<watch::Sender<u32>>,
    ) -> anyhow::Result<Self> {
        let mut batches = Vec::with_capacity(retained.len());
        let mut covered_pending = 0usize;
        for (presignatures, batch_index, start_index) in retained {
            let pool: Vec<Option<(Vec<S>, G)>> = presignatures
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
                "Recovered presig batch installed: address={address}, batch_index={batch_index}, \
                 start_index={start_index}, size={}, enabled={}, fingerprint={}",
                pool.len(),
                pool.iter().filter(|s| s.is_some()).count(),
                presig_pool_fingerprint(pool.iter().flatten().map(|(_, nonce)| nonce)),
            );
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
        Ok(Self {
            config: Arc::new(SigningEpochConfig {
                address,
                committee,
                threshold,
                key_shares,
                verifying_key,
                refill_divisor,
            }),
            state: RwLock::new(SigningPoolState {
                batches,
                partial_signing_outputs: HashMap::new(),
                next_batch: None,
            }),
            refill_tx,
            peer_cooldowns: PeerCooldowns::new(),
            bad_share_peers: Mutex::new(HashSet::new()),
        })
    }

    /// Stage a refill result for installation once signing advances past the
    /// current batches. `batch_index` must be the index the presignatures
    /// were generated for; a result that is not strictly newer than the
    /// latest installed batch is discarded, since installing it under a
    /// later index would re-serve already-consumed nonces.
    pub fn set_next_batch(&self, batch_index: u32, presignatures: Presignatures) {
        let pool: Vec<Option<(Vec<S>, G)>> = presignatures.map(Some).collect();
        let fingerprint = presig_pool_fingerprint(pool.iter().flatten().map(|(_, nonce)| nonce));
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
            return;
        }
        if let Some(existing) = &state.next_batch {
            tracing::warn!(
                "Replacing prefetched presig batch {} with batch {batch_index}",
                existing.batch_index,
            );
        }
        tracing::info!(
            "Presig batch prefetched: address={}, batch_index={batch_index}, size={}, \
             fingerprint={fingerprint}",
            self.config.address,
            pool.len(),
        );
        state.next_batch = Some(PrefetchedBatch { batch_index, pool });
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

    pub fn handle_get_partial_signatures_request(
        &self,
        request: &GetPartialSignaturesRequest,
    ) -> SigningResult<GetPartialSignaturesResponse> {
        let state = self.state.read().unwrap();
        let partial_sigs = request
            .signing_ids
            .iter()
            .filter_map(|id| {
                state
                    .partial_signing_outputs
                    .get(id)
                    .map(|output| (*id, output.partial_sigs.clone()))
            })
            .collect();
        Ok(GetPartialSignaturesResponse { partial_sigs })
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
                Ok((public_nonce, partials)) => {
                    let contributors = partials.iter().map(|e| (e.index, self_address)).collect();
                    pending.push(InputSigningState {
                        signing_id: input.signing_id,
                        message: input.message,
                        public_nonce,
                        derivation_address: input.derivation_address,
                        partials,
                        contributors,
                        peers_remaining: all_peers.clone(),
                    })
                }
                Err(e) => {
                    let _ = result_tx.send((input.signing_id, Err(e)));
                }
            }
        }
        let _collection_timer = metrics
            .mpc_sign_collection_duration_seconds
            .with_label_values(&[MPC_LABEL_SIGNING])
            .start_timer();
        let mut backoff = PARTIAL_SIGS_COLLECTION_POLL_BACKOFF;
        while !pending.is_empty() {
            let mut i = 0;
            while i < pending.len() {
                let st = &pending[i];
                let peers_exhausted = st.peers_remaining.is_empty();
                if st.partials.len() < threshold as usize && !peers_exhausted {
                    i += 1;
                    continue;
                }
                let params = AggregationParams {
                    message: &st.message,
                    public_nonce: &st.public_nonce,
                    beacon_value,
                    threshold,
                    verifying_key: &verifying_key,
                    derivation_address: st.derivation_address.as_ref(),
                };
                match try_finalize_signature(&params, &st.partials, peers_exhausted, metrics).await
                {
                    FinalizeOutcome::NeedMore => i += 1,
                    FinalizeOutcome::Done(sig, bad_indices) => {
                        let st = pending.swap_remove(i);
                        let _ = result_tx.send((st.signing_id, Ok(sig)));
                        if !bad_indices.is_empty() {
                            self.blame_bad_shares(
                                &bad_indices,
                                &st.contributors,
                                &mut pending,
                                metrics,
                            );
                        }
                    }
                    FinalizeOutcome::Failed(e) => {
                        let st = pending.swap_remove(i);
                        let _ = result_tx.send((st.signing_id, Err(e)));
                    }
                }
            }
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
                .collect_partial_sigs_from_peers(p2p_channel, &mut pending, deadline, metrics)
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
                tracing::info!(
                    "Cache hit for {signing_id} (global_presig_index={global_presig_index}), \
                     reusing cached partial sigs (batch_index={})",
                    state.batches.last().map_or(0, |b| b.batch_index),
                );
                CacheOrPresig::Cached(existing.public_nonce, existing.partial_sigs.clone())
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
                    // Index not found in any current batch; try to swap in
                    // the prefetched next batch. Only a prefetch generated
                    // for exactly the next index may be installed: its
                    // position in the global index space is derived from the
                    // local install order, so relabeling any other result
                    // would silently bind the wrong nonces to these indices.
                    if let Some(latest) = state.batches.last() {
                        let next_start = latest.end_index();
                        let next_batch_index = latest.batch_index + 1;
                        match &state.next_batch {
                            Some(next) if next.batch_index == next_batch_index => {
                                let next = state.next_batch.take().expect("checked above");
                                tracing::info!(
                                    "Presig batch installed: address={}, batch_index={next_batch_index}, \
                                     start_index={next_start}, size={}, fingerprint={}",
                                    config.address,
                                    next.pool.len(),
                                    presig_pool_fingerprint(
                                        next.pool.iter().flatten().map(|(_, nonce)| nonce)
                                    ),
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
                                    // Stale: can only re-serve consumed
                                    // nonces. Drop it so the refill request
                                    // below fetches the right batch.
                                    state.next_batch = None;
                                } else {
                                    // A future batch: keep it, but the gap
                                    // means the expected batch was never
                                    // staged, so request it explicitly.
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
                    PartialSigningOutput {
                        public_nonce: result.0,
                        partial_sigs: result.1.clone(),
                    },
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
    partials: Vec<Eval<S>>,
    /// The peer whose value was accepted for each share index in `partials`
    /// (self for locally generated partials). Exactly one value per index is
    /// ever accepted — first writer wins — so when RS recovery proves an
    /// index's value bad, this map names the peer that sent it. The
    /// first-writer rule also keeps a peer claiming someone else's index
    /// from either failing aggregation (duplicate indices are rejected by
    /// `aggregate_signatures`) or shifting blame onto the index's real
    /// owner: whichever value is in the pool, its actual sender is recorded.
    contributors: HashMap<ShareIndex, Address>,
    /// Peers not yet merged for this input
    peers_remaining: HashSet<Address>,
}

enum FinalizeOutcome {
    /// Aggregation succeeded. The second field carries the share indices the
    /// RS-recovery path proved bad (empty on the clean path), so the caller
    /// can blame the contributing peers and scrub their partials from the
    /// other pending inputs.
    Done(SchnorrSignature, Vec<ShareIndex>),
    NeedMore,
    Failed(SigningError),
}

async fn try_finalize_signature(
    params: &AggregationParams<'_>,
    partials: &[Eval<S>],
    peers_exhausted: bool,
    metrics: &Metrics,
) -> FinalizeOutcome {
    let threshold = params.threshold;
    let need_more_or_fail = |collected: usize| {
        if peers_exhausted {
            FinalizeOutcome::Failed(SigningError::TooManyInvalidSignatures {
                collected,
                threshold,
            })
        } else {
            FinalizeOutcome::NeedMore
        }
    };
    if partials.len() < threshold as usize {
        return need_more_or_fail(partials.len());
    }
    let _timer = metrics
        .mpc_sign_aggregation_duration_seconds
        .with_label_values(&[MPC_LABEL_SIGNING])
        .start_timer();
    let message = params.message.to_vec();
    let nonce = *params.public_nonce;
    let beacon = *params.beacon_value;
    let vk = *params.verifying_key;
    let deriv = params.derivation_address.copied();
    let sigs = partials.to_vec();
    let agg = super::spawn_blocking(move || {
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
    .await;
    match agg {
        Ok(sig) => return FinalizeOutcome::Done(sig, Vec::new()),
        Err(FastCryptoError::InvalidSignature) => {} // fall through to RS recovery
        Err(e) => return FinalizeOutcome::Failed(SigningError::CryptoError(e.to_string())),
    }
    if partials.len().saturating_sub(threshold as usize) / 2 < 1 {
        return need_more_or_fail(partials.len());
    }
    let message = params.message.to_vec();
    let nonce = *params.public_nonce;
    let beacon = *params.beacon_value;
    let vk = *params.verifying_key;
    let deriv = params.derivation_address.copied();
    let sigs = partials.to_vec();
    let recovered = super::spawn_blocking(move || {
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
    .await;
    match recovered {
        Ok((sig, bad_indices)) => FinalizeOutcome::Done(sig, bad_indices),
        Err(FastCryptoError::TooManyErrors(_)) => need_more_or_fail(partials.len()),
        Err(e) => FinalizeOutcome::Failed(SigningError::CryptoError(e.to_string())),
    }
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
    /// its duration. Peers in cooldown or blamed for bad shares are skipped
    /// for the round entirely.
    async fn collect_partial_sigs_from_peers(
        &self,
        p2p_channel: &impl P2PChannel,
        pending: &mut [InputSigningState],
        deadline: Instant,
        metrics: &Metrics,
    ) -> bool {
        let threshold = self.config.threshold;
        let now = Instant::now();
        let mut peer_ids: HashMap<Address, Vec<Address>> = HashMap::new();
        {
            let bad_peers = self.bad_share_peers.lock().unwrap();
            for st in pending.iter() {
                for peer in &st.peers_remaining {
                    if !bad_peers.contains(peer) && !self.peer_cooldowns.is_cooling(peer, now) {
                        peer_ids.entry(*peer).or_default().push(st.signing_id);
                    }
                }
            }
        }
        if peer_ids.is_empty() {
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
                    // A concurrent signing task may have blamed this peer
                    // after the poll launched; its partials are not welcome.
                    if self.bad_share_peers.lock().unwrap().contains(&peer) {
                        continue;
                    }
                    self.peer_cooldowns.record_success(&peer);
                    for (signing_id, sigs) in response.partial_sigs {
                        if let Some(&i) = index.get(&signing_id)
                            && pending[i].peers_remaining.remove(&peer)
                        {
                            let st = &mut pending[i];
                            for eval in sigs {
                                // First writer wins per share index: a
                                // duplicate would fail aggregation outright
                                // (`aggregate_signatures` rejects duplicate
                                // indices), and recording the accepted
                                // value's actual sender is what keeps blame
                                // attribution honest.
                                if let std::collections::hash_map::Entry::Vacant(slot) =
                                    st.contributors.entry(eval.index)
                                {
                                    slot.insert(peer);
                                    st.partials.push(eval);
                                    progressed = true;
                                }
                            }
                        }
                    }
                    if pending
                        .iter()
                        .all(|st| st.partials.len() >= threshold as usize)
                    {
                        break;
                    }
                }
                Err(e) => {
                    self.peer_cooldowns.record_failure(peer);
                    metrics
                        .mpc_partial_sig_poll_failures_total
                        .with_label_values(&[&peer.to_string()])
                        .inc();
                    tracing::info!(
                        "Batched get_partial_signatures from {peer} failed \
                         (cooling down for {PARTIAL_SIGS_PEER_COOLDOWN:?}): {e}"
                    );
                }
            }
        }
        progressed
    }

    /// Excludes the peers that contributed provably bad shares (per the
    /// completed input's contributor map) for the rest of the epoch, and
    /// scrubs *all* of their contributions from the still-pending inputs:
    /// once one share from a peer is proven bad, its other shares are not
    /// trusted either, and removing them returns the remaining aggregations
    /// to the clean first-`threshold`-shares path instead of paying the RS
    /// recovery detour (more partials, more rounds) per input.
    fn blame_bad_shares(
        &self,
        bad_indices: &[ShareIndex],
        contributors: &HashMap<ShareIndex, Address>,
        pending: &mut [InputSigningState],
        metrics: &Metrics,
    ) {
        let self_address = self.config.address;
        let mut blamed: HashSet<Address> = HashSet::new();
        for idx in bad_indices {
            match contributors.get(idx) {
                Some(peer) if *peer == self_address => {
                    // Locally generated shares failing verification points at
                    // local state corruption, not a peer to exclude.
                    tracing::error!(
                        "Locally generated partial signature at share index {idx} is bad; \
                         local presig/key state may be corrupt"
                    );
                }
                Some(peer) => {
                    blamed.insert(*peer);
                    metrics
                        .mpc_bad_partial_sigs_total
                        .with_label_values(&[&peer.to_string()])
                        .inc();
                    tracing::warn!(
                        "Peer {peer} contributed a provably bad partial signature \
                         (share index {idx}); excluding its shares for the rest of the epoch"
                    );
                }
                None => tracing::warn!(
                    "RS recovery corrected a bad share at index {idx} with no recorded \
                     contributor"
                ),
            }
        }
        if blamed.is_empty() {
            return;
        }
        {
            let mut bad_peers = self.bad_share_peers.lock().unwrap();
            bad_peers.extend(blamed.iter().copied());
            tracing::warn!(
                "{} peer(s) now excluded for bad shares this epoch",
                bad_peers.len()
            );
        }
        for st in pending.iter_mut() {
            let scrub: HashSet<ShareIndex> = st
                .contributors
                .iter()
                .filter(|(_, peer)| blamed.contains(*peer))
                .map(|(idx, _)| *idx)
                .collect();
            st.partials.retain(|eval| !scrub.contains(&eval.index));
            st.contributors.retain(|_, peer| !blamed.contains(peer));
            // Drop blamed peers from the not-yet-merged set too, so inputs
            // that can no longer reach threshold fail fast as
            // TooManyInvalidSignatures instead of waiting out the deadline.
            for peer in &blamed {
                st.peers_remaining.remove(peer);
            }
        }
    }
}

struct AggregationParams<'a> {
    message: &'a [u8],
    public_nonce: &'a G,
    beacon_value: &'a S,
    threshold: u16,
    verifying_key: &'a G,
    derivation_address: Option<&'a DerivationAddress>,
}

/// Recovers the signing scalar from `partial_signatures` via Reed-Solomon
/// error correction and finalizes the signature. On success, also returns the
/// share indices whose contributed values disagree with the recovered
/// message polynomial: since the polynomial is verified end-to-end (the
/// finalized signature must verify against the group verifying key), a
/// mismatch at an index proves that share's contribution was bad, which is
/// what lets the caller blame the peer that sent it.
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
    let bad_indices = partial_signatures
        .iter()
        .filter(|e| poly.eval(e.index).value != e.value)
        .map(|e| e.index)
        .collect();
    Ok((sig, bad_indices))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::ChannelError;
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

    struct CannedP2PChannel {
        responses: HashMap<Address, ChannelResult<Vec<Eval<S>>>>,
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
        CannedP2PChannel { responses }
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
                })
                .map(Ok)
                .unwrap_or_else(|| Err(ChannelError::ClientNotFound(*party)))
        }
    }

    /// Counts polls per peer; `fail` peers error, the rest return an empty
    /// response (as a peer that has not signed yet would).
    struct CountingP2PChannel {
        fail: HashSet<Address>,
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
            } else {
                Ok(GetPartialSignaturesResponse {
                    partial_sigs: std::collections::BTreeMap::new(),
                })
            }
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
            let committee = Committee::new(members, 100, 3334u16, 0u16, 3333u16, 0);

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
                        presignatures,
                        0, // batch_index
                        0, // batch_start_index
                        crate::constants::PRESIG_REFILL_DIVISOR,
                        refill_tx.clone(),
                    );
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

        /// Have peers generate + store partial sigs so their RPC handlers work.
        /// `global_presig_index` is the global index used to locate the presig
        /// in the batch list. If `skip` is Some(i), that manager is skipped
        /// (use for the caller who will generate its own sigs inside `sign()`).
        /// Returns (public_nonce, Vec of per-party partial sigs).
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
                    PartialSigningOutput {
                        public_nonce: pn,
                        partial_sigs: sigs.clone(),
                    },
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
                mgr.set_next_batch(next_index, presignatures);
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

    /// Build 5 partial sigs from a (n=7, t=3, f=2) setup for RS recovery tests.
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
        for (i, sk_share) in sk_shares.iter().enumerate().take(5) {
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
        let committee = Committee::new(members, 100, 3334u16, 0u16, 3333u16, 0);

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
            vec![(new_batch(), 0, 0), (new_batch(), 1, size0)],
            num_consumed,
            &pending,
            crate::constants::PRESIG_REFILL_DIVISOR,
            Arc::new(refill_tx),
        )
        .unwrap();

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
            vec![(new_batch(), 1, size0)], // batch 0 dropped
            num_consumed,
            &pending, // pending {3} lives in the dropped batch 0
            crate::constants::PRESIG_REFILL_DIVISOR,
            Arc::new(refill_tx2),
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
        let beacon = S::zero();
        let req_id = test_request_id();

        setup.prepare_all(message, &beacon, req_id, 0, None);

        let resp = setup.managers[0]
            .handle_get_partial_signatures_request(&GetPartialSignaturesRequest {
                signing_ids: vec![req_id],
            })
            .unwrap();
        assert!(resp.partial_sigs.contains_key(&req_id));
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
                PartialSigningOutput {
                    public_nonce,
                    partial_sigs: vec![],
                },
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
                PartialSigningOutput {
                    public_nonce: pn,
                    partial_sigs: sigs,
                },
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

        // Whether recovery ran depends on arrival order (the clean path wins
        // when the corrupt response is not among the first `threshold`
        // partials), but blame must never land on an honest peer.
        let blamed = setup.managers[0].bad_share_peers.lock().unwrap().clone();
        assert!(
            blamed.is_subset(&[test_address(1)].into_iter().collect()),
            "only the corrupting peer may be blamed, got: {blamed:?}"
        );
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
        contributors: Vec<(u16, Address)>,
        peers_remaining: Vec<Address>,
    ) -> InputSigningState {
        InputSigningState {
            signing_id,
            message: b"m".to_vec(),
            public_nonce: G::generator(),
            derivation_address: None,
            partials,
            contributors: contributors
                .into_iter()
                .map(|(i, a)| (share_index(i), a))
                .collect(),
            peers_remaining: peers_remaining.into_iter().collect(),
        }
    }

    #[tokio::test]
    async fn test_blame_bad_shares_excludes_peer_and_scrubs_pending() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let bad_peer = test_address(1);
        let good_peer = test_address(2);
        let other_peer = test_address(3);

        // The completed input attributed share 2 to `bad_peer`.
        let done_contributors: HashMap<ShareIndex, Address> =
            [(share_index(2), bad_peer)].into_iter().collect();

        // A still-pending input holds two shares from `bad_peer` (2 and 3)
        // and one from `good_peer` (4).
        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![
                eval_at(2, S::zero()),
                eval_at(3, S::zero()),
                eval_at(4, S::zero()),
            ],
            vec![(2, bad_peer), (3, bad_peer), (4, good_peer)],
            vec![bad_peer, other_peer],
        )];

        mgr.blame_bad_shares(&[share_index(2)], &done_contributors, &mut pending, &metrics);

        assert!(mgr.bad_share_peers.lock().unwrap().contains(&bad_peer));
        let st = &pending[0];
        // Both of the blamed peer's shares are scrubbed, not only the caught
        // one.
        assert_eq!(
            st.partials
                .iter()
                .map(|e| e.index.get())
                .collect::<Vec<_>>(),
            vec![4]
        );
        assert!(!st.contributors.contains_key(&share_index(2)));
        assert!(!st.contributors.contains_key(&share_index(3)));
        assert!(st.contributors.contains_key(&share_index(4)));
        assert!(!st.peers_remaining.contains(&bad_peer));
        assert!(st.peers_remaining.contains(&other_peer));
        assert_eq!(
            metrics
                .mpc_bad_partial_sigs_total
                .with_label_values(&[&bad_peer.to_string()])
                .get(),
            1
        );
    }

    #[tokio::test]
    async fn test_collect_skips_blamed_peers() {
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let blamed = test_address(1);
        let healthy = test_address(2);
        mgr.bad_share_peers.lock().unwrap().insert(blamed);

        let p2p = CountingP2PChannel {
            fail: HashSet::new(),
            calls: Mutex::new(HashMap::new()),
        };
        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![],
            vec![],
            vec![blamed, healthy],
        )];

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(&p2p, &mut pending, deadline, &metrics)
            .await;

        let calls = p2p.calls.lock().unwrap();
        assert_eq!(
            calls.get(&blamed),
            None,
            "a blamed peer must not be polled"
        );
        assert_eq!(calls.get(&healthy), Some(&1));
    }

    #[tokio::test]
    async fn test_collect_first_writer_wins_per_share_index() {
        // A peer claiming a share index that is already in the pool must not
        // overwrite it (a duplicate would fail aggregation, and accepting the
        // second value would let a squatter shift blame onto the index's real
        // owner); its genuinely new shares are still accepted and attributed
        // to it.
        let setup = SigningTestSetup::new(4);
        let mgr = &setup.managers[0];
        let metrics = test_metrics();
        let self_address = mgr.config.address;
        let squatter = test_address(1);
        let mut rng = StdRng::seed_from_u64(4242);

        let responses = HashMap::from([(
            squatter,
            Ok(vec![
                eval_at(1, S::rand(&mut rng)),
                eval_at(5, S::rand(&mut rng)),
            ]),
        )]);
        let p2p = CannedP2PChannel { responses };

        let mut pending = vec![test_input_state(
            test_request_id(),
            vec![eval_at(1, S::zero())],
            vec![(1, self_address)],
            vec![squatter],
        )];

        let deadline = Instant::now() + Duration::from_secs(5);
        mgr.collect_partial_sigs_from_peers(&p2p, &mut pending, deadline, &metrics)
            .await;

        let st = &pending[0];
        let index_1_values: Vec<&S> = st
            .partials
            .iter()
            .filter(|e| e.index == share_index(1))
            .map(|e| &e.value)
            .collect();
        assert_eq!(index_1_values, vec![&S::zero()], "share 1 must keep the first-written value");
        assert_eq!(st.contributors.get(&share_index(1)), Some(&self_address));
        assert_eq!(st.contributors.get(&share_index(5)), Some(&squatter));
        assert_eq!(st.partials.len(), 2);
    }

    #[tokio::test]
    async fn test_sign_recovers_from_corrupt_local_share_without_blaming_peers() {
        // Corrupt the caller's own cached partial: local shares fill the
        // first aggregation slots, so the clean path always fails and the RS
        // recovery path runs deterministically. Recovery must identify the
        // local share and blame no peer.
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
                PartialSigningOutput {
                    public_nonce,
                    partial_sigs: corrupted,
                },
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
        assert!(
            setup.managers[0].bad_share_peers.lock().unwrap().is_empty(),
            "a corrupt local share must not get any peer excluded"
        );
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
        let p2p = CannedP2PChannel { responses };

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
        let hanging: HashSet<Address> = [2usize, 3, 4, 5, 6].into_iter().map(test_address).collect();
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

    #[test]
    fn test_aggregate_with_recovery_correctable() {
        // t=3, 5 sigs with 1 corrupted → RS corrects and names the bad index.
        let message = b"rs-test";
        let mut data = build_aggregate_test_data(123, message);

        data.partial_sigs[0].value = S::rand(&mut data.rng);
        let corrupted_index = data.partial_sigs[0].index;

        let (sig, bad_indices) = aggregate_signatures_with_recovery(
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
            bad_indices,
            vec![corrupted_index],
            "recovery must identify exactly the corrupted share index"
        );
    }

    #[test]
    fn test_aggregate_with_recovery_too_many_errors() {
        // t=3, 5 sigs with 2 corrupted → RS capacity (5-3)/2=1, can't correct 2.
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
        setup.managers[0].set_next_batch(0, presigs);
        assert!(!setup.managers[0].has_next_batch());

        // A result for the actual next batch is accepted.
        let presigs = setup.build_presignatures().swap_remove(0);
        setup.managers[0].set_next_batch(1, presigs);
        assert!(setup.managers[0].has_next_batch());
    }

    /// A prefetched batch tagged with an older index than the expected next
    /// batch must not be installed under the next batch's index range
    /// (regression test for the testnet incident where a duplicated
    /// batch-19 refill result was relabeled as batch 20, binding stale
    /// nonces to fresh global presig indices).
    #[tokio::test]
    async fn test_stale_prefetch_is_not_relabeled_as_next_batch() {
        let mut setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        setup.refill_rx.borrow_and_update();

        // Force a stale prefetch (tagged with the already-installed batch 0)
        // past the `set_next_batch` guard, straight into the state.
        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 0,
            pool: vec![],
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

    /// A prefetched batch tagged with a future index is kept (it will be
    /// needed later) but not installed in place of the expected next batch.
    #[tokio::test]
    async fn test_future_prefetch_is_kept_but_not_installed() {
        let mut setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        setup.refill_rx.borrow_and_update();

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 2,
            pool: vec![],
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

    /// `available_presig_end_index` only counts a prefetch that is
    /// contiguous with the installed range; a future-tagged one would
    /// report capacity across a coverage gap and suppress the leader's
    /// proactive refill.
    #[test]
    fn test_available_end_index_ignores_non_contiguous_prefetch() {
        let setup = SigningTestSetup::new(4);
        let batch_size = setup.managers[0].initial_presig_count() as u64;
        assert_eq!(setup.managers[0].available_presig_end_index(), batch_size);

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 2,
            pool: vec![None; 5],
        });
        assert_eq!(setup.managers[0].available_presig_end_index(), batch_size);

        setup.managers[0].state.write().unwrap().next_batch = Some(PrefetchedBatch {
            batch_index: 1,
            pool: vec![None; 5],
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
