// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::LEADER_TASK_TIMEOUT;
use super::LeaderService;
use super::parse_member_signature;
use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::leader::garbage_collection::PendingUtxoCleanup;
use crate::onchain::types::UtxoId;
use crate::onchain::types::WithdrawalTransaction;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::MpcInputSignaturesMessage;
use crate::withdrawals::WithdrawalBroadcastError;
use crate::withdrawals::WithdrawalBroadcastErrorKind;
use crate::withdrawals::WithdrawalTxSigning;
use fastcrypto::groups::secp256k1::schnorr::SchnorrPublicKey;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::proto::SignMpcInputSignaturesRequest;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio::task::JoinSet;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

pub(super) enum WithdrawalBroadcastOutcome {
    ConfirmedOnSui { utxo_ids: Vec<UtxoId> },
    WaitForNextBitcoinBlock,
}

pub(super) type WithdrawalBroadcastResult =
    Result<WithdrawalBroadcastOutcome, WithdrawalBroadcastError>;

fn should_reallocate_stale_presigs(
    signing_epoch: u64,
    current_epoch: u64,
    unsigned: &[u64],
) -> bool {
    signing_epoch != current_epoch && !unsigned.is_empty()
}

fn next_signing_chunk(unsigned: &[u64], chunk_size: usize) -> Vec<u64> {
    unsigned.iter().take(chunk_size.max(1)).copied().collect()
}

/// Derives the x-only verifying key the MPC signature for input `idx` must
/// validate against (the master key derived by the input's path), mirroring the
/// per-input check the committee re-runs at the commit cert
/// (`validate_and_sign_mpc_input_signatures`).
fn input_verifying_key(
    inner: &Hashi,
    txn: &WithdrawalTransaction,
    idx: u64,
) -> anyhow::Result<SchnorrPublicKey> {
    let input = txn
        .inputs
        .get(idx as usize)
        .ok_or_else(|| anyhow::anyhow!("input index {idx} out of range"))?;
    let input_pubkey = inner.deposit_pubkey(input.derivation_path.as_ref())?;
    SchnorrPublicKey::from_byte_array(&input_pubkey.serialize())
        .map_err(|e| anyhow::anyhow!("invalid verifying key for input {idx}: {e}"))
}

/// Merge one member's returned `(input_index, sig)` pairs into `union`, keeping
/// the first *valid* signature seen per index (`verify` gates each candidate, so
/// a single bad/buggy member cannot poison the chunk's commit cert).
/// Out-of-chunk and already-present indices are skipped. Returns `true` once
/// `union` covers every expected index, so the caller can stop waiting on the
/// remaining members.
fn merge_into_union(
    union: &mut BTreeMap<u64, SchnorrSignature>,
    expected: &BTreeSet<u64>,
    candidates: Vec<(u64, SchnorrSignature)>,
    verify: impl Fn(u64, &SchnorrSignature) -> bool,
) -> bool {
    for (idx, sig) in candidates {
        if !expected.contains(&idx) || union.contains_key(&idx) {
            continue;
        }
        if verify(idx, &sig) {
            union.insert(idx, sig);
        }
    }
    union.len() == expected.len()
}

/// Outcome of feeding one streamed partial signature into
/// [`ExpectedSignatureCollector::record`].
#[derive(Debug, PartialEq, Eq)]
enum CollectOutcome {
    /// The index was not requested; nothing was recorded. Its signature is not
    /// even parsed, so a malformed extra signature cannot fail the chunk.
    Ignored,
    /// A requested signature was recorded; more expected indices remain.
    Recorded,
    /// A requested signature was recorded and every expected index is now in
    /// hand — the caller can stop reading the stream.
    Complete,
}

/// Accumulates the MPC signatures for exactly the requested input indices as a
/// committee member streams them back (order-independent).
///
/// Unrequested indices are ignored *before* their signature is parsed, so an
/// old/buggy peer that signs extra inputs (possibly with malformed sigs) can
/// neither fail nor stall the chunk: `record` reports [`CollectOutcome::Complete`]
/// the moment the last requested index lands, letting the caller return without
/// draining the stream to EOF.
struct ExpectedSignatureCollector {
    expected: BTreeSet<u64>,
    collected: BTreeMap<u64, SchnorrSignature>,
}

impl ExpectedSignatureCollector {
    fn new(expected_indices: &[u64]) -> Self {
        Self {
            expected: expected_indices.iter().copied().collect(),
            collected: BTreeMap::new(),
        }
    }

    /// Records one streamed `(idx, signature)` pair:
    /// - unrequested `idx` -> [`CollectOutcome::Ignored`] (signature untouched);
    /// - requested `idx` seen before -> error (duplicate);
    /// - requested `idx` with a malformed/invalid signature -> error;
    /// - requested `idx` recorded -> [`CollectOutcome::Recorded`], or
    ///   [`CollectOutcome::Complete`] once all expected indices are present.
    fn record(&mut self, idx: u64, signature: &[u8]) -> anyhow::Result<CollectOutcome> {
        if !self.expected.contains(&idx) {
            return Ok(CollectOutcome::Ignored);
        }
        if self.collected.contains_key(&idx) {
            anyhow::bail!("returned duplicate input_index {idx}");
        }
        let bytes: [u8; 64] = signature.try_into().map_err(|_| {
            anyhow::anyhow!("returned invalid signature length for input_index {idx}")
        })?;
        let sig = SchnorrSignature::from_byte_array(&bytes).map_err(|e| {
            anyhow::anyhow!("returned invalid signature for input_index {idx}: {e}")
        })?;
        self.collected.insert(idx, sig);
        if self.is_complete() {
            Ok(CollectOutcome::Complete)
        } else {
            Ok(CollectOutcome::Recorded)
        }
    }

    fn collected_count(&self) -> usize {
        self.collected.len()
    }

    fn expected_count(&self) -> usize {
        self.expected.len()
    }

    fn is_complete(&self) -> bool {
        self.collected_count() == self.expected_count()
    }

    /// Consumes the collector when the stream is exhausted, returning whatever
    /// requested signatures this member produced, sorted by index. The set may
    /// be partial: the leader unions partials across members
    /// (`collect_withdrawal_tx_signatures`), so a member that signed only part
    /// of the chunk still contributes forward progress.
    fn into_collected(self) -> Vec<(u64, SchnorrSignature)> {
        self.collected.into_iter().collect()
    }
}

impl LeaderService {
    // ========================================================================
    // Step 3: MPC sign withdrawal transactions and store signatures on-chain
    // ========================================================================

    /// Starts bounded background tasks for unsigned withdrawal transactions that need MPC signing.
    pub(super) fn process_unsigned_withdrawal_txns(&mut self) {
        debug!("Entering process_unsigned_withdrawal_txns");
        if self.is_reconfiguring() {
            debug!("Reconfig in progress, skipping withdrawal tx signing");
            return;
        }

        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| !p.is_fully_signed());
        withdrawal_txns.sort_by_key(|p| p.created_timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_signings
            .retain(|id| pending_ids.contains(id));

        // Cap to 1 when the limiter is in play: the watcher advances
        // `next_seq` per signed event, and the guardian rejects
        // out-of-order `timestamp_secs` — both serialise on this path.
        let max_concurrent = if self.inner.guardian_client().is_some() {
            1
        } else {
            self.inner.config.max_concurrent_leader_job_tasks()
        };
        for txn in withdrawal_txns {
            if self.withdrawal_signing_tasks.len() >= max_concurrent {
                break;
            }
            if self.inflight_withdrawal_signings.contains(&txn.id) {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_signings.insert(txn_id);
            self.withdrawal_signing_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::process_unsigned_withdrawal_txn(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "withdrawal signing for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                    )),
                };

                (txn_id, result)
            });
        }
    }

    /// Removes completed signing tasks from the inflight set and logs their result.
    pub(super) fn handle_completed_withdrawal_signing_task(
        &mut self,
        result: Result<(Address, anyhow::Result<()>), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_signings.remove(&withdrawal_id);
                Ok(inner)
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_signing", mapped);
    }

    /// Drives one withdrawal's signing forward by one step: reallocate stale
    /// presigs, record the next chunk(s) of MPC signatures, or — once every input
    /// is MPC-signed — finalize with the one-shot guardian signatures. Each chunk
    /// is durable on-chain, so timeouts / rotation / restart resume from on-chain
    /// state rather than restarting from scratch.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn process_unsigned_withdrawal_txn(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        // Stale-epoch presigs: reassign only the unsigned tail to the current
        // epoch, then retry next checkpoint. Completed signatures are
        // epoch-independent and are left untouched.
        let current_epoch = inner.onchain_state().epoch();
        let unsigned = txn.signing.unsigned_indices();
        if should_reallocate_stale_presigs(txn.signing.epoch, current_epoch, &unsigned) {
            info!(
                "Withdrawal signing batch from epoch {} (current {}); reallocating pending presigs",
                txn.signing.epoch, current_epoch,
            );
            let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
            executor.execute_reallocate_presigs(&txn.id).await?;
            info!("Pending presigs reallocated; will sign on next checkpoint");
            return Ok(());
        }

        let members = inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // If any input is still unsigned, collect and commit the next chunk.
        if !unsigned.is_empty() {
            return Self::sign_withdrawal_chunks(&inner, &txn, &members, unsigned).await;
        }

        // Every input is MPC-signed: finalize with the guardian (one shot).
        info!("All inputs MPC-signed; finalizing withdrawal with guardian");

        // Fresh per-attempt timestamp from the leader's current checkpoint;
        // using `txn.timestamp_ms` lets stuck batches age past the per-node
        // `GUARDIAN_TIMESTAMP_TOLERANCE_SECS` check on retries.
        let timestamp_secs = inner.onchain_state().latest_checkpoint_timestamp_ms() / 1000;

        // Fail fast before MPC if our own limiter would reject.
        let expected_limiter_seq = if let Some(limiter) = inner.local_limiter() {
            let amount_sats = crate::withdrawals::withdrawal_limiter_consumption_amount(&txn);
            let next_seq = limiter.next_seq();
            let result = limiter.validate_consume(next_seq, timestamp_secs, amount_sats);
            inner.metrics.record_limiter_validate(
                &result,
                crate::metrics::GUARDIAN_LIMITER_CALLSITE_LEADER_PRE_MPC,
            );
            if let Err(e) = result {
                warn!(
                    withdrawal_txn_id = %txn.id,
                    "Leader local limiter rejected withdrawal; will retry on next checkpoint: {e}"
                );
                return Ok(());
            }
            // TODO(guardian-seq-durability): the guardian advances next_seq at
            // finalize-request, but the mirror only advances on the on-chain
            // WithdrawalSigned, so over the multi-checkpoint signing window the
            // mirror can lag by several seqs. A leader with a stale/empty
            // `guardian_last_finalized` (e.g. just rotated in) can slip past the
            // should_defer check below and present a stale seq -> guardian rejects ->
            // retry. Latency, not safety (guardian is source of truth; the reconcile
            // loop self-heals). Likely fine as-is; if PTN shows it matters (watch
            // guardian_finalize_deferred_total), one idea worth exploring would be
            // seeding the defer-gate from authoritative state on election.
            // Pace guardian finalize on the local limiter to avoid reusing a consumed seq.
            if inner.guardian_client().is_some()
                && inner.guardian_should_defer_finalize(next_seq, txn.id)
            {
                debug!(
                    withdrawal_txn_id = %txn.id,
                    next_seq,
                    "Deferring guardian finalize until local limiter catches up to guardian seq"
                );
                inner.metrics.guardian_finalize_deferred_total.inc();
                return Ok(());
            }
            Some(next_seq)
        } else {
            None
        };

        // 1-2. The full per-input MPC set is already durable on-chain (committed
        // incrementally in prior chunks); read it back to bind it at finalize.
        let witness_signatures = txn.signing.dense_signatures().ok_or_else(|| {
            anyhow::anyhow!(
                "withdrawal {} reported complete but has unsigned inputs",
                txn.id
            )
        })?;

        // 3. Post-MPC: forward to guardian for the enclave signature. Reuses
        // the `timestamp_secs` from the pre-MPC validate so the BLS-signed
        // certificate covers a consistent `(timestamp, seq, amount)` triple.
        // The per-input enclave signatures are stored on-chain alongside the
        // MPC sigs to satisfy the 2-of-2 deposit witness.
        let guardian_signatures: Vec<Vec<u8>> =
            match (inner.guardian_client(), expected_limiter_seq) {
                (Some(guardian), Some(seq)) => {
                    let sigs = Self::finalize_withdrawal_through_guardian(
                        &inner,
                        &txn,
                        &members,
                        guardian,
                        timestamp_secs,
                        seq,
                    )
                    .await?;
                    inner.record_guardian_finalized(seq, txn.id);
                    sigs
                }
                _ => {
                    anyhow::bail!(
                        "Guardian endpoint or seq missing — refusing to sign \
                         a 2-of-2 withdrawal without the guardian half of the \
                         witness"
                    );
                }
            };

        // 4. Build the WithdrawalTxSigning (binds BOTH sig arrays) and get
        // the BLS certificate via fan-out.
        let signed_message = WithdrawalTxSigning {
            withdrawal_id: txn.id,
            request_ids: txn.request_ids.clone(),
            signatures: witness_signatures.clone(),
            guardian_signatures: guardian_signatures.clone(),
        };

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let required_weight = certificate_threshold(committee.total_weight());
        // Pass the limiter seq/timestamp the leader validated against (above) as
        // validation-only fields so each committee member re-validates the rate
        // limit once at the finalize cert. They are NOT part of the signed message.
        let proto_request = signed_message.to_proto(expected_limiter_seq, timestamp_secs);

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_tx_signing_signature(&inner, proto_request, &member).await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(withdrawal_txn_id = %txn.id, "Failed to add withdrawal sign message signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient signatures for sign_withdrawal: weight {weight} < {required_weight}"
            );
        }

        let signed = aggregator.finish()?;

        // 5. Submit finalize_withdrawal to Sui (attaches guardian sigs, flips the
        // broadcast gate). Broadcast + confirm happen via
        // process_signed_withdrawal_txns on a later tick.
        let included_checkpoint_seq = Self::submit_finalize_withdrawal(
            &inner,
            &txn.id,
            &txn.request_ids.clone(),
            &guardian_signatures,
            signed.committee_signature(),
        )
        .await
        .inspect(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["finalize_withdrawal", "success"])
                .inc();
        })
        .inspect_err(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["finalize_withdrawal", "failure"])
                .inc();
        })?;

        // Wait for our watcher to catch up to the checkpoint that included
        // the sign_withdrawal txn before returning, so the next tick
        // doesn't respawn with stale state.
        const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner
                .onchain_state()
                .wait_until_checkpoint(included_checkpoint_seq),
        )
        .await
        .is_err()
        {
            warn!(
                withdrawal_txn_id = %txn.id,
                included_checkpoint_seq,
                "Timeout waiting for watcher to reach the included checkpoint; \
                 a duplicate sign attempt may follow"
            );
        }

        Ok(())
    }

    /// Collects MPC signatures for the still-unsigned inputs and commits them in
    /// cert-gated chunks of up to `Config::mpc_signing_chunk_size`. Each chunk is durable
    /// on-chain (`commit_input_signatures`); the next checkpoint resumes from
    /// on-chain state, so a single failing input or a leader change only costs
    /// the in-flight chunk, never the whole withdrawal.
    async fn sign_withdrawal_chunks(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        members: &[CommitteeMember],
        unsigned: Vec<u64>,
    ) -> anyhow::Result<()> {
        // The rate limiter is no longer checked per signing pass — signing is
        // driven unconditionally and the committee re-validates the limit once at
        // the finalize cert (see `validate_and_sign_withdrawal_tx_signing`).
        // `M` (mpc_signing_chunk_size) sizes both the collection unit and the
        // on-chain write batch here. They're separable in principle — the collect
        // is window-bound (how much fits in one signing pass) and the commit is
        // PTB-bound (Sui's 16 KiB pure-arg limit) — but one knob is enough for
        // now: collect one chunk, commit it immediately, then let a later tick
        // resume from the durable on-chain state.
        let chunk_size = inner.config.mpc_signing_chunk_size();
        let chunk_indices = next_signing_chunk(&unsigned, chunk_size);
        info!(
            unsigned = unsigned.len(),
            chunk_size = chunk_indices.len(),
            "Collecting MPC signatures for next unsigned input chunk"
        );
        // Per-input sighashes the MPC signatures must verify against; used to
        // gate each candidate before it is unioned into the chunk.
        let unsigned_tx = inner.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;
        let signing_messages = inner.withdrawal_signing_messages(&unsigned_tx, &txn.inputs)?;

        let sigs_by_index = Self::collect_withdrawal_tx_signatures(
            inner,
            txn,
            &chunk_indices,
            members,
            &signing_messages,
        )
        .await
        .ok_or_else(|| anyhow::anyhow!("Failed to collect MPC signatures for {:?}", txn.id))?;

        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let required_weight = certificate_threshold(committee.total_weight());

        // The collect returns at most one chunk's worth of inputs (≤ M), unioned
        // across members; commit whatever it gathered in a single cert-gated PTB.
        // Any inputs not covered this tick resume from on-chain state next tick.
        let indices: Vec<u64> = sigs_by_index.iter().map(|(i, _)| *i).collect();
        let signatures: Vec<Vec<u8>> = sigs_by_index
            .iter()
            .map(|(_, sig)| sig.to_byte_array().to_vec())
            .collect();

        let signed_message = MpcInputSignaturesMessage {
            withdrawal_id: txn.id,
            indices: indices.clone(),
            signatures: signatures.clone(),
        };
        let proto_request = signed_message.to_proto();

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let proto_request = proto_request.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_mpc_input_signatures_signature(&inner, proto_request, &member).await
            });
        }
        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!(withdrawal_txn_id = %txn.id, "Failed to add chunk cert signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }
        if aggregator.weight() < required_weight {
            anyhow::bail!(
                "Insufficient signatures for commit_input_signatures: weight {} < {required_weight}",
                aggregator.weight()
            );
        }
        let signed = aggregator.finish()?;

        let last_checkpoint = Self::submit_commit_input_signatures(
            inner,
            &txn.id,
            &indices,
            &signatures,
            signed.committee_signature(),
        )
        .await
        .inspect(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["commit_input_signatures", "success"])
                .inc();
        })
        .inspect_err(|_| {
            inner
                .metrics
                .sui_tx_submissions_total
                .with_label_values(&["commit_input_signatures", "failure"])
                .inc();
        })?;

        // Wait for our watcher to observe the last committed chunk so the next
        // tick resumes from fresh on-chain state (and doesn't re-sign it).
        const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
        if last_checkpoint > 0
            && tokio::time::timeout(
                VISIBILITY_TIMEOUT,
                inner.onchain_state().wait_until_checkpoint(last_checkpoint),
            )
            .await
            .is_err()
        {
            warn!(withdrawal_txn_id = %txn.id, "Timeout waiting for watcher to reach the committed chunk checkpoint");
        }
        Ok(())
    }

    /// Collects MPC signatures for the requested chunk by **unioning** partials
    /// across committee members: each member contributes whatever of the chunk it
    /// has signed, and the first *valid* signature seen per input is kept (any
    /// member's aggregate signature for an input is interchangeable). This makes
    /// forward progress under contention — when no single member has the whole
    /// chunk yet — and is safe because the chain records per-input, out-of-order,
    /// first-writer-wins.
    ///
    /// Each candidate is verified against its sighash before being unioned, so a
    /// single bad/buggy member cannot poison the chunk's commit cert. Returns the
    /// (possibly partial) union, or `None` if not a single valid signature was
    /// collected (the next tick retries).
    async fn collect_withdrawal_tx_signatures(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        expected_indices: &[u64],
        members: &[CommitteeMember],
        signing_messages: &[[u8; 32]],
    ) -> Option<Vec<(u64, SchnorrSignature)>> {
        let withdrawal_txn_id = txn.id;
        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let expected_indices = expected_indices.to_vec();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_tx_signature(
                    &inner,
                    &withdrawal_txn_id,
                    &expected_indices,
                    &member,
                )
                .await
            });
        }

        // Per-input verifying keys for the chunk, derived once. A missing key
        // (derivation failed) means candidates for that index can't be verified
        // and are dropped.
        let mut verify_keys: HashMap<u64, SchnorrPublicKey> =
            HashMap::with_capacity(expected_indices.len());
        for &idx in expected_indices {
            match input_verifying_key(inner, txn, idx) {
                Ok(pk) => {
                    verify_keys.insert(idx, pk);
                }
                Err(e) => {
                    warn!(%withdrawal_txn_id, "Cannot derive verifying key for input {idx}: {e}")
                }
            }
        }

        let expected: BTreeSet<u64> = expected_indices.iter().copied().collect();
        let mut union: BTreeMap<u64, SchnorrSignature> = BTreeMap::new();
        while let Some(result) = sig_tasks.join_next().await {
            let candidates = match result {
                Ok(Ok(sigs)) => sigs,
                Ok(Err(e)) => {
                    warn!("Could not get signatures from a node: {e}");
                    continue;
                }
                Err(e) => {
                    warn!("Withdrawal tx signature task failed: {e}");
                    continue;
                }
            };
            let complete = merge_into_union(&mut union, &expected, candidates, |idx, sig| {
                match (verify_keys.get(&idx), signing_messages.get(idx as usize)) {
                    (Some(pk), Some(msg)) => pk.verify(msg, sig).is_ok(),
                    _ => false,
                }
            });
            if complete {
                // Whole chunk in hand; cancel the remaining members.
                break;
            }
        }

        if union.is_empty() {
            error!(
                "Could not collect any MPC signatures for {:?}; stopping processing",
                withdrawal_txn_id
            );
            return None;
        }
        Some(union.into_iter().collect())
    }

    /// Opens a streaming signing RPC to one committee member and collects that
    /// member's MPC signatures for the requested input indices (out-of-order
    /// allowed). The returned set may be partial — the member streams whatever of
    /// the requested subset it has signed — and the caller unions partials across
    /// members.
    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        expected_indices: &[u64],
        member: &CommitteeMember,
    ) -> anyhow::Result<Vec<(u64, SchnorrSignature)>> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signature");

        let mut rpc_client = inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                )
            })?;

        let proto_request = SignWithdrawalTransactionRequest {
            withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
            input_indices: expected_indices.to_vec(),
        };

        let mut stream = rpc_client
            .sign_withdrawal_transaction(proto_request)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to start withdrawal tx signature stream from {validator_address}: {e}"
                )
            })?
            .into_inner();

        let mut collector = ExpectedSignatureCollector::new(expected_indices);
        while let Some(partial) = stream
            .message()
            .await
            .map_err(|e| anyhow::anyhow!("stream error from {validator_address}: {e}"))?
        {
            let idx = partial.input_index as u64;
            match collector.record(idx, partial.signature.as_ref()) {
                Ok(CollectOutcome::Ignored) => trace!(
                    "Withdrawal tx signature stream from {validator_address} returned extra input_index {idx}; ignoring"
                ),
                Ok(CollectOutcome::Recorded) => {}
                // Every requested index is in hand. Stop reading instead of
                // draining to EOF, so a peer that keeps signing unrequested
                // inputs can't stall this chunk.
                Ok(CollectOutcome::Complete) => break,
                // Drop just this candidate (malformed length / duplicate index)
                // and keep the member's other sigs — mirrors merge_into_union's
                // per-candidate drop instead of failing the member's whole stream.
                Err(e) => warn!(
                    "Withdrawal tx signature stream from {validator_address}: dropping input_index {idx}: {e}"
                ),
            }
        }
        Ok(collector.into_collected())
    }

    /// Requests a committee member's BLS signature over the on-chain withdrawal signing message.
    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_tx_signing_signature(
        inner: &Arc<Hashi>,
        proto_request: SignWithdrawalTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal tx signing signature");

        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "withdrawal tx signing signature",
            move |mut client| {
                let request = proto_request.clone();
                async move { client.sign_withdrawal_tx_signing(request).await }
            },
        )
        .await?;

        trace!(
            "Retrieved withdrawal tx signing signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal tx signing response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    /// Requests a committee member's BLS signature over one MPC-signature chunk.
    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_mpc_input_signatures_signature(
        inner: &Arc<Hashi>,
        proto_request: SignMpcInputSignaturesRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting MPC input signatures chunk signature");

        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "mpc input signatures signature",
            move |mut client| {
                let request = proto_request.clone();
                async move { client.sign_mpc_input_signatures(request).await }
            },
        )
        .await?;

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from chunk response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    /// Submits one durable chunk of per-input MPC signatures to Sui.
    async fn submit_commit_input_signatures(
        inner: &Arc<Hashi>,
        withdrawal_id: &Address,
        indices: &[u64],
        signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<u64> {
        info!(
            "Submitting commit_input_signatures for {:?} ({} inputs)",
            withdrawal_id,
            indices.len()
        );
        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_commit_input_signatures(withdrawal_id, indices, signatures, cert)
            .await
    }

    /// Submits the finalize step (guardian sigs + broadcast gate) to Sui.
    async fn submit_finalize_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_id: &Address,
        request_ids: &[Address],
        guardian_signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<u64> {
        info!("Submitting finalize_withdrawal for {:?}", withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_finalize_withdrawal(withdrawal_id, request_ids, guardian_signatures, cert)
            .await
    }

    // ========================================================================
    // Step 4-5: Broadcast signed tx and confirm on-chain
    // ========================================================================

    /// Runs per-checkpoint signed-withdrawal work: normal status checks plus
    /// draining BTC-block-triggered retry checks.
    pub(super) fn process_signed_withdrawal_txns(&mut self) {
        debug!("Entering process_signed_withdrawal_txns");
        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.is_fully_signed());
        withdrawal_txns.sort_by_key(|p| p.created_timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_broadcasts
            .retain(|id| pending_ids.contains(id));
        self.withdrawals_waiting_for_btc_block
            .retain(|id| pending_ids.contains(id));
        self.pending_btc_block_withdrawal_checks
            .retain(|id| pending_ids.contains(id));
        self.withdrawal_broadcast_retry_tracker.prune(&pending_ids);

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        let checkpoint_timestamp_ms = self.inner.onchain_state().latest_checkpoint_timestamp_ms();
        for txn in withdrawal_txns {
            if self.withdrawal_broadcast_tasks.len() >= max_concurrent {
                break;
            }
            if self.withdrawals_waiting_for_btc_block.contains(&txn.id)
                || self.is_withdrawal_broadcast_queued_or_inflight(&txn.id)
                || self
                    .withdrawal_broadcast_retry_tracker
                    .should_skip(&txn.id, checkpoint_timestamp_ms)
            {
                continue;
            }

            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_broadcasts.insert(txn_id);
            self.withdrawal_broadcast_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::handle_signed_withdrawal(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(WithdrawalBroadcastError::new(
                        WithdrawalBroadcastErrorKind::TaskFailed,
                        anyhow::anyhow!(
                            "withdrawal broadcast for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                        ),
                    )),
                };

                (txn_id, result)
            });
        }

        self.process_pending_btc_block_withdrawal_checks();
    }

    /// Moves withdrawals that were parked until Bitcoin advanced into the active BTC-block check queue.
    pub(super) fn schedule_withdrawal_checks_for_btc_block(&mut self) {
        let waiting = std::mem::take(&mut self.withdrawals_waiting_for_btc_block);
        let eligible: Vec<_> = waiting
            .into_iter()
            .filter(|withdrawal_id| !self.is_withdrawal_broadcast_queued_or_inflight(withdrawal_id))
            .collect();
        self.pending_btc_block_withdrawal_checks.extend(eligible);
    }

    /// Drains the BTC-block-triggered withdrawal check queue into its separate bounded task pool.
    fn process_pending_btc_block_withdrawal_checks(&mut self) {
        let mut withdrawal_txns = self.inner.onchain_state().withdrawal_txns();
        withdrawal_txns.retain(|p| p.is_fully_signed());
        withdrawal_txns.sort_by_key(|p| p.created_timestamp_ms);

        let pending_ids: Vec<Address> = withdrawal_txns.iter().map(|p| p.id).collect();
        self.inflight_withdrawal_btc_block_checks
            .retain(|id| pending_ids.contains(id));
        self.pending_btc_block_withdrawal_checks
            .retain(|id| pending_ids.contains(id));
        self.withdrawal_broadcast_retry_tracker.prune(&pending_ids);

        let max_concurrent = self.inner.config.max_concurrent_leader_job_tasks();
        let checkpoint_timestamp_ms = self.inner.onchain_state().latest_checkpoint_timestamp_ms();
        for txn in withdrawal_txns {
            if self.withdrawal_btc_block_check_tasks.len() >= max_concurrent {
                break;
            }
            if !self.pending_btc_block_withdrawal_checks.contains(&txn.id)
                || self.is_withdrawal_broadcast_inflight(&txn.id)
                || self
                    .withdrawal_broadcast_retry_tracker
                    .should_skip(&txn.id, checkpoint_timestamp_ms)
            {
                continue;
            }

            self.pending_btc_block_withdrawal_checks.remove(&txn.id);
            let txn_id = txn.id;
            let inner = self.inner.clone();

            self.inflight_withdrawal_btc_block_checks.insert(txn_id);
            self.withdrawal_btc_block_check_tasks.spawn(async move {
                let result = tokio::time::timeout(
                    LEADER_TASK_TIMEOUT,
                    Self::handle_signed_withdrawal(inner, txn),
                )
                .await;

                let result = match result {
                    Ok(result) => result,
                    Err(_) => Err(WithdrawalBroadcastError::new(
                        WithdrawalBroadcastErrorKind::TaskFailed,
                        anyhow::anyhow!(
                            "withdrawal broadcast for {txn_id} timed out after {LEADER_TASK_TIMEOUT:?}"
                        ),
                    )),
                };

                (txn_id, result)
            });
        }
    }

    /// Handles completion of a normal checkpoint-triggered signed-withdrawal status task.
    pub(super) fn handle_completed_withdrawal_broadcast_task(
        &mut self,
        result: Result<(Address, WithdrawalBroadcastResult), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_broadcasts.remove(&withdrawal_id);
                Ok(self.handle_withdrawal_broadcast_result(withdrawal_id, inner))
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_broadcast", mapped);
    }

    /// Handles completion of a BTC-block-triggered signed-withdrawal status task.
    pub(super) fn handle_completed_withdrawal_btc_block_check_task(
        &mut self,
        result: Result<(Address, WithdrawalBroadcastResult), tokio::task::JoinError>,
    ) {
        let mapped = match result {
            Ok((withdrawal_id, inner)) => {
                self.inflight_withdrawal_btc_block_checks
                    .remove(&withdrawal_id);
                Ok(self.handle_withdrawal_broadcast_result(withdrawal_id, inner))
            }
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => Err(e),
        };
        Self::log_task_result("withdrawal_btc_block_check", mapped);
    }

    /// Applies a signed-withdrawal task outcome to leader scheduler state.
    fn handle_withdrawal_broadcast_result(
        &mut self,
        withdrawal_id: Address,
        result: WithdrawalBroadcastResult,
    ) -> anyhow::Result<()> {
        match result {
            Ok(WithdrawalBroadcastOutcome::ConfirmedOnSui { utxo_ids }) => {
                self.withdrawal_broadcast_retry_tracker
                    .clear(&withdrawal_id);
                self.pending_utxo_cleanups
                    .push_back(PendingUtxoCleanup { utxo_ids });
            }
            Ok(WithdrawalBroadcastOutcome::WaitForNextBitcoinBlock) => {
                self.withdrawal_broadcast_retry_tracker
                    .clear(&withdrawal_id);
                self.withdrawals_waiting_for_btc_block.insert(withdrawal_id);
            }
            Err(err) => {
                self.withdrawal_broadcast_retry_tracker.record_failure(
                    err.kind(),
                    withdrawal_id,
                    self.inner.onchain_state().latest_checkpoint_timestamp_ms(),
                );
                return Err(err.into());
            }
        }
        Ok(())
    }

    /// Returns whether a signed withdrawal is queued or running in any broadcast/status path.
    fn is_withdrawal_broadcast_queued_or_inflight(&self, withdrawal_id: &Address) -> bool {
        self.pending_btc_block_withdrawal_checks
            .contains(withdrawal_id)
            || self.is_withdrawal_broadcast_inflight(withdrawal_id)
    }

    /// Returns whether a signed withdrawal is running in any broadcast/status task pool.
    fn is_withdrawal_broadcast_inflight(&self, withdrawal_id: &Address) -> bool {
        self.inflight_withdrawal_broadcasts.contains(withdrawal_id)
            || self
                .inflight_withdrawal_btc_block_checks
                .contains(withdrawal_id)
    }

    /// Checks BTC tx status, broadcasts or re-broadcasts if needed, and confirms on Sui when
    /// enough BTC confirmations are reached.
    ///
    /// Returns the next scheduler action after the status check completes.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid))]
    async fn handle_signed_withdrawal(
        inner: Arc<Hashi>,
        txn: WithdrawalTransaction,
    ) -> WithdrawalBroadcastResult {
        let confirmation_threshold = inner.onchain_state().bitcoin_confirmation_threshold();
        let txid: bitcoin::Txid = txn.txid.into();
        tracing::Span::current().record("bitcoin_txid", tracing::field::display(&txid));

        match inner.btc_monitor().get_transaction_status(txid).await {
            Ok(TxStatus::Confirmed { confirmations })
                if confirmations >= confirmation_threshold =>
            {
                info!(
                    confirmations,
                    "Withdrawal tx confirmed, proceeding to on-chain confirmation"
                );
                let utxo_ids: Vec<UtxoId> = txn.inputs.iter().map(|u| u.id).collect();
                Self::confirm_withdrawal_on_sui(&inner, &txn)
                    .await
                    .map_err(|e| {
                        WithdrawalBroadcastError::new(
                            WithdrawalBroadcastErrorKind::SuiConfirmation,
                            e,
                        )
                    })?;
                return Ok(WithdrawalBroadcastOutcome::ConfirmedOnSui { utxo_ids });
            }
            Ok(TxStatus::Confirmed { confirmations }) => {
                debug!(
                    confirmations,
                    confirmation_threshold, "Withdrawal tx waiting for more confirmations"
                );
            }
            Ok(TxStatus::InMempool) => {
                debug!("Withdrawal tx in mempool, waiting for confirmations");
            }
            Ok(TxStatus::NotFound) => {
                Self::rebuild_and_broadcast_withdrawal_btc_tx(&inner, &txn, txid)
                    .await
                    .map_err(|e| {
                        WithdrawalBroadcastError::new(WithdrawalBroadcastErrorKind::BitcoinRpc, e)
                    })?;
            }
            Err(e) => {
                return Err(WithdrawalBroadcastError::new(
                    WithdrawalBroadcastErrorKind::BitcoinRpc,
                    anyhow::anyhow!(
                        "failed to query transaction status for withdrawal transaction {}: {e}",
                        txn.id
                    ),
                ));
            }
        }
        Ok(WithdrawalBroadcastOutcome::WaitForNextBitcoinBlock)
    }

    /// Rebuilds a fully signed Bitcoin transaction from on-chain WithdrawalTransaction
    /// data (stored witness signatures) and broadcast it to the Bitcoin network.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id, bitcoin_txid = %txid))]
    async fn rebuild_and_broadcast_withdrawal_btc_tx(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
        txid: bitcoin::Txid,
    ) -> anyhow::Result<()> {
        warn!("Withdrawal tx not found, re-broadcasting from on-chain signatures");

        let tx = Self::rebuild_signed_tx_from_onchain(inner, txn)
            .inspect_err(|e| error!("Failed to rebuild signed withdrawal tx: {e}"))?;

        inner
            .btc_monitor()
            .broadcast_transaction(tx)
            .await
            .inspect(|()| info!("Re-broadcast withdrawal tx"))
            .inspect_err(|e| error!("Failed to re-broadcast withdrawal tx: {e}"))
    }

    /// Rebuilds a fully signed Bitcoin transaction from on-chain
    /// `WithdrawalTransaction` data and broadcast-ready 2-of-2 witness.
    ///
    /// Witness layout per input (BIP342 multi_a, verified against
    /// rust-miniscript's `Terminal::MultiA` satisfier):
    ///
    /// ```text
    /// [hashi_sig, guardian_sig, leaf_script, control_block]
    /// ```
    fn rebuild_signed_tx_from_onchain(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let raw_sigs = txn
            .mpc_signatures()
            .ok_or_else(|| anyhow::anyhow!("Withdrawal transaction is not fully signed"))?;
        let raw_guardian_sigs = txn
            .guardian_signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No guardian signatures on withdrawal transaction"))?;

        let mut tx = inner.build_unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())?;

        anyhow::ensure!(
            raw_sigs.len() == tx.input.len(),
            "MPC signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_sigs.len()
        );
        anyhow::ensure!(
            raw_guardian_sigs.len() == tx.input.len(),
            "Guardian signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_guardian_sigs.len()
        );
        anyhow::ensure!(
            tx.input.len() == txn.inputs.len(),
            "Input count mismatch: tx has {} inputs, txn has {}",
            tx.input.len(),
            txn.inputs.len()
        );

        for (((input, txn_input), hashi_sig_bytes), guardian_sig_bytes) in tx
            .input
            .iter_mut()
            .zip(txn.inputs.iter())
            .zip(raw_sigs)
            .zip(raw_guardian_sigs)
        {
            let (script, control_block, _) =
                inner.deposit_spend_artifacts(txn_input.derivation_path.as_ref())?;
            let mut witness = bitcoin::Witness::new();
            // multi_a satisfier order: hashi_sig (bottom) then guardian_sig (top).
            witness.push(hashi_sig_bytes);
            witness.push(guardian_sig_bytes);
            witness.push(script.to_bytes());
            witness.push(control_block.serialize());
            input.witness = witness;
        }

        Ok(tx)
    }

    /// Collects a confirmation certificate and submits the finalized withdrawal to Sui.
    #[tracing::instrument(level = "info", skip_all, fields(withdrawal_txn_id = %txn.id))]
    async fn confirm_withdrawal_on_sui(
        inner: &Arc<Hashi>,
        txn: &WithdrawalTransaction,
    ) -> anyhow::Result<()> {
        let members = inner
            .onchain_state()
            .current_committee_members()
            .ok_or_else(|| anyhow::anyhow!("No current committee members for confirmation"))?;

        let confirmation_cert =
            Self::collect_withdrawal_confirmation_signature(inner, txn.id, &members).await?;

        Self::submit_confirm_withdrawal(inner, &txn.id, &confirmation_cert)
            .await
            .inspect(|()| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "success"])
                    .inc();
                inner.metrics.withdrawals_finalized_total.inc();
            })
            .inspect_err(|_| {
                inner
                    .metrics
                    .sui_tx_submissions_total
                    .with_label_values(&["confirm_withdrawal", "failure"])
                    .inc();
            })?;

        Ok(())
    }

    /// Collects enough committee signatures to certify that a withdrawal can be confirmed.
    #[tracing::instrument(level = "debug", skip_all, fields(withdrawal_txn_id = %withdrawal_txn_id))]
    async fn collect_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let committee = inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let confirmation = crate::withdrawals::WithdrawalConfirmation {
            withdrawal_id: withdrawal_txn_id,
        };

        let required_weight = certificate_threshold(committee.total_weight());

        let mut sig_tasks = JoinSet::new();
        for member in members {
            let inner = inner.clone();
            let member = member.clone();
            sig_tasks.spawn(async move {
                Self::request_withdrawal_confirmation_signature(&inner, withdrawal_txn_id, &member)
                    .await
            });
        }

        let mut aggregator = BlsSignatureAggregator::new(&committee, confirmation);
        while let Some(result) = sig_tasks.join_next().await {
            let Ok(Some(sig)) = result else { continue };
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add withdrawal confirmation signature: {e}");
            }
            if aggregator.weight() >= required_weight {
                break;
            }
        }

        let weight = aggregator.weight();
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient withdrawal confirmation signatures for {:?}: weight {weight} < {required_weight}",
                withdrawal_txn_id
            );
        }

        Ok(aggregator.finish()?.into_parts().0)
    }

    /// Requests one committee member's BLS signature over a withdrawal confirmation message.
    #[tracing::instrument(level = "debug", skip_all, fields(validator = %member.validator_address()))]
    async fn request_withdrawal_confirmation_signature(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: Address,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting withdrawal confirmation signature");

        let proto_request = SignWithdrawalConfirmationRequest {
            withdrawal_txn_id: withdrawal_txn_id.as_bytes().to_vec().into(),
        };
        let response = Self::call_peer_with_retry(
            inner,
            validator_address,
            "withdrawal confirmation signature",
            move |mut client| {
                let request = proto_request.clone();
                async move { client.sign_withdrawal_confirmation(request).await }
            },
        )
        .await?;

        trace!(
            "Retrieved withdrawal confirmation signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal confirmation response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    /// Submits the withdrawal confirmation certificate to Sui.
    async fn submit_confirm_withdrawal(
        inner: &Arc<Hashi>,
        withdrawal_txn_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Confirming withdrawal {:?}", withdrawal_txn_id);

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        executor
            .execute_confirm_withdrawal(withdrawal_txn_id, cert)
            .await?;

        info!("Successfully confirmed withdrawal {:?}", withdrawal_txn_id);

        Ok(())
    }
}

impl WithdrawalTxSigning {
    /// Converts the withdrawal signing message into the bridge-service protobuf request type.
    ///
    /// `expected_limiter_seq`/`timestamp_secs` are validation-only RPC fields —
    /// committee members re-validate the rate limit at finalize against them. They
    /// are deliberately NOT part of the BLS-signed message.
    fn to_proto(
        &self,
        expected_limiter_seq: Option<u64>,
        timestamp_secs: u64,
    ) -> SignWithdrawalTxSigningRequest {
        SignWithdrawalTxSigningRequest {
            withdrawal_id: self.withdrawal_id.as_bytes().to_vec().into(),
            request_ids: self
                .request_ids
                .iter()
                .map(|id| id.as_bytes().to_vec().into())
                .collect(),
            signatures: self
                .signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
            guardian_signatures: self
                .guardian_signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
            expected_limiter_seq,
            timestamp_secs: Some(timestamp_secs),
        }
    }
}

impl MpcInputSignaturesMessage {
    /// Converts the chunk message into the bridge-service protobuf request type.
    fn to_proto(&self) -> SignMpcInputSignaturesRequest {
        SignMpcInputSignaturesRequest {
            withdrawal_id: self.withdrawal_id.as_bytes().to_vec().into(),
            indices: self.indices.clone(),
            signatures: self
                .signatures
                .iter()
                .map(|sig| sig.clone().into())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_presig_reallocation_requires_pending_inputs() {
        assert!(should_reallocate_stale_presigs(5, 6, &[0]));
        assert!(!should_reallocate_stale_presigs(5, 6, &[]));
        assert!(!should_reallocate_stale_presigs(6, 6, &[0]));
    }

    #[test]
    fn next_signing_chunk_is_capped_to_configured_size() {
        assert_eq!(next_signing_chunk(&[0, 1, 2, 3], 2), vec![0, 1]);
    }

    #[test]
    fn next_signing_chunk_treats_zero_size_as_one() {
        assert_eq!(next_signing_chunk(&[7, 8], 0), vec![7]);
    }

    // Valid 64-byte BIP-340 Schnorr signatures lifted from fastcrypto's own
    // secp256k1 test vectors; both parse cleanly via
    // `SchnorrSignature::from_byte_array`, so they exercise the
    // recorded/complete paths without standing up a live signer.
    fn valid_sig_a() -> Vec<u8> {
        hex::decode(
            "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8\
             585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
        )
        .unwrap()
    }

    fn valid_sig_b() -> Vec<u8> {
        hex::decode(
            "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C637\
             6AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
        )
        .unwrap()
    }

    #[test]
    fn valid_sig_fixtures_parse() {
        // Guard the fixtures themselves so a bad copy/paste surfaces here
        // rather than as a confusing failure in the behavioural tests.
        assert!(SchnorrSignature::from_byte_array(&valid_sig_a().try_into().unwrap()).is_ok());
        assert!(SchnorrSignature::from_byte_array(&valid_sig_b().try_into().unwrap()).is_ok());
    }

    #[test]
    fn collector_ignores_unexpected_extra_index_before_parsing() {
        let mut collector = ExpectedSignatureCollector::new(&[0, 1]);
        // Unrequested index carrying deliberately malformed (too-short) bytes:
        // it must be ignored *before* the signature is parsed, so the malformed
        // extra can't fail the chunk.
        assert_eq!(
            collector.record(7, &[0u8; 3]).unwrap(),
            CollectOutcome::Ignored
        );
        assert_eq!(collector.collected_count(), 0);
        assert!(!collector.is_complete());
    }

    #[test]
    fn collector_completes_on_last_expected_out_of_order() {
        let mut collector = ExpectedSignatureCollector::new(&[0, 1, 2]);
        assert_eq!(
            collector.record(2, &valid_sig_a()).unwrap(),
            CollectOutcome::Recorded
        );
        assert_eq!(
            collector.record(0, &valid_sig_b()).unwrap(),
            CollectOutcome::Recorded
        );
        // The final requested index arrives last and out of order, yet the
        // collector reports Complete immediately — the caller can stop reading.
        assert_eq!(
            collector.record(1, &valid_sig_a()).unwrap(),
            CollectOutcome::Complete
        );
        assert!(collector.is_complete());

        let indices: Vec<u64> = collector
            .into_collected()
            .into_iter()
            .map(|(i, _)| i)
            .collect();
        assert_eq!(indices, vec![0, 1, 2]);
    }

    #[test]
    fn collector_errors_on_duplicate_expected_index() {
        let mut collector = ExpectedSignatureCollector::new(&[0, 1]);
        assert_eq!(
            collector.record(0, &valid_sig_a()).unwrap(),
            CollectOutcome::Recorded
        );
        let err = collector.record(0, &valid_sig_b()).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "unexpected error: {err}");
    }

    #[test]
    fn collector_errors_on_malformed_expected_signature() {
        let mut collector = ExpectedSignatureCollector::new(&[0]);
        let err = collector.record(0, &[0u8; 10]).unwrap_err().to_string();
        assert!(err.contains("invalid signature"), "unexpected error: {err}");
    }

    #[test]
    fn collector_into_collected_returns_partial_when_stream_ends_incomplete() {
        let mut collector = ExpectedSignatureCollector::new(&[0, 1, 2]);
        collector.record(0, &valid_sig_a()).unwrap();
        // EOF before indices 1 and 2 arrived: the member contributes its partial
        // set (just index 0); the leader unions it with other members' partials.
        let indices: Vec<u64> = collector
            .into_collected()
            .into_iter()
            .map(|(i, _)| i)
            .collect();
        assert_eq!(indices, vec![0]);
    }

    fn sig_a() -> SchnorrSignature {
        SchnorrSignature::from_byte_array(&valid_sig_a().try_into().unwrap()).unwrap()
    }

    fn sig_b() -> SchnorrSignature {
        SchnorrSignature::from_byte_array(&valid_sig_b().try_into().unwrap()).unwrap()
    }

    #[test]
    fn merge_into_union_keeps_first_valid_and_reports_complete() {
        let expected: BTreeSet<u64> = [0, 1].into_iter().collect();
        let mut union: BTreeMap<u64, SchnorrSignature> = BTreeMap::new();

        // First member has only index 0 -> not complete yet.
        let complete = merge_into_union(&mut union, &expected, vec![(0, sig_a())], |_, _| true);
        assert!(!complete);
        assert_eq!(union.keys().copied().collect::<Vec<_>>(), vec![0]);

        // Second member re-sends 0 (kept from the first) and adds 1 -> completes.
        let complete = merge_into_union(
            &mut union,
            &expected,
            vec![(0, sig_b()), (1, sig_b())],
            |_, _| true,
        );
        assert!(complete);
        assert_eq!(union.keys().copied().collect::<Vec<_>>(), vec![0, 1]);
    }

    #[test]
    fn merge_into_union_skips_invalid_and_out_of_chunk() {
        let expected: BTreeSet<u64> = [0, 1].into_iter().collect();
        let mut union: BTreeMap<u64, SchnorrSignature> = BTreeMap::new();

        // idx 0 fails verification, idx 5 is out of chunk, idx 1 is valid.
        let complete = merge_into_union(
            &mut union,
            &expected,
            vec![(0, sig_a()), (5, sig_a()), (1, sig_a())],
            |idx, _| idx != 0,
        );
        assert!(!complete);
        assert_eq!(union.keys().copied().collect::<Vec<_>>(), vec![1]);
    }
}
