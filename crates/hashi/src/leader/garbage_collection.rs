// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Garbage collection for expired on-chain data.

use super::LeaderService;
use crate::onchain::TobKey;
use crate::onchain::TobPruneTarget;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::UtxoId;
use crate::onchain::types::UtxoRecord;
use crate::sui_tx_executor::SuiTxExecutor;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use sui_sdk_types::Address;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::warn;

const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24; // 1 day
const DEPOSIT_REQUEST_DELETE_DELAY_MS: u64 = 1000 * 60; // 1 minute
const MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC: usize = 500;

const MAX_PROPOSAL_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days
const PROPOSAL_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day

// Cap how many proposals we delete per GC so the `delete_expired` PTB stays within Sui's
// 1024-command-per-PTB ceiling. A larger backlog drains over successive checkpoints, oldest first.
// Mirrors `MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC`.
const MAX_PROPOSAL_DELETIONS_PER_GC: usize = 500;

// Cap the orphan scan so one cleanup task stays bounded; a larger backlog
// drains over successive checkpoints. Mirrors the two caps above.
const MAX_UTXO_CLEANUPS_PER_GC: usize = 500;

// Cap how many TOB cert buckets one prune sweep destroys. Lower than the
// caps above because each destroyed bucket is much heavier than one deleted
// record: it drains a whole LinkedTable (~80 object deletions on a full
// committee), so the per-transaction chunk in
// `execute_destroy_tob_certs` is small and a sweep is several transactions.
// A larger backlog drains over successive sweeps, oldest epochs first.
const MAX_TOB_PRUNES_PER_GC: usize = 200;

/// Mirror of the Move floors in `cert_submission.move`. The Move asserts are
/// authoritative — drift here only produces aborting GC transactions, never
/// an unsafe delete. Key-generation buckets are retained longer than the
/// `tob::destroy_all` minimum because break-glass key recovery pairs them
/// with the local DB's dealer/rotation messages (kept for the trailing 7
/// epochs).
const KEY_GEN_CERT_RETENTION_EPOCHS: u64 = 8;
/// Nonce buckets are only ever read during their own epoch; +2 mirrors
/// `tob::destroy_all`'s backstop.
const NONCE_CERT_MIN_AGE_EPOCHS: u64 = 2;

/// The destroy entries are v2-introduced; hold the prune job off until the
/// active on-chain version carries them.
const TOB_PRUNE_MIN_PACKAGE_VERSION: u64 = 2;

/// Failure kind for the UTXO cleanup GC. `max_retries` is unbounded: this is
/// a singleton maintenance task that must never permanently give up (a
/// drained gas wallet can heal by top-up), so it backs off to `max_delay_ms`
/// instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UtxoCleanupErrorKind {
    Failed,
}

impl crate::leader::retry::RetryPolicy for UtxoCleanupErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        5_000
    }

    fn max_delay_ms(self) -> u64 {
        5 * 60 * 1000
    }

    fn max_retries(self) -> u32 {
        u32::MAX
    }
}

/// Failure kind for the TOB cert prune GC. Same unbounded-retry rationale as
/// [`UtxoCleanupErrorKind`]: singleton maintenance that must never
/// permanently give up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TobPruneErrorKind {
    Failed,
}

impl crate::leader::retry::RetryPolicy for TobPruneErrorKind {
    fn retry_base_delay_ms(self) -> u64 {
        5_000
    }

    fn max_delay_ms(self) -> u64 {
        5 * 60 * 1000
    }

    fn max_retries(self) -> u32 {
        u32::MAX
    }
}

/// Result of one TOB prune sweep, consumed by the leader loop's reap arm.
#[derive(Debug)]
pub(super) struct TobPruneOutcome {
    /// The hashi epoch captured when the sweep was spawned; advances the
    /// once-per-epoch gate. Captured at spawn so an epoch flip mid-sweep
    /// cannot mask the new epoch's work.
    pub(super) swept_epoch: u64,
    /// Whether the sweep selected fewer buckets than its cap — i.e. the
    /// backlog is fully drained and the gate may close until the epoch
    /// advances.
    pub(super) drained: bool,
}

impl LeaderService {
    /// Check for and delete expired deposit requests.
    /// Unapproved requests expire based on creation time; approved requests expire based on
    /// approval time.
    pub(super) fn check_delete_expired_deposit_requests(&mut self, checkpoint_timestamp_ms: u64) {
        if self.deposit_gc_task.is_some() {
            debug!("Deposit GC task already in-flight, skipping");
            return;
        }

        let expired_requests = find_expired_deposit_requests(
            self.inner.onchain_state().deposit_requests(),
            checkpoint_timestamp_ms,
        );
        if expired_requests.is_empty() {
            return;
        }

        info!(
            "Scheduling deletion of {} expired deposit requests",
            expired_requests.len()
        );

        let inner = self.inner.clone();
        self.deposit_gc_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::delete_expired_deposit_requests(inner, expired_requests).await
        })));
    }

    async fn delete_expired_deposit_requests(
        inner: Arc<crate::Hashi>,
        expired_requests: Vec<DepositRequest>,
    ) -> anyhow::Result<()> {
        let count = expired_requests.len();
        let mut executor = SuiTxExecutor::from_hashi(inner)?;
        executor
            .execute_delete_expired_deposit_requests(&expired_requests)
            .await?;
        info!("Successfully deleted {count} expired deposit requests");
        Ok(())
    }

    /// Check for and delete expired proposals.
    /// Proposals are sorted by timestamp and deleted if they are older than MAX_PROPOSAL_AGE_MS.
    pub(super) fn check_delete_proposals(&mut self, checkpoint_timestamp_ms: u64) {
        debug!("Entering check_delete_proposals");

        if self.proposal_gc_task.is_some() {
            debug!("Proposal GC task already in-flight, skipping");
            return;
        }

        let mut proposals = self.inner.onchain_state().proposals();
        // Sort proposals by timestamp, from earliest to latest
        proposals.sort_by_key(|p| p.timestamp_ms);

        // Check if it's time to delete
        let Some(oldest_proposal) = proposals.first() else {
            return;
        };

        // If there aren't any proposals at least 8 days old (7 days expiry + 1 day delay), don't do anything
        if checkpoint_timestamp_ms
            < oldest_proposal.timestamp_ms + MAX_PROPOSAL_AGE_MS + PROPOSAL_DELETE_DELAY_MS
        {
            return;
        }

        // Find all expired proposals (older than 7 days), capped per GC so the
        // resulting PTB stays within Sui's transaction limits.
        let expired_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| checkpoint_timestamp_ms > p.timestamp_ms + MAX_PROPOSAL_AGE_MS)
            .take(MAX_PROPOSAL_DELETIONS_PER_GC)
            .cloned()
            .collect();

        if expired_proposals.is_empty() {
            return;
        }

        info!(
            "Scheduling deletion of {} expired proposals",
            expired_proposals.len()
        );

        let inner = self.inner.clone();
        self.proposal_gc_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::delete_expired_proposals(inner, expired_proposals).await
        })));
    }

    /// If a cleanup scan is due and no task is in-flight, spawn a background
    /// task that scans the object mirror for spent-but-uncleaned UTXO
    /// records and cleans them. The scan is armed at boot
    /// (crash-between-confirm-and-cleanup recovery), whenever a withdrawal
    /// confirms on Sui, and after a task that did work or failed.
    pub(super) fn check_cleanup_spent_utxos(&mut self, checkpoint_timestamp_ms: u64) {
        if self.utxo_cleanup_gc_task.is_some() {
            debug!("UTXO cleanup GC task already in-flight, skipping");
            return;
        }

        if !self.utxo_cleanup_scan_needed {
            return;
        }

        if self.utxo_cleanup_retry.should_skip(checkpoint_timestamp_ms) {
            debug!("UTXO cleanup GC in backoff, skipping");
            return;
        }

        self.utxo_cleanup_scan_needed = false;
        let inner = self.inner.clone();
        let scan_target = self.utxo_cleanup_scan_target;
        self.utxo_cleanup_gc_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::cleanup_spent_utxos(inner, scan_target).await
        })));
    }

    /// Scan the object mirror for spent-but-uncleaned UTXO records and
    /// clean them. Returns how many UTXOs were cleaned so the caller can
    /// decide whether to re-arm the scan (more work may exist past the
    /// per-GC cap).
    ///
    /// The mirror applies `cleanup_spent` Field deletions directly (the
    /// object mirror sees every write, eventless or not), so deciding from
    /// it is safe: another leader's cleanup shows up within the watcher's
    /// stream lag rather than never, as under the event-driven watcher.
    /// The freshness guarantee the old out-of-band scrape's per-page
    /// checkpoint floor provided is supplied by two watermark waits: past
    /// `scan_target` (the arming confirm's checkpoint) before reading, so
    /// the scan sees the spent markings that armed it, and past the landed
    /// cleanup's checkpoint before returning, so the re-armed scan cannot
    /// re-see (and re-pay for) the records this tx just removed.
    async fn cleanup_spent_utxos(
        inner: Arc<crate::Hashi>,
        scan_target: u64,
    ) -> anyhow::Result<usize> {
        const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(30);
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner.onchain_state().wait_until_checkpoint(scan_target),
        )
        .await
        .is_err()
        {
            // Failing (rather than scanning stale) routes through the retry
            // tracker: backoff, re-arm, and a fresh attempt once the mirror
            // catches up.
            anyhow::bail!(
                "mirror did not reach the cleanup scan target checkpoint {scan_target} within \
                 {VISIBILITY_TIMEOUT:?}"
            );
        }
        let utxo_records = inner.onchain_state().utxo_records();
        let utxo_ids = find_spent_utxos_pending_cleanup(&utxo_records);
        if utxo_ids.is_empty() {
            return Ok(0);
        }

        info!(
            utxo_count = utxo_ids.len(),
            "Cleaning up spent UTXO(s) pending cleanup",
        );
        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        let landed_at = executor.execute_cleanup_spent_utxos(&utxo_ids).await?;
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner.onchain_state().wait_until_checkpoint(landed_at),
        )
        .await
        .is_err()
        {
            warn!(
                landed_at,
                "Timeout waiting for the mirror to reach the cleanup checkpoint; \
                 the next scan may resubmit already-cleaned records"
            );
        }
        info!(
            utxo_count = utxo_ids.len(),
            "Successfully cleaned up spent UTXOs",
        );
        Ok(utxo_ids.len())
    }

    async fn delete_expired_proposals(
        inner: Arc<crate::Hashi>,
        expired_proposals: Vec<Proposal>,
    ) -> anyhow::Result<()> {
        use sui_sdk_types::Identifier;
        use sui_sdk_types::StructTag;
        use sui_sdk_types::TypeTag;
        use sui_transaction_builder::Function;
        use sui_transaction_builder::ObjectInput;
        use sui_transaction_builder::TransactionBuilder;

        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        let hashi_ids = inner.config.hashi_ids();

        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );

        // Clock object (0x6) - immutable shared object
        let clock_arg = builder.object(
            ObjectInput::new(Address::from_static("0x6"))
                .as_shared()
                .with_mutable(false),
        );

        // Add a move call for each expired proposal
        for proposal in &expired_proposals {
            let proposal_id_arg = builder.pure(&proposal.id);

            // Get the type argument for the proposal
            let type_arg = match &proposal.proposal_type {
                ProposalType::UpdateConfig => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("update_config"),
                    Identifier::from_static("UpdateConfig"),
                    vec![],
                ))),
                ProposalType::EnableVersion => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("enable_version"),
                    Identifier::from_static("EnableVersion"),
                    vec![],
                ))),
                ProposalType::DisableVersion => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("disable_version"),
                    Identifier::from_static("DisableVersion"),
                    vec![],
                ))),
                ProposalType::Upgrade => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("upgrade"),
                    Identifier::from_static("Upgrade"),
                    vec![],
                ))),
                ProposalType::EmergencyPause => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("emergency_pause"),
                    Identifier::from_static("EmergencyPause"),
                    vec![],
                ))),
                ProposalType::AbortReconfig => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("abort_reconfig"),
                    Identifier::from_static("AbortReconfig"),
                    vec![],
                ))),
                ProposalType::UpdateGuardian => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("update_guardian"),
                    Identifier::from_static("UpdateGuardian"),
                    vec![],
                ))),
                ProposalType::Unknown(type_name) => {
                    error!(
                        "Cannot delete proposal {:?} with unknown type: {}",
                        proposal.id, type_name
                    );
                    continue;
                }
            };

            builder.move_call(
                Function::new(
                    executor.active_call_package_id(),
                    Identifier::from_static("proposal"),
                    Identifier::from_static("delete_expired"),
                )
                .with_type_args(vec![type_arg]),
                vec![hashi_arg, proposal_id_arg, clock_arg],
            );
        }

        let response = executor.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!("Transaction failed to delete expired proposals");
        }
        info!(
            "Successfully deleted {} expired proposals",
            expired_proposals.len()
        );
        Ok(())
    }

    /// If the hashi epoch has advanced since the last fully-drained sweep
    /// and no task is in-flight, spawn a background task that lists the TOB
    /// bag and destroys every dead cert bucket. Epoch-gated rather than
    /// timestamp-gated because eligibility only changes at epoch boundaries
    /// and candidate discovery is a live RPC bag listing, not a mirror read;
    /// the gate is only advanced by a sweep that drained the backlog, so a
    /// cap-limited sweep re-runs on the next leader checkpoint.
    pub(super) fn check_prune_tob_certs(&mut self, checkpoint_timestamp_ms: u64) {
        if self.tob_prune_task.is_some() {
            debug!("TOB prune task already in-flight, skipping");
            return;
        }

        // The destroy entries are v2-introduced. Gating on the ACTIVE version
        // (not merely the latest published) also keeps the sweep off a chain
        // whose semantics this binary does not implement.
        let Some(active) = self.inner.onchain_state().active_package_version() else {
            return;
        };
        if active < TOB_PRUNE_MIN_PACKAGE_VERSION {
            return;
        }

        let current_epoch = self.inner.onchain_state().epoch();
        if self.last_tob_prune_epoch == Some(current_epoch) {
            return;
        }

        if self.tob_prune_retry.should_skip(checkpoint_timestamp_ms) {
            debug!("TOB prune GC in backoff, skipping");
            return;
        }

        let inner = self.inner.clone();
        self.tob_prune_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::prune_tob_certs(inner, current_epoch).await
        })));
    }

    /// List the TOB bag, select dead buckets, and destroy them on-chain.
    ///
    /// Freshness: the listing is a live RPC read; the committee epochs and
    /// current epoch come from the mirror, which can only lag the chain. A
    /// lagging epoch shrinks both floors and a missing recent committee only
    /// disables key-generation selections, so staleness is strictly
    /// conservative — and the Move floors re-check against the authoritative
    /// on-chain epoch at execution regardless. Races with another pruner are
    /// absorbed by the entries' missing-bucket idempotency.
    async fn prune_tob_certs(
        inner: Arc<crate::Hashi>,
        swept_epoch: u64,
    ) -> anyhow::Result<TobPruneOutcome> {
        let keys = inner.onchain_state().list_tob_keys().await?;
        let (committee_epochs, current_epoch) = {
            let state = inner.onchain_state().state();
            let committees = &state.hashi().committees;
            (
                committees.committees().keys().copied().collect(),
                committees.epoch(),
            )
        };
        let targets = find_tob_buckets_to_prune(&keys, &committee_epochs, current_epoch);
        if targets.is_empty() {
            debug!("No TOB cert buckets eligible for pruning");
            return Ok(TobPruneOutcome {
                swept_epoch,
                drained: true,
            });
        }

        // Whether more work may remain past the cap, decided before the
        // destroy so a partially-failed batch also re-runs via the retry path.
        let drained = targets.len() < MAX_TOB_PRUNES_PER_GC;
        info!(
            bucket_count = targets.len(),
            drained, "Destroying dead TOB cert bucket(s)"
        );
        let mut executor = SuiTxExecutor::from_hashi(inner)?;
        executor.execute_destroy_tob_certs(&targets).await?;
        info!(
            bucket_count = targets.len(),
            "Successfully destroyed dead TOB cert buckets"
        );
        Ok(TobPruneOutcome {
            swept_epoch,
            drained,
        })
    }
}

fn deposit_request_expiration_timestamp_ms(request: &DepositRequest) -> u64 {
    let reference_timestamp_ms = match (&request.approval_cert, request.approved_timestamp_ms) {
        (Some(_), Some(approved_timestamp_ms)) => approved_timestamp_ms,
        _ => request.created_timestamp_ms,
    };
    reference_timestamp_ms.saturating_add(MAX_DEPOSIT_REQUEST_AGE_MS)
}

fn find_expired_deposit_requests(
    mut deposit_requests: Vec<DepositRequest>,
    checkpoint_timestamp_ms: u64,
) -> Vec<DepositRequest> {
    deposit_requests.sort_by_key(deposit_request_expiration_timestamp_ms);

    let Some(oldest_request) = deposit_requests.first() else {
        return Vec::new();
    };
    if checkpoint_timestamp_ms
        < deposit_request_expiration_timestamp_ms(oldest_request)
            .saturating_add(DEPOSIT_REQUEST_DELETE_DELAY_MS)
    {
        return Vec::new();
    }

    deposit_requests
        .into_iter()
        .filter(|request| {
            checkpoint_timestamp_ms > deposit_request_expiration_timestamp_ms(request)
        })
        .take(MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC)
        .collect()
}

/// Return UTXO IDs whose `spent_epoch` is set — these are spent UTXOs
/// still present in `utxo_records` that need to be cleaned up on-chain.
/// Capped at [`MAX_UTXO_CLEANUPS_PER_GC`]; the remainder is picked up by a
/// later scan.
///
/// Pure-data core of the cleanup task's scan over the mirror's records,
/// extracted so it can be unit-tested without RPC or a full `LeaderService`.
fn find_spent_utxos_pending_cleanup(utxo_records: &BTreeMap<UtxoId, UtxoRecord>) -> Vec<UtxoId> {
    utxo_records
        .iter()
        .filter(|(_, record)| record.spent_epoch.is_some())
        .map(|(id, _)| *id)
        .take(MAX_UTXO_CLEANUPS_PER_GC)
        .collect()
}

/// Select the TOB cert buckets that are safe to destroy, mirroring the Move
/// floors (which remain authoritative):
///
/// - Nonce buckets: `current_epoch >= epoch + 2`; only ever read during
///   their own epoch.
/// - Key-generation buckets: `current_epoch >= epoch + 8` (break-glass
///   retention) AND a committee epoch strictly between the bucket's and now.
///   Committee epochs are Sui epochs and can gap, and the previous
///   committee's certs seed the next rotation, so an age floor alone cannot
///   identify the previous committee's bucket. A pending committee's epoch
///   sits above `current_epoch` and is excluded by the exclusive range
///   bound.
/// - Any other key shape is left alone: never destroy what we don't
///   understand.
///
/// Output order: epochs ascending (oldest first); within an epoch the
/// key-generation target first, then nonce batches DESCENDING by index, so
/// truncation at [`MAX_TOB_PRUNES_PER_GC`] always leaves a partially-drained
/// epoch's surviving batches as a contiguous `0..m` prefix (in-epoch presig
/// recovery walks batches from 0 and stops at the first hole; dead epochs no
/// longer need that, but the discipline costs nothing).
///
/// Pure-data core, extracted for unit testing like
/// [`find_spent_utxos_pending_cleanup`].
fn find_tob_buckets_to_prune(
    keys: &[TobKey],
    committee_epochs: &BTreeSet<u64>,
    current_epoch: u64,
) -> Vec<TobPruneTarget> {
    use hashi_types::move_types::ProtocolType;

    // Saturating arithmetic throughout: key epochs come from on-chain field
    // names anyone can shape, and an overflow panic here would kill the
    // leader's prune task.
    let mut keygen_epochs: BTreeSet<u64> = BTreeSet::new();
    let mut nonce_batches: BTreeMap<u64, BTreeSet<u32>> = BTreeMap::new();
    for key in keys {
        match (key.protocol_type, key.batch_index) {
            (ProtocolType::Dkg | ProtocolType::KeyRotation, None) => {
                // The bound check both encodes "strictly between" and keeps
                // `range` from panicking on start > end for absurd epochs.
                let lower = key.epoch.saturating_add(1);
                let strictly_between = lower < current_epoch
                    && committee_epochs
                        .range(lower..current_epoch)
                        .next()
                        .is_some();
                if current_epoch >= key.epoch.saturating_add(KEY_GEN_CERT_RETENTION_EPOCHS)
                    && strictly_between
                {
                    keygen_epochs.insert(key.epoch);
                }
            }
            (ProtocolType::NonceGeneration, Some(batch_index))
                if current_epoch >= key.epoch.saturating_add(NONCE_CERT_MIN_AGE_EPOCHS) =>
            {
                nonce_batches
                    .entry(key.epoch)
                    .or_default()
                    .insert(batch_index);
            }
            _ => {}
        }
    }

    let epochs: BTreeSet<u64> = keygen_epochs
        .iter()
        .chain(nonce_batches.keys())
        .copied()
        .collect();
    let mut targets = Vec::new();
    for epoch in epochs {
        if keygen_epochs.contains(&epoch) {
            targets.push(TobPruneTarget::KeyGen { epoch });
        }
        if let Some(batches) = nonce_batches.get(&epoch) {
            targets.extend(
                batches
                    .iter()
                    .rev()
                    .map(|&batch_index| TobPruneTarget::NonceBatch { epoch, batch_index }),
            );
        }
    }
    targets.truncate(MAX_TOB_PRUNES_PER_GC);
    targets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain::types::Utxo;
    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::CommitteeSignature;
    use sui_sdk_types::Digest;

    /// Helper: build a `UtxoId` from a distinguishing byte and vout.
    fn utxo_id(byte: u8, vout: u32) -> UtxoId {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        UtxoId {
            txid: BitcoinTxid::new(bytes),
            vout,
        }
    }

    /// Helper: build a `UtxoRecord` with the given `spent_epoch`.
    fn record(spent_epoch: Option<u64>) -> UtxoRecord {
        UtxoRecord {
            utxo: Utxo {
                id: utxo_id(0, 0),
                amount: 1_000,
                derivation_path: None,
            },
            produced_by: None,
            spent_by: None,
            spent_epoch,
        }
    }

    fn deposit_request(
        id: u64,
        created_timestamp_ms: u64,
        approved_timestamp_ms: Option<u64>,
    ) -> DepositRequest {
        let mut id_bytes = [0; 32];
        id_bytes[24..].copy_from_slice(&id.to_be_bytes());
        DepositRequest {
            id: Address::new(id_bytes),
            sender: Address::ZERO,
            created_timestamp_ms,
            sui_tx_digest: Digest::new([0; 32]),
            utxo: Utxo {
                id: utxo_id(0, id as u32),
                amount: 1_000,
                derivation_path: None,
            },
            approval_cert: approved_timestamp_ms.map(|_| CommitteeSignature {
                epoch: 0,
                signature: Vec::new(),
                signers_bitmap: Vec::new(),
            }),
            approved_timestamp_ms,
            confirmed_timestamp_ms: None,
        }
    }

    #[test]
    fn deposit_expiration_uses_the_relevant_lifecycle_timestamp() {
        let unapproved = deposit_request(1, 100, None);
        let approved = deposit_request(2, 100, Some(100_000));
        let mut malformed = deposit_request(3, 100, None);
        malformed.approval_cert = approved.approval_cert.clone();

        assert_eq!(
            deposit_request_expiration_timestamp_ms(&unapproved),
            100 + MAX_DEPOSIT_REQUEST_AGE_MS
        );
        assert_eq!(
            deposit_request_expiration_timestamp_ms(&approved),
            100_000 + MAX_DEPOSIT_REQUEST_AGE_MS
        );
        assert_eq!(
            deposit_request_expiration_timestamp_ms(&malformed),
            100 + MAX_DEPOSIT_REQUEST_AGE_MS
        );
    }

    #[test]
    fn no_spent_utxos_returns_empty() {
        let utxo_records: BTreeMap<UtxoId, UtxoRecord> =
            BTreeMap::from([(utxo_id(1, 0), record(None)), (utxo_id(2, 0), record(None))]);

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert!(result.is_empty());
    }

    #[test]
    fn spent_utxo_found_for_cleanup() {
        let utxo_records = BTreeMap::from([(utxo_id(1, 0), record(Some(1)))]);

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], utxo_id(1, 0));
    }

    #[test]
    fn multiple_spent_utxos_found() {
        let utxo_records = BTreeMap::from([
            (utxo_id(1, 0), record(Some(1))),
            (utxo_id(2, 0), record(Some(2))),
            (utxo_id(3, 0), record(Some(1))),
        ]);

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn mixed_spent_and_unspent() {
        let utxo_records = BTreeMap::from([
            // Unspent
            (utxo_id(1, 0), record(None)),
            (utxo_id(2, 0), record(None)),
            // Spent
            (utxo_id(3, 0), record(Some(1))),
            (utxo_id(4, 0), record(Some(2))),
        ]);

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&utxo_id(3, 0)));
        assert!(result.contains(&utxo_id(4, 0)));
    }

    #[test]
    fn empty_utxo_records_returns_empty() {
        let utxo_records: BTreeMap<UtxoId, UtxoRecord> = BTreeMap::new();

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert!(result.is_empty());
    }

    #[test]
    fn scan_is_capped_per_gc() {
        let utxo_records: BTreeMap<UtxoId, UtxoRecord> = (0..MAX_UTXO_CLEANUPS_PER_GC as u32 + 7)
            .map(|i| (utxo_id((i % 251) as u8, i), record(Some(1))))
            .collect();

        let result = find_spent_utxos_pending_cleanup(&utxo_records);
        assert_eq!(result.len(), MAX_UTXO_CLEANUPS_PER_GC);
    }

    // ~~~~~~~ find_tob_buckets_to_prune ~~~~~~~

    use hashi_types::move_types::ProtocolType;

    fn nonce_key(epoch: u64, batch_index: u32) -> TobKey {
        TobKey {
            epoch,
            batch_index: Some(batch_index),
            protocol_type: ProtocolType::NonceGeneration,
        }
    }

    fn keygen_key(epoch: u64, protocol_type: ProtocolType) -> TobKey {
        TobKey {
            epoch,
            batch_index: None,
            protocol_type,
        }
    }

    fn epochs(list: &[u64]) -> BTreeSet<u64> {
        list.iter().copied().collect()
    }

    #[test]
    fn nonce_floor_is_exactly_two_epochs() {
        let keys = [nonce_key(8, 0), nonce_key(9, 0)];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[2, 10]), 10);
        assert_eq!(
            targets,
            vec![TobPruneTarget::NonceBatch {
                epoch: 8,
                batch_index: 0
            }]
        );
    }

    #[test]
    fn keygen_within_retention_kept() {
        // current-7 clears the committee guard (committee at 5 strictly
        // between) but sits inside the break-glass retention window.
        let keys = [keygen_key(3, ProtocolType::KeyRotation)];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[3, 5, 10]), 10);
        assert!(targets.is_empty());
    }

    #[test]
    fn keygen_requires_committee_strictly_between() {
        // Gap scenario: committees {2, 10} — the bucket at 2 belongs to the
        // PREVIOUS committee even though it clears the age floor, so it must
        // be kept. With a committee at 0 below it, the bucket at 0 goes.
        let keys = [keygen_key(2, ProtocolType::KeyRotation)];
        assert!(find_tob_buckets_to_prune(&keys, &epochs(&[2, 10]), 10).is_empty());

        let keys = [
            keygen_key(0, ProtocolType::Dkg),
            keygen_key(2, ProtocolType::KeyRotation),
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10]), 10);
        assert_eq!(targets, vec![TobPruneTarget::KeyGen { epoch: 0 }]);
    }

    #[test]
    fn keygen_selected_at_exact_retention_boundary() {
        // current == epoch + KEY_GEN_CERT_RETENTION_EPOCHS is the first
        // eligible epoch; one below is not.
        let keys = [keygen_key(2, ProtocolType::KeyRotation)];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[2, 5, 10]), 10);
        assert_eq!(targets, vec![TobPruneTarget::KeyGen { epoch: 2 }]);
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[2, 5, 9]), 9);
        assert!(targets.is_empty());
    }

    #[test]
    fn keygen_committee_at_exactly_epoch_plus_one_satisfies_guard() {
        // Pins the inclusive lower bound of the strictly-between range: a
        // committee at bucket_epoch + 1 is enough.
        let keys = [keygen_key(2, ProtocolType::KeyRotation)];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[3, 10]), 10);
        assert_eq!(targets, vec![TobPruneTarget::KeyGen { epoch: 2 }]);
    }

    #[test]
    fn keygen_pending_committee_does_not_satisfy_guard() {
        // A pending committee (epoch 12 > current 10) is in the committee
        // set but must not stand in for "strictly between".
        let keys = [keygen_key(2, ProtocolType::KeyRotation)];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[2, 10, 12]), 10);
        assert!(targets.is_empty());
    }

    #[test]
    fn current_and_pending_epoch_buckets_never_selected() {
        let keys = [
            nonce_key(10, 0),
            nonce_key(12, 0),
            keygen_key(10, ProtocolType::KeyRotation),
            keygen_key(12, ProtocolType::KeyRotation),
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10, 12]), 10);
        assert!(targets.is_empty());
    }

    #[test]
    fn ordering_oldest_epoch_first_nonce_batches_descending() {
        let keys = [
            nonce_key(3, 0),
            nonce_key(3, 1),
            nonce_key(0, 2),
            nonce_key(0, 0),
            nonce_key(0, 1),
            keygen_key(0, ProtocolType::Dkg),
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10]), 10);
        assert_eq!(
            targets,
            vec![
                TobPruneTarget::KeyGen { epoch: 0 },
                TobPruneTarget::NonceBatch {
                    epoch: 0,
                    batch_index: 2
                },
                TobPruneTarget::NonceBatch {
                    epoch: 0,
                    batch_index: 1
                },
                TobPruneTarget::NonceBatch {
                    epoch: 0,
                    batch_index: 0
                },
                TobPruneTarget::NonceBatch {
                    epoch: 3,
                    batch_index: 1
                },
                TobPruneTarget::NonceBatch {
                    epoch: 3,
                    batch_index: 0
                },
            ]
        );
    }

    #[test]
    fn cap_truncation_leaves_contiguous_prefix() {
        // One epoch with more batches than the cap: the selected batches are
        // the HIGHEST indices, so the survivors are exactly 0..m.
        let keys: Vec<TobKey> = (0..MAX_TOB_PRUNES_PER_GC as u32 + 7)
            .map(|i| nonce_key(1, i))
            .collect();
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[1, 10]), 10);
        assert_eq!(targets.len(), MAX_TOB_PRUNES_PER_GC);
        let selected: BTreeSet<u32> = targets
            .iter()
            .map(|t| match t {
                TobPruneTarget::NonceBatch { batch_index, .. } => *batch_index,
                other => panic!("unexpected target {other:?}"),
            })
            .collect();
        let expected: BTreeSet<u32> = (7..MAX_TOB_PRUNES_PER_GC as u32 + 7).collect();
        assert_eq!(selected, expected);
    }

    #[test]
    fn dkg_and_rotation_same_epoch_dedupe_to_one_keygen_target() {
        let keys = [
            keygen_key(0, ProtocolType::Dkg),
            keygen_key(0, ProtocolType::KeyRotation),
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10]), 10);
        assert_eq!(targets, vec![TobPruneTarget::KeyGen { epoch: 0 }]);
    }

    #[test]
    fn malformed_key_shapes_skipped() {
        // Nonce without a batch index, keygen with one: shapes the writers
        // never produce. Never destroy what we don't understand.
        let keys = [
            TobKey {
                epoch: 0,
                batch_index: None,
                protocol_type: ProtocolType::NonceGeneration,
            },
            TobKey {
                epoch: 0,
                batch_index: Some(1),
                protocol_type: ProtocolType::Dkg,
            },
            TobKey {
                epoch: 0,
                batch_index: Some(1),
                protocol_type: ProtocolType::KeyRotation,
            },
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10]), 10);
        assert!(targets.is_empty());
    }

    #[test]
    fn absurd_epochs_do_not_panic() {
        // Field names are attacker-shapeable; saturating arithmetic must
        // hold at the extremes.
        let keys = [
            nonce_key(u64::MAX, 0),
            keygen_key(u64::MAX, ProtocolType::Dkg),
        ];
        let targets = find_tob_buckets_to_prune(&keys, &epochs(&[0, 2, 10]), 10);
        assert!(targets.is_empty());
    }
}
