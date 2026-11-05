// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Garbage collection for expired on-chain data.

use super::LeaderService;
use crate::onchain::TobKey;
use crate::onchain::TobKeyPage;
use crate::onchain::TobPruneTarget;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::UtxoId;
use crate::onchain::types::UtxoRecord;
use crate::sui_tx_executor::ArchiveVictim;
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

/// Runtime-object budget for one GC transaction. Sui admits at most 1000
/// child objects into a transaction's object-runtime cache
/// (`object_runtime_max_num_cached_objects`); the next dynamic-field load
/// fails with `MovePrimitiveRuntimeError` inside `sui::dynamic_field`. A
/// probe of an absent key counts like a load. The leader only submits what
/// simulates, so an oversized sweep never lands, and because every sweep
/// picks the oldest victims it retries the same batch forever: the backlog
/// grows and the GC never recovers on its own. Same budget as the withdrawal
/// flow: 922 leaves 7.8% headroom below the hard cap.
const GC_RUNTIME_OBJECT_BUDGET: usize =
    crate::withdrawals::WITHDRAWAL_ARCHIVE_RUNTIME_OBJECT_BUDGET;

const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24; // 1 day
const DEPOSIT_REQUEST_DELETE_DELAY_MS: u64 = 1000 * 60; // 1 minute

/// Runtime-object cost of `deposit::delete_expired_deposit`: the
/// `BitcoinState` dynamic field once per transaction, then per request the
/// `processed` probe (one `Field`) and the `requests` ObjectBag remove
/// (`Field` plus child). Measured on testnet against the deployed package:
/// a PTB of 333 deletions simulates, 334 fails on its 1000th load.
const DEPOSIT_DELETE_FIXED_RUNTIME_OBJECTS: usize = 1;
const DEPOSIT_DELETE_RUNTIME_OBJECTS_PER_REQUEST: usize = 3;
const MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC: usize = (GC_RUNTIME_OBJECT_BUDGET
    - DEPOSIT_DELETE_FIXED_RUNTIME_OBJECTS)
    / DEPOSIT_DELETE_RUNTIME_OBJECTS_PER_REQUEST;

const MAX_PROPOSAL_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days
const PROPOSAL_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day

/// Runtime-object cost of `proposal::delete_expired`, one command per
/// proposal: the `executed` probe (one `Field`) and the `active` ObjectBag
/// remove (`Field` plus child). The bags hang off a plain `Hashi` field, so
/// nothing is loaded up front; the fixed term is slack. Modeled, not
/// measured: same shape as the deposit delete.
const PROPOSAL_DELETE_FIXED_RUNTIME_OBJECTS: usize = 1;
const PROPOSAL_DELETE_RUNTIME_OBJECTS_PER_PROPOSAL: usize = 3;
const MAX_PROPOSAL_DELETIONS_PER_GC: usize = (GC_RUNTIME_OBJECT_BUDGET
    - PROPOSAL_DELETE_FIXED_RUNTIME_OBJECTS)
    / PROPOSAL_DELETE_RUNTIME_OBJECTS_PER_PROPOSAL;

/// Runtime-object cost of `cleanup_spent_utxos`, one command for the whole
/// batch: the `BitcoinState` dynamic field once, then per UTXO the
/// `utxo_records` probe (one `Field`; the remove reuses the cache) and the
/// `spent_utxos` add, whose existence check probes one more `Field`.
/// Modeled, not measured: at the old cap of 500 the last add would be the
/// 1000th load.
const UTXO_CLEANUP_FIXED_RUNTIME_OBJECTS: usize = 1;
const UTXO_CLEANUP_RUNTIME_OBJECTS_PER_UTXO: usize = 2;
const MAX_UTXO_CLEANUPS_PER_GC: usize = (GC_RUNTIME_OBJECT_BUDGET
    - UTXO_CLEANUP_FIXED_RUNTIME_OBJECTS)
    / UTXO_CLEANUP_RUNTIME_OBJECTS_PER_UTXO;

/// Sui's hard object-runtime cache limit, and the testnet measurement the
/// deposit model has to reproduce: 333 deletions fit, 334 do not. A change
/// to either deposit coefficient must come with a new measurement.
const SUI_OBJECT_RUNTIME_CACHE_LIMIT: usize = 1000;
const _: () = assert!(
    DEPOSIT_DELETE_FIXED_RUNTIME_OBJECTS + DEPOSIT_DELETE_RUNTIME_OBJECTS_PER_REQUEST * 333
        <= SUI_OBJECT_RUNTIME_CACHE_LIMIT
);
const _: () = assert!(
    DEPOSIT_DELETE_FIXED_RUNTIME_OBJECTS + DEPOSIT_DELETE_RUNTIME_OBJECTS_PER_REQUEST * 334
        > SUI_OBJECT_RUNTIME_CACHE_LIMIT
);
const _: () = assert!(GC_RUNTIME_OBJECT_BUDGET < SUI_OBJECT_RUNTIME_CACHE_LIMIT);

/// Sui's per-PTB command ceiling. The per-command sweeps above are bound by
/// the object budget first; this pins the ordering so a cheaper Move path
/// cannot push a cap past the command limit unnoticed.
const MAX_PTB_COMMANDS: usize = 1024;
const _: () = assert!(MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC <= MAX_PTB_COMMANDS);
const _: () = assert!(MAX_PROPOSAL_DELETIONS_PER_GC <= MAX_PTB_COMMANDS);

// Cap how many TOB cert buckets one prune sweep destroys. Lower than the
// caps above because each destroyed bucket is much heavier than one deleted
// record: it drains a whole LinkedTable (~80 object deletions on a full
// committee), so the per-transaction chunk in
// `execute_destroy_tob_certs` is small and a sweep is several transactions.
// A larger backlog drains over successive sweeps.
const MAX_TOB_PRUNES_PER_GC: usize = 200;

const MAX_TOB_PRUNE_PAGES_PER_SWEEP: usize = 10;

const MAX_TOB_PRUNE_SWEEP_FAILURES: u32 = 3;

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

/// The active on-chain version that carries the destroy entries: every
/// version of the squashed package.
const TOB_PRUNE_MIN_PACKAGE_VERSION: u64 = 1;

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

// Cap the archival scan so one GC task stays bounded; a larger backlog
// drains over successive checkpoints, oldest confirmations first.
const MAX_WITHDRAWAL_ARCHIVES_PER_GC: usize = 500;

// `archive_confirmed_withdrawals` ships in every version of the squashed
// package.
const WITHDRAWAL_ARCHIVE_MIN_PACKAGE_VERSION: u64 = 1;

/// Failure kind for the withdrawal archival GC. Unbounded retries for the
/// same reason as [`UtxoCleanupErrorKind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WithdrawalArchiveErrorKind {
    Failed,
}

impl crate::leader::retry::RetryPolicy for WithdrawalArchiveErrorKind {
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

#[derive(Debug)]
pub(super) struct TobPruneOutcome {
    pub(super) next_page_token: Option<bytes::Bytes>,
    pub(super) found_destroyable: bool,
}

#[derive(Debug, Default)]
pub(super) struct TobPruneSchedule {
    pass: Option<TobPrunePass>,
    drained_epoch: Option<u64>,
    last_turn: Option<u64>,
    failures: u32,
}

#[derive(Debug)]
struct TobPrunePass {
    started_epoch: u64,
    resume_token: Option<bytes::Bytes>,
    found_destroyable: bool,
}

impl TobPruneSchedule {
    pub(super) fn is_due(&self, current_epoch: u64, turn: u64) -> bool {
        self.drained_epoch != Some(current_epoch) && self.last_turn != Some(turn)
    }

    pub(super) fn begin(&mut self, current_epoch: u64, turn: u64) -> Option<bytes::Bytes> {
        self.last_turn = Some(turn);
        self.pass
            .get_or_insert_with(|| TobPrunePass {
                started_epoch: current_epoch,
                resume_token: None,
                found_destroyable: false,
            })
            .resume_token
            .clone()
    }

    pub(super) fn finish(&mut self, outcome: &TobPruneOutcome) {
        self.failures = 0;
        let Some(pass) = self.pass.as_mut() else {
            return;
        };
        pass.found_destroyable |= outcome.found_destroyable;
        match &outcome.next_page_token {
            Some(token) => pass.resume_token = Some(token.clone()),
            None => {
                if !pass.found_destroyable {
                    self.drained_epoch = Some(pass.started_epoch);
                }
                self.pass = None;
            }
        }
    }

    pub(super) fn fail(&mut self) {
        self.failures += 1;
        if self.failures >= MAX_TOB_PRUNE_SWEEP_FAILURES {
            self.failures = 0;
            self.pass = None;
        }
    }
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
    /// confirms on Sui, after a task that did work or failed, and by the
    /// disarmed-state mirror probe below.
    pub(super) fn check_cleanup_spent_utxos(&mut self, checkpoint_timestamp_ms: u64) {
        if self.utxo_cleanup_gc_task.is_some() {
            debug!("UTXO cleanup GC task already in-flight, skipping");
            return;
        }

        if !self.utxo_cleanup_scan_needed {
            // The arming flag is local, and a confirm can land without this
            // node's broadcast result path observing it (another leader
            // submitted it, the task timeout truncated the result, or it
            // was submitted out-of-band); the retained-txn filter then
            // blocks any retry from re-emitting ConfirmedOnSui. The spent
            // records are still visible in every mirror, so probe for them
            // rather than trust the flag alone.
            if !has_spent_utxos_pending_cleanup(&self.inner.onchain_state().utxo_records()) {
                return;
            }
            self.utxo_cleanup_scan_needed = true;
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

    /// Kick the deferred-archival GC for confirmed withdrawals. Shape and
    /// arming protocol mirror [`Self::check_cleanup_spent_utxos`]; the extra
    /// version gate exists because the archival entry only exists in v2
    /// bytecode. It gates on the withdrawal-EFFECTIVE version (the active
    /// version): every published version of the squashed package defers
    /// archival to this GC.
    pub(super) fn check_archive_confirmed_withdrawals(&mut self, checkpoint_timestamp_ms: u64) {
        if self.withdrawal_archive_gc_task.is_some() {
            debug!("Withdrawal archival GC task already in-flight, skipping");
            return;
        }

        let Some(active) = self.inner.onchain_state().active_package_version() else {
            return;
        };
        if active < WITHDRAWAL_ARCHIVE_MIN_PACKAGE_VERSION {
            return;
        }

        if !self.withdrawal_archive_scan_needed {
            // Mirror probe matching the cleanup arm in
            // `check_cleanup_spent_utxos`: a confirm whose ConfirmedOnSui
            // result never reached this node still leaves its txn visible
            // as confirmed in the mirror, and no retry can re-emit the
            // result once the mirror shows the confirm.
            if !has_confirmed_withdrawals_pending_archive(
                &self.inner.onchain_state().withdrawal_txns(),
            ) {
                return;
            }
            self.withdrawal_archive_scan_needed = true;
        }

        if self
            .withdrawal_archive_retry
            .should_skip(checkpoint_timestamp_ms)
        {
            debug!("Withdrawal archival GC in backoff, skipping");
            return;
        }

        self.withdrawal_archive_scan_needed = false;
        let inner = self.inner.clone();
        let scan_target = self.withdrawal_archive_scan_target;
        self.withdrawal_archive_gc_task =
            Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
                Self::archive_confirmed_withdrawals(inner, scan_target).await
            })));
    }

    /// Scan the mirror for confirmed-but-unarchived withdrawal txns and
    /// archive them (moving each txn to `confirmed_txns` and its requests to
    /// `processed` on-chain). Returns how many were archived so the caller
    /// can re-arm past the per-GC cap. Freshness protocol identical to
    /// [`Self::cleanup_spent_utxos`].
    async fn archive_confirmed_withdrawals(
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
            anyhow::bail!(
                "mirror did not reach the archival scan target checkpoint {scan_target} within \
                 {VISIBILITY_TIMEOUT:?}"
            );
        }
        let withdrawal_txns = inner.onchain_state().withdrawal_txns();
        let victims = find_confirmed_withdrawals_pending_archive(&withdrawal_txns);
        if victims.is_empty() {
            return Ok(0);
        }

        info!(
            txn_count = victims.len(),
            "Archiving confirmed withdrawal(s) pending archival",
        );
        let mut executor = SuiTxExecutor::from_hashi(inner.clone())?;
        let landed_at = executor
            .execute_archive_confirmed_withdrawals(&victims)
            .await?;
        if tokio::time::timeout(
            VISIBILITY_TIMEOUT,
            inner.onchain_state().wait_until_checkpoint(landed_at),
        )
        .await
        .is_err()
        {
            warn!(
                landed_at,
                "Timeout waiting for the mirror to reach the archival checkpoint; \
                 the next scan may resubmit already-archived txns"
            );
        }
        info!(
            txn_count = victims.len(),
            "Successfully archived confirmed withdrawals",
        );
        Ok(victims.len())
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
        let hashi_initial_shared_version = crate::cli::client::fetch_initial_shared_version(
            &mut inner.onchain_state().client(),
            hashi_ids.hashi_object_id,
        )
        .await?;

        let mut builder = TransactionBuilder::new();

        // Fully-resolved shared inputs: expired proposals may carry
        // upgrade-introduced type args (e.g. IgnoreMember), which the
        // fullnode's simulate-time resolver cannot inspect on sui >= 1.76
        // unless every shared input is pre-resolved.
        let hashi_arg = builder.object(
            ObjectInput::new(hashi_ids.hashi_object_id)
                .with_version(hashi_initial_shared_version)
                .as_shared()
                .with_mutable(true),
        );

        // Clock object (0x6) - immutable shared object
        let clock_arg = builder.object(
            ObjectInput::new(Address::from_static("0x6"))
                .with_version(1)
                .as_shared()
                .with_mutable(false),
        );

        // Add a move call for each expired proposal
        let package_versions = inner.onchain_state().state().package_versions().clone();
        for proposal in &expired_proposals {
            let proposal_id_arg = builder.pure(&proposal.id);

            let Some(package_version) = proposal.proposal_type.package_version() else {
                error!(
                    "Cannot delete proposal {:?} with unknown type: {:?}",
                    proposal.id, proposal.proposal_type
                );
                continue;
            };
            let Some(type_package_id) = package_versions.get(package_version) else {
                error!(
                    "Cannot delete proposal {:?}: defining package version {} for {} is not published",
                    proposal.id,
                    package_version,
                    proposal.proposal_type.as_str()
                );
                continue;
            };

            // Get the type argument for the proposal
            let type_arg = match &proposal.proposal_type {
                ProposalType::UpdateConfig => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("update_config"),
                    Identifier::from_static("UpdateConfig"),
                    vec![],
                ))),
                ProposalType::UpdateEpochConfig => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("update_epoch_config"),
                    Identifier::from_static("UpdateEpochConfig"),
                    vec![],
                ))),
                ProposalType::AddConfig => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("add_config"),
                    Identifier::from_static("AddConfig"),
                    vec![],
                ))),
                ProposalType::EnableVersion => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("enable_version"),
                    Identifier::from_static("EnableVersion"),
                    vec![],
                ))),
                ProposalType::DisableVersion => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("disable_version"),
                    Identifier::from_static("DisableVersion"),
                    vec![],
                ))),
                ProposalType::Upgrade => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("upgrade"),
                    Identifier::from_static("Upgrade"),
                    vec![],
                ))),
                ProposalType::EmergencyPause => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("emergency_pause"),
                    Identifier::from_static("EmergencyPause"),
                    vec![],
                ))),
                ProposalType::IgnoreMember => TypeTag::Struct(Box::new(StructTag::new(
                    type_package_id,
                    Identifier::from_static("ignore_member"),
                    Identifier::from_static("IgnoreMember"),
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

            // Active package: the type arg may name an upgrade-introduced
            // type, and calling the original package alongside it is a
            // linkage conflict (see build_vote_transaction).
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

    pub(super) fn check_prune_tob_certs(
        &mut self,
        checkpoint_height: u64,
        checkpoint_timestamp_ms: u64,
    ) {
        if self.tob_prune_task.is_some() {
            debug!("TOB prune task already in-flight, skipping");
            return;
        }
        let Some(active) = self.inner.onchain_state().active_package_version() else {
            return;
        };
        if active < TOB_PRUNE_MIN_PACKAGE_VERSION {
            return;
        }
        let current_epoch = self.inner.onchain_state().epoch();
        let turn = super::leader_turn(checkpoint_height);
        if !self.tob_prune_schedule.is_due(current_epoch, turn) {
            return;
        }
        if self.tob_prune_retry.should_skip(checkpoint_timestamp_ms) {
            debug!("TOB prune GC in backoff, skipping");
            return;
        }
        let resume_token = self.tob_prune_schedule.begin(current_epoch, turn);
        let inner = self.inner.clone();
        self.tob_prune_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::prune_tob_certs(inner, resume_token).await
        })));
    }

    async fn prune_tob_certs(
        inner: Arc<crate::Hashi>,
        resume_token: Option<bytes::Bytes>,
    ) -> anyhow::Result<TobPruneOutcome> {
        let (committee_epochs, current_epoch) = {
            let state = inner.onchain_state().state();
            let committees = &state.hashi().committees;
            (
                committees.committees().keys().copied().collect(),
                committees.epoch(),
            )
        };
        let onchain = inner.onchain_state();
        let (targets, next_page_token) = collect_tob_prune_targets(
            move |token| onchain.list_tob_key_page(token),
            resume_token,
            &committee_epochs,
            current_epoch,
        )
        .await?;
        let pass_continues = next_page_token.is_some();
        if targets.is_empty() {
            debug!(
                pass_continues,
                "No TOB cert buckets eligible for pruning in this sweep"
            );
            return Ok(TobPruneOutcome {
                next_page_token,
                found_destroyable: false,
            });
        }
        info!(
            target_count = targets.len(),
            pass_continues, "Destroying dead TOB cert bucket(s)"
        );
        let mut executor = SuiTxExecutor::from_hashi(inner)?;
        let skipped = executor.execute_destroy_tob_certs(&targets).await?;
        info!(
            target_count = targets.len(),
            skipped_count = skipped.len(),
            "Finished destroying dead TOB cert buckets"
        );
        Ok(TobPruneOutcome {
            next_page_token,
            found_destroyable: targets.len() > skipped.len(),
        })
    }
}

async fn collect_tob_prune_targets<F, Fut>(
    mut list_page: F,
    resume_token: Option<bytes::Bytes>,
    committee_epochs: &BTreeSet<u64>,
    current_epoch: u64,
) -> anyhow::Result<(Vec<TobPruneTarget>, Option<bytes::Bytes>)>
where
    F: FnMut(Option<bytes::Bytes>) -> Fut,
    Fut: Future<Output = anyhow::Result<TobKeyPage>>,
{
    let mut targets = Vec::new();
    let mut token = resume_token;
    for page_index in 0..MAX_TOB_PRUNE_PAGES_PER_SWEEP {
        let page = match list_page(token.clone()).await {
            Ok(page) => page,
            Err(e) if page_index > 0 => {
                warn!("Listing the TOB bag failed mid-sweep; keeping what was collected: {e:#}");
                break;
            }
            Err(e) => return Err(e),
        };
        for target in find_tob_buckets_to_prune(&page.keys, committee_epochs, current_epoch) {
            if targets.len() == MAX_TOB_PRUNES_PER_GC {
                break;
            }
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        token = page.next_page_token;
        if token.is_none() || targets.len() == MAX_TOB_PRUNES_PER_GC {
            break;
        }
    }
    Ok((targets, token))
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

/// Disarmed-state probe for the cleanup scan's arming gate: whether the
/// mirror holds any spent-but-uncleaned UTXO record. The arming flag is
/// local to one node, so records left by a confirm this node's result path
/// never observed would otherwise strand until an unrelated confirm re-arms
/// whichever node is leader.
fn has_spent_utxos_pending_cleanup(utxo_records: &BTreeMap<UtxoId, UtxoRecord>) -> bool {
    utxo_records
        .values()
        .any(|record| record.spent_epoch.is_some())
}

/// Disarmed-state probe for the archival scan's arming gate, the
/// withdrawal-archive twin of [`has_spent_utxos_pending_cleanup`].
fn has_confirmed_withdrawals_pending_archive(
    withdrawal_txns: &[crate::onchain::types::WithdrawalTransaction],
) -> bool {
    withdrawal_txns.iter().any(|txn| txn.is_confirmed())
}

/// Confirmed-but-unarchived withdrawal txns, oldest confirmation first so a
/// capped backlog drains FIFO. Each victim carries its request ids so the
/// executor can pack GC transactions against the runtime-object budget and
/// chunk oversized txns through the split archival entries.
fn find_confirmed_withdrawals_pending_archive(
    withdrawal_txns: &[crate::onchain::types::WithdrawalTransaction],
) -> Vec<ArchiveVictim> {
    let mut confirmed: Vec<_> = withdrawal_txns
        .iter()
        .filter(|txn| txn.is_confirmed())
        .collect();
    confirmed.sort_by_key(|txn| txn.confirmed_timestamp_ms);
    confirmed
        .into_iter()
        .take(MAX_WITHDRAWAL_ARCHIVES_PER_GC)
        .map(|txn| ArchiveVictim {
            txn_id: txn.id,
            request_ids: txn.request_ids.clone(),
        })
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
/// key-generation target first, then nonce batches DESCENDING by index,
/// truncated at [`MAX_TOB_PRUNES_PER_GC`]. The sweep calls this once per page,
/// so across pages targets come in the bag's hash order.
///
/// Pure-data core, extracted for unit testing like
/// [`find_spent_utxos_pending_cleanup`].
fn find_tob_buckets_to_prune(
    keys: &[TobKey],
    committee_epochs: &BTreeSet<u64>,
    current_epoch: u64,
) -> Vec<TobPruneTarget> {
    use hashi_types::move_types::ProtocolType;

    // Saturating arithmetic throughout: bag writes are committee-gated
    // (submit entries assert membership and current/pending epoch), but the
    // pruner treats field-name epochs as untrusted data anyway; an overflow
    // panic here would kill the leader's prune task.
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
    use crate::onchain::types::WithdrawalTransaction;
    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::CommitteeSignature;
    use hashi_types::move_types::SigningBatch;
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
    fn expired_deposit_scan_is_capped_per_gc() {
        let now = 10 * MAX_DEPOSIT_REQUEST_AGE_MS;
        let requests: Vec<DepositRequest> = (0..MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC as u64 + 7)
            .map(|i| deposit_request(i, i, None))
            .collect();

        let result = find_expired_deposit_requests(requests, now);
        assert_eq!(result.len(), MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC);
        // oldest first, so the overflow that waits for the next sweep is the youngest
        assert_eq!(result[0].created_timestamp_ms, 0);
        assert_eq!(
            result[result.len() - 1].created_timestamp_ms,
            MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC as u64 - 1
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

    /// Helper: build a `WithdrawalTransaction` that is confirmed or not.
    fn withdrawal_txn(byte: u8, confirmed: bool) -> WithdrawalTransaction {
        WithdrawalTransaction {
            id: Address::new([byte; 32]),
            txid: BitcoinTxid::new([byte; 32]),
            request_ids: vec![],
            inputs: vec![],
            withdrawal_outputs: vec![],
            change_outputs: vec![],
            created_timestamp_ms: 0,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: confirmed.then_some(1),
            randomness: vec![],
            signing: SigningBatch {
                signatures: vec![],
                epoch: 0,
            },
            guardian_signatures: None,
        }
    }

    /// The disarmed-state probe must arm only when a spent record actually
    /// exists in the mirror; anything else would re-arm every leader tick.
    #[test]
    fn cleanup_probe_requires_a_spent_record() {
        assert!(!has_spent_utxos_pending_cleanup(&BTreeMap::new()));
        assert!(!has_spent_utxos_pending_cleanup(&BTreeMap::from([(
            utxo_id(1, 0),
            record(None)
        )])));
        assert!(has_spent_utxos_pending_cleanup(&BTreeMap::from([
            (utxo_id(1, 0), record(None)),
            (utxo_id(2, 0), record(Some(3))),
        ])));
    }

    /// The archival twin: arm only on a confirmed-but-unarchived txn.
    #[test]
    fn archive_probe_requires_a_confirmed_txn() {
        assert!(!has_confirmed_withdrawals_pending_archive(&[]));
        assert!(!has_confirmed_withdrawals_pending_archive(&[
            withdrawal_txn(1, false)
        ]));
        assert!(has_confirmed_withdrawals_pending_archive(&[
            withdrawal_txn(1, false),
            withdrawal_txn(2, true),
        ]));
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

    fn page(keys: Vec<TobKey>, next: Option<usize>) -> TobKeyPage {
        TobKeyPage {
            keys,
            next_page_token: next.map(|index| bytes::Bytes::from(index.to_string())),
        }
    }

    async fn sweep(
        bag: &[TobKeyPage],
        resume_token: Option<bytes::Bytes>,
    ) -> (Vec<TobPruneTarget>, Option<bytes::Bytes>) {
        collect_tob_prune_targets(
            |token: Option<bytes::Bytes>| {
                let index = token.map_or(0, |token| {
                    std::str::from_utf8(&token).unwrap().parse().unwrap()
                });
                std::future::ready(anyhow::Ok(bag[index].clone()))
            },
            resume_token,
            &epochs(&[0, 2, 10]),
            10,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn capped_sweep_resumes_from_its_token() {
        let bag = [
            page((0..150).map(|i| nonce_key(1, i)).collect(), Some(1)),
            page((150..250).map(|i| nonce_key(1, i)).collect(), Some(2)),
            page((0..10).map(|i| nonce_key(3, i)).collect(), None),
        ];
        let (targets, token) = sweep(&bag, None).await;
        assert_eq!(targets.len(), MAX_TOB_PRUNES_PER_GC);
        assert_eq!(token, bag[1].next_page_token);
        let (targets, token) = sweep(&bag, token).await;
        assert_eq!(targets.len(), 10);
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn sweep_stops_at_its_page_budget() {
        let pages = MAX_TOB_PRUNE_PAGES_PER_SWEEP + 2;
        let bag: Vec<TobKeyPage> = (0..pages)
            .map(|i| {
                page(
                    vec![nonce_key(10, i as u32)],
                    (i + 1 < pages).then_some(i + 1),
                )
            })
            .collect();
        let (targets, token) = sweep(&bag, None).await;
        assert!(targets.is_empty());
        assert_eq!(
            token,
            bag[MAX_TOB_PRUNE_PAGES_PER_SWEEP - 1].next_page_token
        );
        let (_, token) = sweep(&bag, token).await;
        assert_eq!(token, None);
    }

    #[tokio::test]
    async fn failed_later_page_keeps_what_was_collected() {
        let first = page(vec![nonce_key(1, 0)], Some(1));
        let list_page = |token: Option<bytes::Bytes>| {
            std::future::ready(match token {
                None => anyhow::Ok(first.clone()),
                Some(_) => Err(anyhow::anyhow!("unavailable")),
            })
        };
        let (targets, token) = collect_tob_prune_targets(list_page, None, &epochs(&[0, 2, 10]), 10)
            .await
            .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(token, first.next_page_token);
        assert!(
            collect_tob_prune_targets(list_page, token, &epochs(&[0, 2, 10]), 10)
                .await
                .is_err()
        );
    }

    fn swept(next_page_token: Option<&'static str>, found_destroyable: bool) -> TobPruneOutcome {
        TobPruneOutcome {
            next_page_token: next_page_token
                .map(|token| bytes::Bytes::from_static(token.as_bytes())),
            found_destroyable,
        }
    }

    #[test]
    fn pass_marks_the_epoch_it_started_under_drained() {
        let mut schedule = TobPruneSchedule::default();
        assert_eq!(schedule.begin(5, 1), None);
        schedule.finish(&swept(Some("next"), false));
        assert!(!schedule.is_due(5, 1));
        assert!(schedule.is_due(6, 2));
        assert_eq!(
            schedule.begin(6, 2),
            swept(Some("next"), false).next_page_token
        );
        schedule.finish(&swept(None, false));
        assert!(!schedule.is_due(5, 3));
        assert!(schedule.is_due(6, 3));
    }

    #[test]
    fn pass_that_found_targets_is_not_drained() {
        let mut schedule = TobPruneSchedule::default();
        schedule.begin(5, 1);
        schedule.finish(&swept(Some("next"), true));
        schedule.begin(5, 2);
        schedule.finish(&swept(None, false));
        assert!(schedule.is_due(5, 3));
        assert_eq!(schedule.begin(5, 3), None);
        schedule.finish(&swept(None, false));
        assert!(!schedule.is_due(5, 4));
    }

    #[test]
    fn repeated_failures_start_the_pass_over() {
        let next = swept(Some("next"), false).next_page_token;
        let mut schedule = TobPruneSchedule::default();
        schedule.begin(5, 1);
        schedule.finish(&swept(Some("next"), false));
        for turn in 2..4 {
            assert_eq!(schedule.begin(5, turn), next);
            schedule.fail();
        }
        assert_eq!(schedule.begin(5, 4), next);
        schedule.finish(&swept(Some("next"), false));
        for turn in 5..7 {
            assert_eq!(schedule.begin(5, turn), next);
            schedule.fail();
        }
        assert_eq!(schedule.begin(5, 7), next);
        schedule.fail();
        assert_eq!(schedule.begin(5, 8), None);
    }
}
