// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Garbage collection for expired on-chain data.

use super::LeaderService;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::UtxoId;
use crate::onchain::types::UtxoRecord;
use crate::sui_tx_executor::SuiTxExecutor;
use std::collections::BTreeMap;
use std::sync::Arc;
use sui_sdk_types::Address;
use tokio_util::task::AbortOnDropHandle;
use tracing::debug;
use tracing::error;
use tracing::info;

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

impl LeaderService {
    /// Check for and delete expired deposit requests.
    /// Deposit requests are sorted by timestamp and deleted if they are older than
    /// MAX_DEPOSIT_REQUEST_AGE_MS.
    pub(super) fn check_delete_expired_deposit_requests(&mut self, checkpoint_timestamp_ms: u64) {
        if self.deposit_gc_task.is_some() {
            debug!("Deposit GC task already in-flight, skipping");
            return;
        }

        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        deposit_requests.sort_by_key(|r| r.created_timestamp_ms);

        let Some(oldest_request) = deposit_requests.first() else {
            return;
        };

        if checkpoint_timestamp_ms
            < oldest_request.created_timestamp_ms
                + MAX_DEPOSIT_REQUEST_AGE_MS
                + DEPOSIT_REQUEST_DELETE_DELAY_MS
        {
            return;
        }

        let expired_requests: Vec<_> = deposit_requests
            .iter()
            .filter(|r| {
                checkpoint_timestamp_ms > r.created_timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS
            })
            .take(MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC)
            .cloned()
            .collect();
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
    /// task that refreshes the UTXO-pool mirror from chain, scans it for
    /// spent-but-uncleaned records, and cleans them. The scan is armed at
    /// boot (crash-between-confirm-and-cleanup recovery), whenever a
    /// withdrawal confirms on Sui, and after a task that did work or failed.
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
        self.utxo_cleanup_gc_task = Some(AbortOnDropHandle::new(tokio::task::spawn(async move {
            Self::cleanup_spent_utxos(inner).await
        })));
    }

    /// Scrape a fresh task-local snapshot of the on-chain UTXO pool, then
    /// clean every record it shows as spent-but-uncleaned. Returns how many
    /// UTXOs were cleaned so the caller can decide whether to re-arm the
    /// scan (more work may exist past the per-GC cap).
    ///
    /// Deciding from a fresh chain read — never from the shared mirror — is
    /// what makes the tx worth paying for: the mirror overstates pending
    /// cleanups whenever another leader cleaned records (`cleanup_spent`
    /// emits no event), and submitting from it re-cleans those records as
    /// paid on-chain no-ops. The mirror itself is left untouched; the
    /// watcher task is its sole writer.
    async fn cleanup_spent_utxos(inner: Arc<crate::Hashi>) -> anyhow::Result<usize> {
        let pool = inner.onchain_state().scrape_utxo_pool_snapshot().await?;
        let utxo_ids = find_spent_utxos_pending_cleanup(pool.utxo_records());
        if utxo_ids.is_empty() {
            return Ok(0);
        }

        info!(
            utxo_count = utxo_ids.len(),
            "Cleaning up spent UTXO(s) pending cleanup",
        );
        let mut executor = SuiTxExecutor::from_hashi(inner)?;
        executor.execute_cleanup_spent_utxos(&utxo_ids).await?;
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
                    hashi_ids.package_id,
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
}

/// Return UTXO IDs whose `spent_epoch` is set — these are spent UTXOs
/// still present in `utxo_records` that need to be cleaned up on-chain.
/// Capped at [`MAX_UTXO_CLEANUPS_PER_GC`]; the remainder is picked up by a
/// later scan.
///
/// This is the pure-data core of [`LeaderService::discover_orphaned_utxo_cleanups`],
/// extracted so it can be unit-tested without constructing a full `LeaderService`.
fn find_spent_utxos_pending_cleanup(utxo_records: &BTreeMap<UtxoId, UtxoRecord>) -> Vec<UtxoId> {
    utxo_records
        .iter()
        .filter(|(_, record)| record.spent_epoch.is_some())
        .map(|(id, _)| *id)
        .take(MAX_UTXO_CLEANUPS_PER_GC)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain::types::Utxo;
    use hashi_types::bitcoin_txid::BitcoinTxid;

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
}
