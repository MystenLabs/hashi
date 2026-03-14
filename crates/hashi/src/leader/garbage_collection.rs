//! Garbage collection for expired on-chain data.

use super::LeaderService;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::onchain::types::UtxoId;
use crate::sui_tx_executor::SuiTxExecutor;
use sui_sdk_types::Address;
use tracing::error;
use tracing::info;

const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days
const DEPOSIT_REQUEST_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day
const MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC: usize = 500;

const MAX_PROPOSAL_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days
const PROPOSAL_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day

const MAX_SPENT_UTXO_AGE_EPOCHS: u64 = 7; // 7 epochs
const SPENT_UTXO_DELETE_DELAY_EPOCHS: u64 = 1; // 1 epoch
const MAX_SPENT_UTXO_DELETIONS_PER_GC: usize = 500;

impl LeaderService {
    /// Check for and delete expired deposit requests.
    /// Deposit requests are sorted by timestamp and deleted if they are older than MAX_DEPOSIT_REQUEST_AGE_MS.
    pub(crate) async fn check_delete_expired_deposit_requests(
        &self,
        deposit_requests: &[DepositRequest],
        checkpoint_timestamp_ms: u64,
    ) {
        // Check if it's time to delete
        let Some(oldest_request) = deposit_requests.first() else {
            return;
        };
        // If there aren't any deposit requests at least 4 days old, don't do anything
        if checkpoint_timestamp_ms
            < oldest_request.timestamp_ms
                + MAX_DEPOSIT_REQUEST_AGE_MS
                + DEPOSIT_REQUEST_DELETE_DELAY_MS
        {
            return;
        }

        // Find all expired requests (older than 3 days)
        let expired_requests = deposit_requests
            .iter()
            .filter(|r| checkpoint_timestamp_ms > r.timestamp_ms + MAX_DEPOSIT_REQUEST_AGE_MS)
            .take(MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC)
            .cloned()
            .collect::<Vec<_>>();

        info!(
            "Deleting {} expired deposit requests",
            expired_requests.len()
        );

        let result = async {
            let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
            executor
                .execute_delete_expired_deposit_requests(&expired_requests)
                .await
        }
        .await;

        if let Err(e) = result {
            error!("Failed to delete expired deposit requests: {e}");
        } else {
            info!(
                "Successfully deleted {} expired deposit requests",
                expired_requests.len()
            );
        }
    }

    /// Check for and delete expired proposals.
    /// Proposals are sorted by timestamp and deleted if they are older than MAX_PROPOSAL_AGE_MS.
    pub(crate) async fn check_delete_proposals(&self, checkpoint_timestamp_ms: u64) {
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

        // Find all expired proposals (older than 7 days)
        let expired_proposals: Vec<_> = proposals
            .iter()
            .filter(|p| checkpoint_timestamp_ms > p.timestamp_ms + MAX_PROPOSAL_AGE_MS)
            .cloned()
            .collect();

        if expired_proposals.is_empty() {
            return;
        }

        info!("Deleting {} expired proposals", expired_proposals.len());

        let result = self
            .delete_expired_proposals_batch(&expired_proposals)
            .await;
        if let Err(e) = result {
            error!("Failed to delete expired proposals: {e}");
        } else {
            info!(
                "Successfully deleted {} expired proposals",
                expired_proposals.len()
            );
        }
    }

    async fn delete_expired_proposals_batch(
        &self,
        expired_proposals: &[Proposal],
    ) -> anyhow::Result<()> {
        use sui_sdk_types::Identifier;
        use sui_sdk_types::StructTag;
        use sui_sdk_types::TypeTag;
        use sui_transaction_builder::Function;
        use sui_transaction_builder::ObjectInput;
        use sui_transaction_builder::TransactionBuilder;

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        let hashi_ids = self.inner.config.hashi_ids();

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
        for proposal in expired_proposals {
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
        Ok(())
    }

    /// Check for and delete expired spent UTXOs.
    /// Spent UTXOs are sorted by spent_epoch and deleted if they are older than MAX_SPENT_UTXO_AGE_EPOCHS.
    pub(crate) async fn check_delete_spent_utxos(&self) {
        let mut spent_utxos_sorted = self.inner.onchain_state().spent_utxos_entries();
        spent_utxos_sorted.sort_by_key(|(_, epoch)| *epoch);
        let current_epoch = self.inner.onchain_state().epoch();

        // Check if it's time to delete
        let Some((_, oldest_epoch)) = spent_utxos_sorted.first() else {
            return;
        };

        // If there aren't any spent UTXOs at least 8 epochs old (7 epochs max + 1 epoch delay), don't do anything
        if current_epoch < oldest_epoch + MAX_SPENT_UTXO_AGE_EPOCHS + SPENT_UTXO_DELETE_DELAY_EPOCHS
        {
            return;
        }

        // Find all expired spent UTXOs (older than 7 epochs)
        let expired_utxo_ids: Vec<UtxoId> = spent_utxos_sorted
            .iter()
            .filter(|(_, spent_epoch)| current_epoch > spent_epoch + MAX_SPENT_UTXO_AGE_EPOCHS)
            .take(MAX_SPENT_UTXO_DELETIONS_PER_GC)
            .map(|(id, _)| *id)
            .collect();

        if expired_utxo_ids.is_empty() {
            return;
        }

        info!("Deleting {} expired spent UTXOs", expired_utxo_ids.len());

        let result = self
            .delete_expired_spent_utxos_batch(&expired_utxo_ids)
            .await;
        if let Err(e) = result {
            error!("Failed to delete expired spent UTXOs: {e}");
        } else {
            info!(
                "Successfully deleted {} expired spent UTXOs",
                expired_utxo_ids.len()
            );
        }
    }

    async fn delete_expired_spent_utxos_batch(
        &self,
        expired_utxo_ids: &[UtxoId],
    ) -> anyhow::Result<()> {
        use sui_sdk_types::Identifier;
        use sui_transaction_builder::Function;
        use sui_transaction_builder::ObjectInput;
        use sui_transaction_builder::TransactionBuilder;

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        let hashi_ids = self.inner.config.hashi_ids();

        let mut builder = TransactionBuilder::new();

        let hashi_arg = builder.object(
            ObjectInput::new(hashi_ids.hashi_object_id)
                .as_shared()
                .with_mutable(true),
        );

        // Add a move call for each expired spent UTXO
        for utxo_id in expired_utxo_ids {
            let txid_arg = builder.pure(&utxo_id.txid);
            let vout_arg = builder.pure(&utxo_id.vout);

            builder.move_call(
                Function::new(
                    hashi_ids.package_id,
                    Identifier::from_static("withdraw"),
                    Identifier::from_static("delete_expired_spent_utxo"),
                ),
                vec![hashi_arg, txid_arg, vout_arg],
            );
        }

        let response = executor.execute(builder).await?;
        if !response.transaction().effects().status().success() {
            anyhow::bail!("Transaction failed to delete expired spent UTXOs");
        }
        Ok(())
    }
}
