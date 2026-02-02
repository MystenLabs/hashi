use crate::Hashi;
use crate::config::ForceRunAsLeader;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::Proposal;
use crate::onchain::types::ProposalType;
use crate::sui_tx_executor::SuiTxExecutor;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::MemberSignature;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use std::sync::Arc;
use sui_sdk_types::Address;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;
const MAX_DEPOSIT_REQUEST_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 3; // 3 days
const DEPOSIT_REQUEST_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day
const MAX_DEPOSIT_REQUEST_DELETIONS_PER_GC: usize = 500;
const MAX_PROPOSAL_AGE_MS: u64 = 1000 * 60 * 60 * 24 * 7; // 7 days
const PROPOSAL_DELETE_DELAY_MS: u64 = 1000 * 60 * 60 * 24; // 1 day

#[derive(Clone)]
pub struct LeaderService {
    inner: Arc<Hashi>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self { inner: hashi }
    }

    // TODO: return a handle so we can gracefully shutdown, etc
    pub async fn start(self) -> () {
        info!("Starting leader service");
        let mut checkpoint_rx = self.inner.onchain_state().subscribe_checkpoint();

        loop {
            trace!("Waiting for next checkpoint...");
            let wait_result = checkpoint_rx.changed().await;
            if let Err(e) = wait_result {
                error!("Error waiting for checkpoint change: {e}");
                break;
            }
            let (checkpoint_height, checkpoint_timestamp_ms) = {
                let checkpoint_info = checkpoint_rx.borrow_and_update();
                (checkpoint_info.height, checkpoint_info.timestamp_ms)
            };

            if self.is_current_leader(checkpoint_height) {
                info!("Checkpoint {checkpoint_height}: We are the leader node");
            } else {
                trace!("We are not the leader node");
                continue;
            }

            self.process_deposit_requests(checkpoint_timestamp_ms).await;
            self.check_delete_proposals(checkpoint_timestamp_ms).await;
        }
    }

    pub fn is_current_leader(&self, checkpoint_height: u64) -> bool {
        match self.inner.config.force_run_as_leader() {
            ForceRunAsLeader::Always => return true,
            ForceRunAsLeader::Never => return false,
            ForceRunAsLeader::Default => (),
        }

        let onchain_state = self.inner.onchain_state();
        let state = onchain_state.state();
        let Some(committee) = state.hashi().committees.current_committee() else {
            // TODO: do we need to do anything when bootstrapping? At genesis there is no committee.
            return false;
        };
        let this_validator_address = self
            .inner
            .config
            .validator_address()
            .expect("No configured validator address");
        let Some(this_validator_idx) = committee
            .index_of(&this_validator_address)
            .map(|i| i as u64)
        else {
            // We are not in the committee yet, so we cannot be the leader
            return false;
        };
        let num_validators = committee.members().len() as u64;

        let current_turn = checkpoint_height / NUM_CONSECUTIVE_LEADER_CHECKPOINTS;
        let is_leader = (current_turn % num_validators) == this_validator_idx;

        debug!("Node index {this_validator_idx} is leader node: {is_leader}");
        is_leader
    }

    async fn process_deposit_requests(&self, checkpoint_timestamp_ms: u64) {
        let mut deposit_requests: Vec<_> = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .deposit_queue
                .requests()
                .values()
                .cloned()
                .collect()
        };
        // Sort deposit_requests by timestamp, from earliest to latest
        deposit_requests.sort_by_key(|r| r.timestamp_ms);

        info!("Processing {} deposit requests", deposit_requests.len());

        // TODO: parallelize?
        for deposit_request in &deposit_requests {
            self.process_deposit_request(deposit_request).await;
        }

        self.check_delete_expired_deposit_requests(&deposit_requests, checkpoint_timestamp_ms)
            .await;
    }

    async fn process_deposit_request(&self, deposit_request: &DepositRequest) {
        // TODO: parallelize, and after we have a quorum of sigs, stop waiting for sigs from any
        // additional validators
        info!("Processing deposit request: {:?}", deposit_request.id);

        // Validate deposit_request before asking for signatures
        let validate_result = self.inner.validate_deposit_request(deposit_request).await;
        if let Err(e) = validate_result {
            error!(
                "Deposit request {:?} failed validation: {e}",
                deposit_request.id
            );
            return;
        }
        info!(
            "Deposit request {:?} validated successfully",
            deposit_request.id
        );

        let proto_request = deposit_request.to_proto();
        let members = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .current_committee()
                .expect("No current committee")
                .members()
                .to_vec()
        };

        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) = self
                .request_deposit_confirmation_signature(proto_request.clone(), &member)
                .await
            {
                signatures.push(signature);
            }
        }

        let result = self
            .submit_deposit_confirmation(deposit_request.clone(), signatures)
            .await;
        if let Err(e) = result {
            error!(
                "Failed to submit deposit confirmation for deposit request:{deposit_request:?}: {e}"
            );
        }
    }

    async fn request_deposit_confirmation_signature(
        &self,
        proto_request: SignDepositConfirmationRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting deposit confirmation signature from {}",
            validator_address
        );

        let mut rpc_client = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .client(&validator_address)
                .or_else(|| {
                    error!(
                        "Cannot find client for validator address: {:?}",
                        validator_address
                    );
                    None
                })?
                .bridge_service_client()
        };

        let response = rpc_client
            .sign_deposit_confirmation(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get deposit confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved deposit confirmation signature from {}",
            validator_address
        );

        into_member_signature(response.into_inner())
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn submit_deposit_confirmation(
        &self,
        deposit_request: DepositRequest,
        signatures: Vec<MemberSignature>,
    ) -> anyhow::Result<()> {
        info!(
            "Aggregating signatures and submitting confirmation to hashi for deposit id {:?}",
            deposit_request.id
        );

        let committee = {
            let state = self.inner.onchain_state().state();
            state
                .hashi()
                .committees
                .current_committee()
                .expect("No current committee")
                .clone()
        };

        // Aggregate signatures
        let mut signature_aggregator =
            BlsSignatureAggregator::new(&committee, deposit_request.clone());
        for signature in signatures {
            signature_aggregator.add_signature(signature)?;
        }

        // Check for quorum
        // TODO: better way to check for quorom than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = 6667;
        if weight < required_weight {
            anyhow::bail!(
                "Aggregate weight of signatures {weight} is less than required weight {required_weight}"
            );
        }

        // Submit onchain
        let signed_message = signature_aggregator.finish()?;
        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_confirm_deposit(&deposit_request, signed_message)
            .await?;
        info!(
            "Successfully submitted deposit confirmation for request: {:?}",
            deposit_request.id
        );
        Ok(())
    }

    // Deposit requests comes sorted in ascending order, from oldest to newest
    async fn check_delete_expired_deposit_requests(
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
    async fn check_delete_proposals(&self, checkpoint_timestamp_ms: u64) {
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
                ProposalType::UpdateDepositFee => TypeTag::Struct(Box::new(StructTag::new(
                    hashi_ids.package_id,
                    Identifier::from_static("update_deposit_fee"),
                    Identifier::from_static("UpdateDepositFee"),
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
}

impl DepositRequest {
    fn to_proto(&self) -> SignDepositConfirmationRequest {
        SignDepositConfirmationRequest {
            id: self.id.as_bytes().to_vec().into(),
            txid: self.utxo.id.txid.as_bytes().to_vec().into(),
            vout: self.utxo.id.vout,
            amount: self.utxo.amount,
            derivation_path: self
                .utxo
                .derivation_path
                .map(|p| p.as_bytes().to_vec().into()),
            timestamp_ms: self.timestamp_ms,
        }
    }
}

fn into_member_signature(
    response: SignDepositConfirmationResponse,
) -> anyhow::Result<MemberSignature> {
    let member_signature = response.member_signature.ok_or(anyhow::anyhow!(
        "No member_signature in SignDepositConfirmationResponse"
    ))?;
    let epoch = member_signature
        .epoch
        .ok_or(anyhow::anyhow!("No epoch in MemberSignature"))?;
    let address_string = member_signature
        .address
        .ok_or(anyhow::anyhow!("No address in MemberSignature"))?;
    let address = address_string
        .parse::<Address>()
        .map_err(|e| anyhow::anyhow!("Unable to parse Address: {}", e))?;
    let signature = BLS12381Signature::from_bytes(
        member_signature
            .signature
            .ok_or(anyhow::anyhow!("No signature in MemberSignature"))?
            .as_bytes(),
    )?;
    Ok(MemberSignature::new(epoch, address, signature))
}
