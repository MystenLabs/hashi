mod garbage_collection;

use crate::Hashi;
use crate::config::ForceRunAsLeader;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::PendingWithdrawal;
use crate::onchain::types::WithdrawalRequest;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::WithdrawalApproval;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignWithdrawalApprovalRequest;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use std::sync::Arc;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;

#[derive(Clone)]
pub struct LeaderService {
    inner: Arc<Hashi>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self { inner: hashi }
    }

    /// Start the leader service and return a `Service` for lifecycle management.
    pub fn start(self) -> Service {
        Service::new().spawn_aborting(async move {
            self.run().await;
            Ok(())
        })
    }

    async fn run(self) {
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
                debug!("Checkpoint {checkpoint_height}: We are the leader node");
            } else {
                trace!("We are not the leader node");
                continue;
            }

            self.process_deposit_requests(checkpoint_timestamp_ms).await;
            self.process_withdrawal_requests().await;
            self.process_pending_withdrawals().await;
            self.check_delete_proposals(checkpoint_timestamp_ms).await;
            self.check_delete_spent_utxos().await;
        }
    }

    pub fn is_current_leader(&self, checkpoint_height: u64) -> bool {
        match self.inner.config.force_run_as_leader() {
            ForceRunAsLeader::Always => return true,
            ForceRunAsLeader::Never => return false,
            ForceRunAsLeader::Default => (),
        }

        let Some(committee) = self.inner.onchain_state().current_committee() else {
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
        let mut deposit_requests = self.inner.onchain_state().deposit_requests();
        // Sort deposit_requests by timestamp, from earliest to latest
        deposit_requests.sort_by_key(|r| r.timestamp_ms);

        debug!("Processing {} deposit requests", deposit_requests.len());

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
        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

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

        let mut rpc_client = self
            .inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

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

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
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

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        // Aggregate signatures
        let mut signature_aggregator =
            BlsSignatureAggregator::new(&committee, deposit_request.clone());
        for signature in signatures {
            signature_aggregator.add_signature(signature)?;
        }

        // Check for quorum
        // TODO: better way to check for quorom than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
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

    // ========================================================================
    // Withdrawal processing
    // ========================================================================

    async fn process_withdrawal_requests(&self) {
        let mut withdrawal_requests = self.inner.onchain_state().withdrawal_requests();
        withdrawal_requests.sort_by_key(|r| r.timestamp_ms);

        // TODO: process multiple at a time.
        // For now we only process one to avoid a race condition on utxo selection
        if let Some(request) = withdrawal_requests.first() {
            self.process_withdrawal_request(request).await;
        }
    }

    async fn process_withdrawal_request(&self, request: &WithdrawalRequest) {
        info!("Processing withdrawal request: {:?}", request.id);

        // 1. Run AML/Sanctions checks for the withdrawal request
        if let Err(e) = self.inner.screen_withdrawal(request).await {
            error!("Withdrawal request {:?} failed AML Checks: {e}", request.id);
            return;
        }

        // 2. Build the withdrawal approval (craft unsigned BTC tx, select UTXOs, etc.)
        let approval = match self.inner.build_withdrawal_approval(request).await {
            Ok(approval) => approval,
            Err(e) => {
                error!(
                    "Failed to build withdrawal approval for request {:?}: {e}",
                    request.id
                );
                return;
            }
        };

        // 3. Fan out to committee for BLS approval signatures
        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let proto_request = approval.to_proto();
        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in &members {
            if let Some(signature) = self
                .request_withdrawal_approval_signature(proto_request.clone(), member)
                .await
            {
                signatures.push(signature);
            }
        }

        // 4. Aggregate BLS signatures and check quorum
        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let mut signature_aggregator = BlsSignatureAggregator::new(&committee, approval.clone());
        for signature in signatures {
            if let Err(e) = signature_aggregator.add_signature(signature) {
                error!("Failed to add withdrawal approval signature: {e}");
            }
        }

        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            error!(
                "Insufficient withdrawal approval signatures for request {:?}: weight {weight} < {required_weight}",
                request.id
            );
            return;
        }

        let signed_approval = match signature_aggregator.finish() {
            Ok(signed_approval) => signed_approval,
            Err(e) => {
                error!(
                    "Failed to build withdrawal approval certificate for request {:?}: {e}",
                    request.id
                );
                return;
            }
        };

        // 5. Commit on Sui via pick_withdrawal_for_processing
        if let Err(e) = self
            .submit_pick_withdrawal_for_processing(&approval, signed_approval.committee_signature())
            .await
        {
            error!(
                "Failed to submit pick_withdrawal_for_processing for request {:?}: {e}",
                request.id
            );
        }
    }

    // ========================================================================
    // Pending withdrawal processing (MPC signing, broadcast, confirm)
    // ========================================================================

    async fn process_pending_withdrawals(&self) {
        let mut pending_withdrawals = self.inner.onchain_state().pending_withdrawals();
        pending_withdrawals.sort_by_key(|p| p.timestamp_ms);

        // TODO: process multiple at a time.
        // For now we only process one to avoid a race condition on utxo selection
        if let Some(pending) = pending_withdrawals.first() {
            self.process_pending_withdrawal(pending).await;
        }
    }

    async fn process_pending_withdrawal(&self, pending: &PendingWithdrawal) {
        info!("Processing pending withdrawal: {:?}", pending.id);

        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        // 1. Request signed withdrawal tx witnesses from committee members.
        // MPC signing requires all threshold members to participate simultaneously
        // via P2P, so we must fan out requests in parallel.
        let Some(signatures_by_input) = self
            .collect_withdrawal_tx_signatures(&pending.id, &members)
            .await
        else {
            return;
        };

        // 2. Build signed tx, then broadcast.

        let tx = match self.build_broadcastable_withdrawal_tx(pending, &signatures_by_input) {
            Ok(tx) => tx,
            Err(e) => {
                error!(
                    "Failed to build signed withdrawal tx for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        let txid = tx.compute_txid();
        if let Err(e) = self.inner.btc_monitor().broadcast_transaction(tx).await {
            error!(
                "Failed to broadcast withdrawal bitcoin tx for {:?} (txid {}): {e}",
                pending.id, txid
            );
            return;
        }

        info!(
            "Broadcasted withdrawal bitcoin tx for {:?} (txid {})",
            pending.id, txid
        );

        let confirmation_signature = match self
            .collect_withdrawal_confirmation_signature(pending.id, &members)
            .await
        {
            Ok(signature) => signature,
            Err(e) => {
                error!(
                    "Failed to gather withdrawal confirmation cert for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        // 3. Confirm withdrawal on Sui
        if let Err(e) = self
            .submit_confirm_withdrawal(&pending.id, &confirmation_signature)
            .await
        {
            error!("Failed to confirm withdrawal {:?}: {e}", pending.id);
        }
    }

    async fn collect_withdrawal_confirmation_signature(
        &self,
        pending_id: Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) = self
                .request_withdrawal_confirmation_signature(pending_id, member)
                .await
            {
                signatures.push(signature);
            }
        }

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");
        let confirmation = crate::withdrawals::WithdrawalConfirmation {
            withdrawal_id: pending_id,
        };
        let mut signature_aggregator = BlsSignatureAggregator::new(&committee, confirmation);
        for signature in signatures {
            if let Err(e) = signature_aggregator.add_signature(signature) {
                error!("Failed to add withdrawal confirmation signature: {e}");
            }
        }

        // TODO: better way to check for quorum than hardcoding
        let weight = signature_aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            anyhow::bail!(
                "Insufficient withdrawal confirmation signatures for pending {:?}: weight {weight} < {required_weight}",
                pending_id
            );
        }

        Ok(signature_aggregator.finish()?.into_parts().0)
    }

    fn build_broadcastable_withdrawal_tx(
        &self,
        pending: &PendingWithdrawal,
        signatures: &[SchnorrSignature],
    ) -> anyhow::Result<bitcoin::Transaction> {
        info!(
            "Building broadcastable withdrawal tx for pending withdrawal id {} with {} signatures",
            pending.id,
            signatures.len()
        );
        let mut tx = self
            .inner
            .build_unsigned_withdrawal_tx(&pending.inputs, &pending.outputs)?;

        anyhow::ensure!(
            tx.input.len() == signatures.len(),
            "Signature count mismatch: {} inputs but {} signatures",
            tx.input.len(),
            signatures.len()
        );

        for (input, signature) in tx.input.iter_mut().zip(signatures) {
            let mut witness = bitcoin::Witness::new();
            witness.push(signature.to_byte_array());
            input.witness = witness;
        }

        Ok(tx)
    }

    async fn request_withdrawal_approval_signature(
        &self,
        proto_request: SignWithdrawalApprovalRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal approval signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_approval(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal approval signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal approval signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal approval response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn request_withdrawal_tx_signature(
        &self,
        pending_withdrawal_id: &Address,
        member: &CommitteeMember,
    ) -> anyhow::Result<Vec<SchnorrSignature>> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal tx signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                )
            })?;

        let proto_request = SignWithdrawalTransactionRequest {
            pending_withdrawal_id: pending_withdrawal_id.as_bytes().to_vec().into(),
        };

        let response = rpc_client
            .sign_withdrawal_transaction(proto_request)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to get withdrawal tx signature from {validator_address}: {e}"
                )
            })?;

        trace!(
            "Retrieved withdrawal tx signature from {}",
            validator_address
        );

        response
            .into_inner()
            .signatures_by_input
            .iter()
            .map(|sig_bytes| {
                let bytes: [u8; 64] = sig_bytes.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("Invalid Schnorr signature length from {validator_address}")
                })?;
                SchnorrSignature::from_byte_array(&bytes).map_err(|e| {
                    anyhow::anyhow!("Invalid Schnorr signature from {validator_address}: {e}")
                })
            })
            .collect()
    }

    async fn collect_withdrawal_tx_signatures(
        &self,
        pending_withdrawal_id: &Address,
        members: &[CommitteeMember],
    ) -> Option<Vec<SchnorrSignature>> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| self.request_withdrawal_tx_signature(pending_withdrawal_id, member))
            .collect();
        let results = futures::future::join_all(futures).await;

        let mut results = results.into_iter();
        loop {
            match results.next() {
                Some(Ok(signatures)) => return Some(signatures),
                Some(Err(_)) => continue,
                None => {
                    error!(
                        "Could not get mpc signatures for {:?}; stopping processing",
                        pending_withdrawal_id
                    );
                    return None;
                }
            }
        }
    }

    async fn request_withdrawal_confirmation_signature(
        &self,
        pending_withdrawal_id: Address,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal confirmation signature from {}",
            validator_address
        );

        let mut rpc_client = self
            .inner
            .onchain_state()
            .bridge_service_client(&validator_address)
            .or_else(|| {
                error!(
                    "Cannot find client for validator address: {:?}",
                    validator_address
                );
                None
            })?;

        let response = rpc_client
            .sign_withdrawal_confirmation(SignWithdrawalConfirmationRequest {
                pending_withdrawal_id: pending_withdrawal_id.as_bytes().to_vec().into(),
            })
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal confirmation signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

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

    async fn submit_pick_withdrawal_for_processing(
        &self,
        approval: &WithdrawalApproval,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!(
            "Submitting pick_withdrawal_for_processing for txid {:?}",
            approval.txid
        );

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_pick_withdrawal_for_processing(approval, cert)
            .await
    }

    async fn submit_confirm_withdrawal(
        &self,
        pending_withdrawal_id: &Address,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Confirming withdrawal {:?}", pending_withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_confirm_withdrawal(pending_withdrawal_id, cert)
            .await?;

        info!(
            "Successfully confirmed withdrawal {:?}",
            pending_withdrawal_id
        );
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

fn parse_member_signature(
    member_signature: hashi_types::proto::MemberSignature,
) -> anyhow::Result<MemberSignature> {
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

impl WithdrawalApproval {
    fn to_proto(&self) -> SignWithdrawalApprovalRequest {
        SignWithdrawalApprovalRequest {
            request_ids: self
                .request_ids
                .iter()
                .map(|id| id.as_bytes().to_vec().into())
                .collect(),
            selected_utxos: self
                .selected_utxos
                .iter()
                .map(|utxo_id| hashi_types::proto::UtxoId {
                    txid: Some(utxo_id.txid.as_bytes().to_vec().into()),
                    vout: Some(utxo_id.vout),
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| hashi_types::proto::WithdrawalOutput {
                    amount: output.amount,
                    bitcoin_address: output.bitcoin_address.clone().into(),
                })
                .collect(),
            txid: self.txid.as_bytes().to_vec().into(),
        }
    }
}
