mod garbage_collection;
mod retry;
pub(crate) use retry::RetryPolicy;

use crate::Hashi;
use crate::btc_monitor::monitor::TxStatus;
use crate::config::ForceRunAsLeader;
use crate::deposits::DepositValidationErrorKind;
use crate::leader::retry::RetryTracker;
use crate::onchain::types::DepositRequest;
use crate::onchain::types::PendingWithdrawal;
use crate::onchain::types::WithdrawalRequest;
use crate::sui_tx_executor::SuiTxExecutor;
use crate::withdrawals::CpfpTxSigning;
use crate::withdrawals::WithdrawalApprovalErrorKind;
use crate::withdrawals::WithdrawalCommitmentErrorKind;
use crate::withdrawals::WithdrawalRequestApproval;
use crate::withdrawals::WithdrawalTxCommitment;
use crate::withdrawals::WithdrawalTxSigning;
use bitcoin::hashes::Hash;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::groups::secp256k1::schnorr::SchnorrSignature;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::CommitteeSignature;
use hashi_types::committee::MemberSignature;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::bitcoin_utils;
use hashi_types::proto::SignCpfpTransactionRequest;
use hashi_types::proto::SignCpfpTxSigningRequest;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalRequestApprovalRequest;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTxConstructionRequest;
use hashi_types::proto::SignWithdrawalTxSigningRequest;
use std::sync::Arc;
use sui_futures::service::Service;
use sui_sdk_types::Address;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;
use x509_parser::nom::AsBytes;

const NUM_CONSECUTIVE_LEADER_CHECKPOINTS: u64 = 100;

pub struct LeaderService {
    inner: Arc<Hashi>,
    deposit_retry_tracker: RetryTracker<DepositValidationErrorKind>,
    withdrawal_approval_retry_tracker: RetryTracker<WithdrawalApprovalErrorKind>,
    withdrawal_commitment_retry_tracker: RetryTracker<WithdrawalCommitmentErrorKind>,
}

impl LeaderService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self {
            inner: hashi,
            deposit_retry_tracker: RetryTracker::new(),
            withdrawal_approval_retry_tracker: RetryTracker::new(),
            withdrawal_commitment_retry_tracker: RetryTracker::new(),
        }
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
            self.process_unapproved_withdrawal_requests(checkpoint_timestamp_ms)
                .await;
            self.process_approved_withdrawal_requests(checkpoint_timestamp_ms)
                .await;
            self.process_unsigned_pending_withdrawals().await;
            self.process_signed_pending_withdrawals(checkpoint_timestamp_ms)
                .await;
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
        let deposit_ids: Vec<Address> = deposit_requests.iter().map(|r| r.id).collect();
        self.deposit_retry_tracker.prune(&deposit_ids);

        debug!("Processing {} deposit requests", deposit_requests.len());

        // TODO: parallelize?
        for deposit_request in &deposit_requests {
            self.process_deposit_request(deposit_request, checkpoint_timestamp_ms)
                .await;
        }

        self.check_delete_expired_deposit_requests(&deposit_requests, checkpoint_timestamp_ms)
            .await;
    }

    async fn process_deposit_request(
        &self,
        deposit_request: &DepositRequest,
        checkpoint_timestamp_ms: u64,
    ) {
        // TODO: parallelize, and after we have a quorum of sigs, stop waiting for sigs from any
        // additional validators

        if self
            .deposit_retry_tracker
            .should_skip(&deposit_request.id, checkpoint_timestamp_ms)
        {
            return;
        }

        info!("Processing deposit request: {:?}", deposit_request.id);

        // Validate deposit_request before asking for signatures
        match self.inner.validate_deposit_request(deposit_request).await {
            Ok(()) => {
                self.deposit_retry_tracker.clear(&deposit_request.id);
            }
            Err(e) => {
                self.deposit_retry_tracker.record_failure(
                    e.kind(),
                    deposit_request.id,
                    checkpoint_timestamp_ms,
                );
                return;
            }
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
    // Step 1: Approve unapproved withdrawal requests
    // ========================================================================

    async fn process_unapproved_withdrawal_requests(&self, checkpoint_timestamp_ms: u64) {
        let mut unapproved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| !r.approved)
            .collect();
        unapproved.sort_by_key(|r| r.timestamp_ms);

        let unapproved_ids: Vec<Address> = unapproved.iter().map(|r| r.id).collect();
        self.withdrawal_approval_retry_tracker
            .prune(&unapproved_ids);

        if unapproved.is_empty() {
            return;
        }

        let this_validator_address = self
            .inner
            .config
            .validator_address()
            .expect("No configured validator address");

        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        // Collect a per-request BLS certificate for each unapproved request.
        // Validators independently validate each request (including sanctions checks),
        let mut certified: Vec<(Address, CommitteeSignature)> = Vec::new();
        for request in &unapproved {
            if self
                .withdrawal_approval_retry_tracker
                .should_skip(&request.id, checkpoint_timestamp_ms)
            {
                continue;
            }

            let approval = WithdrawalRequestApproval {
                request_id: request.id,
            };

            // Validate, screen, and sign locally first
            let local_sig = match self
                .inner
                .validate_and_sign_withdrawal_request_approval(&approval)
                .await
            {
                Ok(sig) => {
                    self.withdrawal_approval_retry_tracker.clear(&request.id);
                    parse_member_signature(sig).unwrap()
                }
                Err(e) => {
                    self.withdrawal_approval_retry_tracker.record_failure(
                        e.kind(),
                        request.id,
                        checkpoint_timestamp_ms,
                    );
                    continue;
                }
            };

            let proto_request = approval.to_proto();
            let mut signatures: Vec<MemberSignature> = vec![local_sig];
            for member in &members {
                if member.validator_address() == this_validator_address {
                    continue;
                }
                if let Some(signature) = self
                    .request_withdrawal_approval_signature(proto_request.clone(), member)
                    .await
                {
                    signatures.push(signature);
                }
            }

            let mut aggregator = BlsSignatureAggregator::new(&committee, approval);
            for sig in signatures {
                if let Err(e) = aggregator.add_signature(sig) {
                    error!("Failed to add approval signature for {:?}: {e}", request.id);
                }
            }

            let weight = aggregator.weight();
            let required_weight = certificate_threshold(committee.total_weight());
            if weight < required_weight {
                self.withdrawal_approval_retry_tracker.record_failure(
                    WithdrawalApprovalErrorKind::FailedQuorum,
                    request.id,
                    checkpoint_timestamp_ms,
                );
                error!(
                    "Insufficient approval signatures for {:?}: weight {weight} < {required_weight}",
                    request.id
                );
                continue;
            }

            match aggregator.finish() {
                Ok(signed) => {
                    certified.push((request.id, signed.committee_signature().clone()));
                }
                Err(e) => {
                    error!(
                        "Failed to build approval certificate for {:?}: {e}",
                        request.id
                    );
                }
            }
        }

        if certified.is_empty() {
            return;
        }

        // Submit all certified approvals in a single PTB.
        // On failure (e.g. a request was canceled mid-flight), remove the
        // offending request and retry until we succeed or run out of requests.
        self.submit_approve_withdrawal_requests_with_retry(certified)
            .await;
    }

    async fn submit_approve_withdrawal_requests_with_retry(
        &self,
        mut certified: Vec<(Address, CommitteeSignature)>,
    ) {
        loop {
            let approvals: Vec<(Address, &CommitteeSignature)> =
                certified.iter().map(|(id, cert)| (*id, cert)).collect();

            match self.submit_approve_withdrawal_requests(&approvals).await {
                Ok(()) => return,
                Err(e) => {
                    let err_msg = format!("{e}");
                    error!("approve_request PTB failed: {err_msg}");

                    // Try to identify which request caused the failure by checking
                    // which ones no longer exist in the queue (canceled).
                    let before_len = certified.len();
                    certified.retain(|(id, _)| {
                        self.inner.onchain_state().withdrawal_request(id).is_some()
                    });

                    if certified.len() == before_len {
                        error!("Could not identify failed request, aborting retry");
                        return;
                    }
                    if certified.is_empty() {
                        return;
                    }

                    info!(
                        "Retrying approve_request with {} remaining requests",
                        certified.len()
                    );
                }
            }
        }
    }

    // ========================================================================
    // Step 2: Construct withdrawal tx for approved requests
    // ========================================================================

    async fn process_approved_withdrawal_requests(&self, checkpoint_timestamp_ms: u64) {
        let mut approved: Vec<_> = self
            .inner
            .onchain_state()
            .withdrawal_requests()
            .into_iter()
            .filter(|r| r.approved)
            .collect();
        approved.sort_by_key(|r| r.timestamp_ms);

        let approved_ids: Vec<Address> = approved.iter().map(|r| r.id).collect();
        self.withdrawal_commitment_retry_tracker
            .prune(&approved_ids);

        // Process the first approved request that isn't in backoff.
        for request in &approved {
            if self
                .withdrawal_commitment_retry_tracker
                .should_skip(&request.id, checkpoint_timestamp_ms)
            {
                continue;
            }
            self.process_approved_withdrawal_request(request, checkpoint_timestamp_ms)
                .await;
            break;
        }
    }

    async fn process_approved_withdrawal_request(
        &self,
        request: &WithdrawalRequest,
        checkpoint_timestamp_ms: u64,
    ) {
        info!("Processing approved withdrawal request: {:?}", request.id);

        // Build the withdrawal tx commitment
        let approval = match self.inner.build_withdrawal_tx_commitment(request).await {
            Ok(approval) => {
                self.withdrawal_commitment_retry_tracker.clear(&request.id);
                approval
            }
            Err(e) => {
                self.withdrawal_commitment_retry_tracker.record_failure(
                    e.kind(),
                    request.id,
                    checkpoint_timestamp_ms,
                );
                return;
            }
        };

        // Fan out to committee for BLS signatures over the commitment message
        let members = self
            .inner
            .onchain_state()
            .current_committee_members()
            .expect("No current committee members");
        let proto_request = approval.to_proto();
        let mut signatures: Vec<MemberSignature> = Vec::new();
        for member in &members {
            if let Some(signature) = self
                .request_withdrawal_tx_commitment_signature(proto_request.clone(), member)
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
            self.withdrawal_commitment_retry_tracker.record_failure(
                WithdrawalCommitmentErrorKind::FailedQuorum,
                request.id,
                checkpoint_timestamp_ms,
            );
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

        // 5. Submit commit_withdrawal_tx to Sui
        if let Err(e) = self
            .submit_commit_withdrawal_tx(&approval, signed_approval.committee_signature())
            .await
        {
            error!(
                "Failed to submit commit_withdrawal_tx for request {:?}: {e}",
                request.id
            );
        }
    }

    // ========================================================================
    // Step 3: MPC sign pending withdrawals and store signatures on-chain
    // ========================================================================

    async fn process_unsigned_pending_withdrawals(&self) {
        let mut pending_withdrawals = self.inner.onchain_state().pending_withdrawals();
        pending_withdrawals.retain(|p| p.signatures.is_none());
        pending_withdrawals.sort_by_key(|p| p.timestamp_ms);

        // TODO: process multiple at a time.
        if let Some(pending) = pending_withdrawals.first() {
            self.process_unsigned_pending_withdrawal(pending).await;
        }
    }

    async fn process_unsigned_pending_withdrawal(&self, pending: &PendingWithdrawal) {
        info!("MPC signing pending withdrawal: {:?}", pending.id);

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

        // 2. Extract raw signature bytes for on-chain storage
        let witness_signatures: Vec<Vec<u8>> = signatures_by_input
            .iter()
            .map(|s| s.to_byte_array().to_vec())
            .collect();

        // 3. Build the WithdrawalTxSigning and get BLS certificate via fan-out
        let signed_message = WithdrawalTxSigning {
            withdrawal_id: pending.id,
            request_ids: pending.request_ids(),
            signatures: witness_signatures.clone(),
        };

        let proto_request = signed_message.to_proto();
        let mut bls_signatures: Vec<MemberSignature> = Vec::new();
        for member in &members {
            if let Some(signature) = self
                .request_withdrawal_tx_signing_signature(proto_request.clone(), member)
                .await
            {
                bls_signatures.push(signature);
            }
        }

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .expect("No current committee");

        let mut aggregator = BlsSignatureAggregator::new(&committee, signed_message.clone());
        for sig in bls_signatures {
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add withdrawal sign message signature: {e}");
            }
        }

        let weight = aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            error!(
                "Insufficient signatures for sign_withdrawal {:?}: weight {weight} < {required_weight}",
                pending.id
            );
            return;
        }

        let signed = match aggregator.finish() {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Failed to build sign_withdrawal certificate for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        // 4. Submit sign_withdrawal to Sui (writes signatures on-chain).
        // Broadcast + confirm happens via process_signed_pending_withdrawals on the next tick.
        if let Err(e) = self
            .submit_sign_withdrawal(
                &pending.id,
                &pending.request_ids(),
                &witness_signatures,
                signed.committee_signature(),
            )
            .await
        {
            error!("Failed to submit sign_withdrawal for {:?}: {e}", pending.id);
        }
    }

    // ========================================================================
    // Step 4-5: Broadcast signed tx and confirm on-chain
    // ========================================================================

    async fn process_signed_pending_withdrawals(&self, checkpoint_timestamp_ms: u64) {
        let mut pending_withdrawals = self.inner.onchain_state().pending_withdrawals();
        pending_withdrawals.retain(|p| p.signatures.is_some());
        pending_withdrawals.sort_by_key(|p| p.timestamp_ms);

        for pending in &pending_withdrawals {
            self.handle_signed_withdrawal(pending, checkpoint_timestamp_ms)
                .await;
        }
    }

    /// Check BTC tx status, broadcast/re-broadcast if needed, confirm when
    /// enough BTC confirmations are reached. Uses on-chain timestamps to initiate CPFP transaction
    async fn handle_signed_withdrawal(
        &self,
        pending: &PendingWithdrawal,
        checkpoint_timestamp_ms: u64,
    ) {
        let confirmation_threshold = self.inner.onchain_state().bitcoin_confirmation_threshold();
        let txid = bitcoin::Txid::from_byte_array(pending.txid.into());

        // If CPFP was submitted, also check the child tx status
        let effective_txid = if let Some(ref cpfp) = pending.cpfp_info {
            bitcoin::Txid::from_byte_array(cpfp.txid.into())
        } else {
            txid
        };

        match self
            .inner
            .btc_monitor()
            .get_transaction_status(effective_txid)
            .await
        {
            Ok(TxStatus::Confirmed { confirmations })
                if confirmations >= confirmation_threshold =>
            {
                info!(
                    "Withdrawal tx {} confirmed with {confirmations} confirmations, \
                     proceeding to on-chain confirmation for {:?}",
                    effective_txid, pending.id
                );
                self.confirm_withdrawal_on_sui(pending).await;
            }
            Ok(TxStatus::Confirmed { confirmations }) => {
                debug!(
                    "Withdrawal tx {} has {confirmations}/{confirmation_threshold} \
                     confirmations, waiting for more",
                    effective_txid
                );
            }
            Ok(TxStatus::InMempool) => {
                debug!(
                    "Withdrawal tx {} in mempool for {:?}, waiting for confirmations",
                    effective_txid, pending.id
                );
                self.maybe_trigger_cpfp(pending, checkpoint_timestamp_ms)
                    .await;
            }
            Ok(TxStatus::NotFound) => {
                if pending.cpfp_info.is_some() {
                    // CPFP child was submitted but not found, rebuild and rebroadcast both
                    self.broadcast_cpfp_package(pending, None).await;
                } else {
                    self.rebuild_and_broadcast_withdrawal_btc_tx(pending, txid)
                        .await;
                }
                self.maybe_trigger_cpfp(pending, checkpoint_timestamp_ms)
                    .await;
            }
            Err(e) => {
                error!(
                    "Failed to query transaction status for {:?} (txid {}): {e}",
                    pending.id, effective_txid
                );
            }
        }
    }

    /// Trigger CPFP if a signed withdrawal has been unconfirmed for longer than `cpfp_trigger_after_ms`
    async fn maybe_trigger_cpfp(&self, pending: &PendingWithdrawal, checkpoint_timestamp_ms: u64) {
        // Don't trigger CPFP if already submitted
        if pending.cpfp_info.is_some() {
            return;
        }

        let threshold_ms = self.inner.config.cpfp_trigger_after_ms();
        let elapsed_ms = checkpoint_timestamp_ms.saturating_sub(pending.timestamp_ms);

        if elapsed_ms >= threshold_ms {
            info!(
                "Withdrawal {:?} has been unconfirmed for {}ms (threshold: {}ms), \
                 triggering CPFP",
                pending.id, elapsed_ms, threshold_ms
            );
            self.process_cpfp_for_withdrawal(pending).await;
        }
    }

    /// Build, sign, and broadcast a CPFP child transaction for a stuck withdrawal.
    async fn process_cpfp_for_withdrawal(&self, pending: &PendingWithdrawal) {
        let members = match self.inner.onchain_state().current_committee_members() {
            Some(m) => m,
            None => {
                error!("No current committee members for CPFP");
                return;
            }
        };

        // Step 1: Collect MPC Schnorr signatures for the CPFP child tx
        let (cpfp_tx, cpfp_signature, child_fee) =
            match self.collect_cpfp_tx_signatures(&pending.id, &members).await {
                Ok(result) => result,
                Err(e) => {
                    error!(
                        "Failed to collect CPFP signatures for {:?}: {e}",
                        pending.id
                    );
                    return;
                }
            };

        let cpfp_txid = Address::new(cpfp_tx.compute_txid().to_byte_array());
        let child_change_amount = cpfp_tx.output[0].value.to_sat();

        // Step 2: Collect BLS signatures and submit CPFP data on-chain
        let cpfp_signing = CpfpTxSigning {
            pending_withdrawal_id: pending.id,
            cpfp_txid,
            cpfp_change_amount: child_change_amount,
            cpfp_signature: cpfp_signature.to_byte_array().to_vec(),
        };

        let cpfp_cert = match self
            .collect_cpfp_tx_signing_signature(&cpfp_signing, &members)
            .await
        {
            Ok(cert) => cert,
            Err(e) => {
                error!(
                    "Failed to collect CPFP BLS signatures for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        // Submit sign_cpfp on Sui
        if let Err(e) = self
            .submit_sign_cpfp(
                &pending.id,
                &cpfp_txid,
                child_change_amount,
                cpfp_signature.to_byte_array().as_ref(),
                &cpfp_cert,
            )
            .await
        {
            error!(
                "Failed to submit sign_cpfp on Sui for {:?}: {e}",
                pending.id
            );
            return;
        }

        info!(
            "CPFP submitted for withdrawal {:?}: child txid {:?}, fee {} sats",
            pending.id, cpfp_txid, child_fee
        );

        // Step 3: Broadcast the package (parent + child)
        self.broadcast_cpfp_package(pending, Some(&cpfp_tx)).await;
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain PendingWithdrawal
    /// data (stored witness signatures) and broadcast it to the Bitcoin network.
    async fn rebuild_and_broadcast_withdrawal_btc_tx(
        &self,
        pending: &PendingWithdrawal,
        txid: bitcoin::Txid,
    ) {
        warn!(
            "Withdrawal tx {} not found for {:?}, re-broadcasting from on-chain signatures",
            txid, pending.id
        );

        let tx = match self.rebuild_signed_tx_from_onchain(pending) {
            Ok(tx) => tx,
            Err(e) => {
                error!(
                    "Failed to rebuild signed withdrawal tx for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        match self.inner.btc_monitor().broadcast_transaction(tx).await {
            Ok(()) => {
                info!("Re-broadcast withdrawal tx {} for {:?}", txid, pending.id);
            }
            Err(e) => {
                error!(
                    "Failed to re-broadcast withdrawal tx {} for {:?}: {e}",
                    txid, pending.id
                );
            }
        }
    }

    /// Rebuild a fully signed Bitcoin transaction from on-chain PendingWithdrawal
    fn rebuild_signed_tx_from_onchain(
        &self,
        pending: &PendingWithdrawal,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let raw_sigs = pending
            .signatures
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No signatures on pending withdrawal"))?;

        let mut tx = self
            .inner
            .build_unsigned_withdrawal_tx(&pending.inputs, &pending.all_outputs())?;

        anyhow::ensure!(
            raw_sigs.len() == tx.input.len(),
            "Signature count mismatch: tx has {} inputs, on-chain has {} signatures",
            tx.input.len(),
            raw_sigs.len()
        );
        anyhow::ensure!(
            tx.input.len() == pending.inputs.len(),
            "Input count mismatch: tx has {} inputs, pending has {}",
            tx.input.len(),
            pending.inputs.len()
        );

        for ((input, pending_input), sig_bytes) in
            tx.input.iter_mut().zip(pending.inputs.iter()).zip(raw_sigs)
        {
            input.witness = self
                .inner
                .build_taproot_witness(sig_bytes, pending_input.derivation_path.as_ref())?;
        }

        Ok(tx)
    }

    // ========================================================================
    // CPFP helpers
    // ========================================================================

    /// Fan out to committee: MPC-sign the CPFP child transaction. (similar to `collect_withdrawal_tx_signatures`)
    async fn collect_cpfp_tx_signatures(
        &self,
        pending_id: &Address,
        members: &[CommitteeMember],
    ) -> anyhow::Result<(bitcoin::Transaction, SchnorrSignature, u64)> {
        let futures: Vec<_> = members
            .iter()
            .map(|member| self.request_cpfp_tx_signature(pending_id, member))
            .collect();
        let results = futures::future::join_all(futures).await;

        for result in results {
            match result {
                Ok(signature) => {
                    // Rebuild the CPFP tx locally to verify
                    let pending = self
                        .inner
                        .onchain_state()
                        .pending_withdrawal(pending_id)
                        .ok_or_else(|| {
                            anyhow::anyhow!("PendingWithdrawal {pending_id} not found")
                        })?;
                    let (cpfp_tx, child_fee) = self.inner.build_unsigned_cpfp_tx(&pending).await?;
                    return Ok((cpfp_tx, signature, child_fee));
                }
                Err(e) => {
                    warn!("Could not get CPFP signature from a node: {e}");
                }
            }
        }
        anyhow::bail!(
            "Could not get CPFP MPC signatures for {:?}; stopping processing",
            pending_id
        )
    }

    /// Fan out to committee: BLS-sign the CPFP witness data for on-chain storage. (similar to `collect_withdrawal_tx_signing_signatures`)
    async fn collect_cpfp_tx_signing_signature(
        &self,
        cpfp_signing: &CpfpTxSigning,
        members: &[CommitteeMember],
    ) -> anyhow::Result<CommitteeSignature> {
        let proto_request = hashi_types::proto::SignCpfpTxSigningRequest {
            pending_withdrawal_id: cpfp_signing
                .pending_withdrawal_id
                .as_bytes()
                .to_vec()
                .into(),
            cpfp_txid: cpfp_signing.cpfp_txid.as_bytes().to_vec().into(),
            cpfp_change_amount: cpfp_signing.cpfp_change_amount,
            cpfp_signature: cpfp_signing.cpfp_signature.clone().into(),
        };

        let mut bls_signatures: Vec<MemberSignature> = Vec::new();
        for member in members {
            if let Some(signature) = self
                .request_cpfp_tx_signing_signature(proto_request.clone(), member)
                .await
            {
                bls_signatures.push(signature);
            }
        }

        let committee = self
            .inner
            .onchain_state()
            .current_committee()
            .ok_or_else(|| anyhow::anyhow!("No current committee"))?;

        let mut aggregator = BlsSignatureAggregator::new(&committee, cpfp_signing.clone());
        for sig in bls_signatures {
            if let Err(e) = aggregator.add_signature(sig) {
                error!("Failed to add CPFP BLS signature: {e}");
            }
        }

        let weight = aggregator.weight();
        let required_weight = certificate_threshold(committee.total_weight());
        if weight < required_weight {
            anyhow::bail!("Insufficient CPFP BLS signatures: weight {weight} < {required_weight}");
        }

        let signed = aggregator
            .finish()
            .map_err(|e| anyhow::anyhow!("Failed to aggregate CPFP BLS signatures: {e}"))?;
        Ok(signed.committee_signature().clone())
    }

    /// Submit the sign_cpfp Move transaction on Sui.
    async fn submit_sign_cpfp(
        &self,
        pending_id: &Address,
        cpfp_txid: &Address,
        cpfp_change_amount: u64,
        cpfp_signature: &[u8],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Submitting sign_cpfp for {:?}", pending_id);

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_sign_cpfp(
                pending_id,
                cpfp_txid,
                cpfp_change_amount,
                cpfp_signature,
                cert,
            )
            .await
    }

    /// Broadcast parent and CPFP child transactions.
    /// If `unsigned_cpfp_tx` is provided (first-time broadcast after signing), uses it directly.
    /// Otherwise, rebuilds the unsigned CPFP child from on-chain data.
    async fn broadcast_cpfp_package(
        &self,
        pending: &PendingWithdrawal,
        unsigned_cpfp_tx: Option<&bitcoin::Transaction>,
    ) {
        // Broadcast the parent (may already be in mempool)
        match self.rebuild_signed_tx_from_onchain(pending) {
            Ok(parent_tx) => {
                let _ = self
                    .inner
                    .btc_monitor()
                    .broadcast_transaction(parent_tx)
                    .await;
            }
            Err(e) => {
                warn!("Failed to rebuild parent tx for CPFP broadcast: {e}");
            }
        }

        // Build or rebuild unsigned CPFP child tx
        let unsigned = match unsigned_cpfp_tx {
            Some(tx) => tx.clone(),
            None => match self.rebuild_unsigned_cpfp_tx_from_onchain(pending) {
                Ok(tx) => tx,
                Err(e) => {
                    error!("Failed to rebuild unsigned CPFP child tx: {e}");
                    return;
                }
            },
        };

        // Sign and broadcast
        let signed_cpfp = match self.rebuild_signed_cpfp_tx(pending, &unsigned) {
            Ok(tx) => tx,
            Err(e) => {
                error!("Failed to build signed CPFP child tx: {e}");
                return;
            }
        };

        match self
            .inner
            .btc_monitor()
            .broadcast_transaction(signed_cpfp)
            .await
        {
            Ok(()) => {
                info!("Broadcast CPFP child tx for {:?}", pending.id);
            }
            Err(e) => {
                error!(
                    "Failed to broadcast CPFP child tx for {:?}: {e}",
                    pending.id
                );
            }
        }
    }

    /// Rebuild the unsigned CPFP child transaction from on-chain PendingWithdrawal data.
    fn rebuild_unsigned_cpfp_tx_from_onchain(
        &self,
        pending: &PendingWithdrawal,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let cpfp_info = pending
            .cpfp_info
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No CPFP info on pending withdrawal"))?;
        let change_output = pending
            .change_output
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No change output on pending withdrawal"))?;

        let cpfp_input = bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array(pending.txid.into()),
                vout: pending.withdrawal_outputs.len() as u32,
            },
            script_sig: bitcoin::ScriptBuf::default(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::default(),
        };
        let script_pubkey =
            crate::withdrawals::script_pubkey_from_raw_address(&change_output.bitcoin_address)?;
        let cpfp_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(cpfp_info.change_amount),
            script_pubkey,
        };
        Ok(bitcoin_utils::construct_tx(
            vec![cpfp_input],
            vec![cpfp_output],
        ))
    }

    /// Add witness to an unsigned CPFP child tx using the on-chain signature.
    fn rebuild_signed_cpfp_tx(
        &self,
        pending: &PendingWithdrawal,
        unsigned_cpfp_tx: &bitcoin::Transaction,
    ) -> anyhow::Result<bitcoin::Transaction> {
        let cpfp_info = pending
            .cpfp_info
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No CPFP info"))?;

        let mut tx = unsigned_cpfp_tx.clone();
        tx.input[0].witness = self
            .inner
            .build_taproot_witness(&cpfp_info.signature, None)?;
        Ok(tx)
    }

    async fn confirm_withdrawal_on_sui(&self, pending: &PendingWithdrawal) {
        let members = match self.inner.onchain_state().current_committee_members() {
            Some(m) => m,
            None => {
                error!("No current committee members for confirmation");
                return;
            }
        };

        let confirmation_cert = match self
            .collect_withdrawal_confirmation_signature(pending.id, &members)
            .await
        {
            Ok(cert) => cert,
            Err(e) => {
                error!(
                    "Failed to collect withdrawal confirmation signatures for {:?}: {e}",
                    pending.id
                );
                return;
            }
        };

        if let Err(e) = self
            .submit_confirm_withdrawal(&pending.id, &confirmation_cert)
            .await
        {
            error!(
                "Failed to submit confirm_withdrawal for {:?}: {e}",
                pending.id
            );
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

    async fn request_withdrawal_tx_commitment_signature(
        &self,
        proto_request: SignWithdrawalTxConstructionRequest,
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
            .sign_withdrawal_tx_construction(proto_request.clone())
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

    async fn request_withdrawal_approval_signature(
        &self,
        proto_request: SignWithdrawalRequestApprovalRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal request approval signature from {}",
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
            .sign_withdrawal_request_approval(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal request approval signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved withdrawal request approval signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from withdrawal request approval response from {}: {e}",
                    validator_address
                );
            })
            .ok()
    }

    async fn request_withdrawal_tx_signing_signature(
        &self,
        proto_request: SignWithdrawalTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting withdrawal tx signing signature from {}",
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
            .sign_withdrawal_tx_signing(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get withdrawal tx signing signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

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
                Some(Err(e)) => {
                    warn!("Could not get signatures from a node: {e}");
                }
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

    async fn submit_approve_withdrawal_requests(
        &self,
        approvals: &[(Address, &CommitteeSignature)],
    ) -> anyhow::Result<()> {
        info!(
            "Submitting approve_request PTB for {} requests",
            approvals.len()
        );

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_approve_withdrawal_requests(approvals)
            .await
    }

    async fn submit_commit_withdrawal_tx(
        &self,
        approval: &WithdrawalTxCommitment,
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!(
            "Submitting commit_withdrawal_tx for txid {:?}",
            approval.txid
        );

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor.execute_commit_withdrawal_tx(approval, cert).await
    }

    async fn submit_sign_withdrawal(
        &self,
        withdrawal_id: &Address,
        request_ids: &[Address],
        signatures: &[Vec<u8>],
        cert: &CommitteeSignature,
    ) -> anyhow::Result<()> {
        info!("Submitting sign_withdrawal for {:?}", withdrawal_id);

        let mut executor = SuiTxExecutor::from_hashi(self.inner.clone())?;
        executor
            .execute_sign_withdrawal(withdrawal_id, request_ids, signatures, cert)
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

    // ========================================================================
    // CPFP gRPC request helpers
    // ========================================================================

    async fn request_cpfp_tx_signature(
        &self,
        pending_withdrawal_id: &Address,
        member: &CommitteeMember,
    ) -> anyhow::Result<SchnorrSignature> {
        let validator_address = member.validator_address();
        trace!("Requesting CPFP tx signature from {}", validator_address);

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

        let proto_request = SignCpfpTransactionRequest {
            pending_withdrawal_id: pending_withdrawal_id.as_bytes().to_vec().into(),
        };

        let response = rpc_client
            .sign_cpfp_transaction(proto_request)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to get CPFP tx signature from {validator_address}: {e}")
            })?;

        trace!("Retrieved CPFP tx signature from {}", validator_address);

        let sig_bytes: [u8; 64] = response
            .into_inner()
            .signature
            .as_ref()
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("Invalid CPFP Schnorr signature length from {validator_address}")
            })?;
        SchnorrSignature::from_byte_array(&sig_bytes).map_err(|e| {
            anyhow::anyhow!("Invalid CPFP Schnorr signature from {validator_address}: {e}")
        })
    }

    async fn request_cpfp_tx_signing_signature(
        &self,
        proto_request: SignCpfpTxSigningRequest,
        member: &CommitteeMember,
    ) -> Option<MemberSignature> {
        let validator_address = member.validator_address();
        trace!(
            "Requesting CPFP tx signing signature from {}",
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
            .sign_cpfp_tx_signing(proto_request.clone())
            .await
            .inspect_err(|e| {
                error!(
                    "Failed to get CPFP tx signing signature from {}: {e}",
                    validator_address
                );
            })
            .ok()?;

        trace!(
            "Retrieved CPFP tx signing signature from {}",
            validator_address
        );

        response
            .into_inner()
            .member_signature
            .ok_or_else(|| anyhow::anyhow!("No member_signature in response"))
            .and_then(parse_member_signature)
            .inspect_err(|e| {
                error!(
                    "Failed to parse member signature from CPFP tx signing response from {}: {e}",
                    validator_address
                );
            })
            .ok()
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

impl WithdrawalRequestApproval {
    fn to_proto(&self) -> SignWithdrawalRequestApprovalRequest {
        SignWithdrawalRequestApprovalRequest {
            request_id: self.request_id.as_bytes().to_vec().into(),
        }
    }
}

impl WithdrawalTxCommitment {
    fn to_proto(&self) -> SignWithdrawalTxConstructionRequest {
        SignWithdrawalTxConstructionRequest {
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

impl WithdrawalTxSigning {
    fn to_proto(&self) -> SignWithdrawalTxSigningRequest {
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
        }
    }
}
