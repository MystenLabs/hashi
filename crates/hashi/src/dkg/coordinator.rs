//! DKG coordinator that manages the protocol state machine

use crate::communication::{AuthenticatedMessage, ChannelError};
use crate::dkg::interfaces::DkgStorage;
use crate::dkg::types::{
    DkgConfig, DkgError, DkgOutput, DkgResult, MessageApproval, OrderedBroadcastMessage,
    P2PMessage, SessionContext, SessionId, ValidatorInfo, ValidatorSignature,
};
use crate::types::ValidatorAddress;
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::{G, avss, complaint};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};
use tokio::select;

#[derive(Debug, Clone)]
pub enum DealerState {
    /// Waiting for share from this dealer
    WaitingForShare { start_time: Instant },
    /// Received share, now processing/verifying
    Processing { received_at: Instant },
    /// Handling complaint about this dealer's share
    ComplaintHandling {
        complaint_time: Instant,
        complaint_count: usize,
        response_count: usize,
    },
    /// Successfully processed this dealer's share
    Completed,
    /// Failed to get valid share from this dealer
    Failed { reason: String },
}

#[derive(Debug, Clone)]
pub enum DkgState {
    /// Initial state, waiting to start
    Idle,
    /// Running phase - tracking each dealer's state separately
    Running {
        start_time: Instant,
        /// State for each dealer's DKG instance
        dealer_states: BTreeMap<ValidatorAddress, DealerState>,
    },
    /// Success state - DKG completed successfully
    Completed { output: DkgOutput },
    /// Failed state - DKG failed
    Failed { reason: String },
}

#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// Timeout for each phase
    pub phase_timeout: Duration,
    /// Maximum number of retries for message sending
    pub max_send_retries: u32,
    /// Whether to persist state to storage
    pub enable_persistence: bool,
}

impl Default for CoordinatorConfig {
    // TODO: Set the values in a config file.
    fn default() -> Self {
        Self {
            phase_timeout: Duration::from_secs(30),
            max_send_retries: 3,
            enable_persistence: true,
        }
    }
}

pub struct DkgCoordinator<P, O, S: DkgStorage> {
    pub validator_info: ValidatorInfo,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub coordinator_config: CoordinatorConfig,
    pub dkg_state: DkgState,
    pub p2p_channel: P,
    pub ordered_broadcast_channel: Option<O>,
    pub storage: Option<S>,
    pub received_messages: BTreeMap<ValidatorAddress, avss::Message>,
    ///  Decrypted and validated shares after processing received messages
    pub processed_shares: BTreeMap<ValidatorAddress, avss::SharesForNode>,
    pub processed_commitments: BTreeMap<ValidatorAddress, Vec<Eval<G>>>,
    pub data_availability_signatures: BTreeMap<ValidatorAddress, Vec<ValidatorSignature>>,
    pub dkg_signatures: BTreeMap<ValidatorAddress, Vec<ValidatorSignature>>,
    pub share_approvals: BTreeMap<ValidatorAddress, HashSet<ValidatorAddress>>,
}

fn validate_sender(
    authenticated_sender: &ValidatorAddress,
    claimed_sender: &ValidatorAddress,
    field_name: &str,
) -> DkgResult<()> {
    if authenticated_sender != claimed_sender {
        return Err(DkgError::InvalidMessage {
            sender: authenticated_sender.clone(),
            reason: format!("{} mismatch", field_name),
        });
    }
    Ok(())
}

impl<P, O, S: DkgStorage> DkgCoordinator<P, O, S> {
    pub fn new(
        validator: ValidatorInfo,
        config: DkgConfig,
        session: SessionContext,
        coordinator_config: CoordinatorConfig,
        p2p_channel: P,
        ordered_broadcast_channel: Option<O>,
        storage: Option<S>,
    ) -> Self {
        Self {
            validator_info: validator,
            dkg_config: config,
            session_context: session,
            coordinator_config,
            dkg_state: DkgState::Idle,
            p2p_channel,
            ordered_broadcast_channel,
            storage,
            received_messages: BTreeMap::new(),
            processed_shares: BTreeMap::new(),
            processed_commitments: BTreeMap::new(),
            data_availability_signatures: BTreeMap::new(),
            dkg_signatures: BTreeMap::new(),
            share_approvals: BTreeMap::new(),
        }
    }

    // TODO: Add unit tests after all the other to-do's are completed
    pub async fn run<'a>(&'a mut self) -> DkgResult<()>
    where
        P: crate::communication::P2PChannel<P2PMessage> + 'a,
        O: crate::communication::OrderedBroadcastChannel<OrderedBroadcastMessage> + 'a,
    {
        if self.is_idle() {
            self.start().await?;
        }
        if !self.is_running() {
            return Err(DkgError::ProtocolFailed(
                "Coordinator is not in a runnable state".to_string(),
            ));
        }
        loop {
            if self.check_timeout() {
                self.handle_timeout();
                break;
            }
            if self.is_complete() || self.is_failed() {
                break;
            }
            self.publish_pending_certificates().await?;
            select! {
                p2p_result = self.p2p_channel.receive() => {
                    match p2p_result {
                        Ok(AuthenticatedMessage { sender, message }) => {
                            if let Err(e) = self.handle_message(sender, message).await {
                                eprintln!("Error handling P2P message: {}", e);
                            }
                        }
                        Err(ChannelError::Timeout) => {
                            // Continue waiting
                        }
                        Err(ChannelError::Closed) => {
                            return Err(DkgError::ProtocolFailed("P2P channel closed".to_string()));
                        }
                        Err(e) => {
                            eprintln!("P2P channel error: {}", e);
                        }
                    }
                }
                ordered_result = async {
                    if let Some(ref mut channel) = self.ordered_broadcast_channel {
                        channel.receive().await
                    } else {
                        // If no ordered channel, just wait forever
                        std::future::pending().await
                    }
                }, if self.ordered_broadcast_channel.is_some() => {
                    match ordered_result {
                        Ok(AuthenticatedMessage { sender: _, message }) => {
                            if let Err(e) = self.handle_ordered_message(message).await {
                                eprintln!("Error handling ordered broadcast message: {}", e);
                            }
                        }
                        Err(ChannelError::Timeout) => {
                            // Continue waiting
                        }
                        Err(ChannelError::Closed) => {
                            return Err(DkgError::ProtocolFailed("Ordered broadcast channel closed".to_string()));
                        }
                        Err(e) => {
                            eprintln!("Ordered broadcast channel error: {}", e);
                        }
                    }
                }
            }
        }
        if self.is_complete() {
            Ok(())
        } else {
            Err(DkgError::ProtocolFailed("DKG protocol failed".to_string()))
        }
    }

    pub async fn handle_message(
        &mut self,
        sender: ValidatorAddress,
        message: P2PMessage,
    ) -> DkgResult<()> {
        if !self.validate_dealer(&sender) {
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Unknown validator".to_string(),
            });
        }
        match message {
            P2PMessage::ShareV1 {
                session_id: _,
                sender: msg_sender,
                message,
            } => {
                validate_sender(&sender, &msg_sender, "Sender")?;
                self.handle_share(sender, *message).await
            }
            P2PMessage::ComplaintV1 {
                session_id: _,
                accuser,
                complaint,
            } => {
                validate_sender(&sender, &accuser, "Accuser")?;
                self.handle_complaint(accuser, complaint).await
            }
            P2PMessage::ComplaintResponseV1 {
                session_id: _,
                responder,
                response,
            } => {
                validate_sender(&sender, &responder, "Responder")?;
                self.handle_complaint_response(responder, response).await
            }
            P2PMessage::ApprovalV1(approval) => self.handle_approval(sender, approval).await,
            P2PMessage::DataAvailabilitySignatureV1 {
                session_id,
                signer,
                dealer,
                message_hash,
                signature,
            } => {
                validate_sender(&sender, &signer, "Signer")?;
                self.validate_session_id(&sender, &session_id)?;
                self.handle_data_availability_signature(signer, dealer, message_hash, signature)
                    .await
            }
            P2PMessage::DkgSignatureV1 {
                session_id,
                signer,
                dealer,
                message_hash,
                signature,
            } => {
                validate_sender(&sender, &signer, "Signer")?;
                self.validate_session_id(&sender, &session_id)?;
                self.handle_dkg_signature(signer, dealer, message_hash, signature)
                    .await
            }
            P2PMessage::ShareRequestV1 {
                session_id,
                requester,
                dealer,
                message_hash,
            } => {
                validate_sender(&sender, &requester, "Requester")?;
                self.validate_session_id(&sender, &session_id)?;
                self.handle_share_request(requester, dealer, message_hash)
                    .await
            }
        }
    }

    pub fn check_timeout(&mut self) -> bool {
        let timeout = self.coordinator_config.phase_timeout;
        match &self.dkg_state {
            DkgState::Running { start_time, .. } => start_time.elapsed() > timeout,
            _ => false,
        }
    }

    pub fn current_state(&self) -> &DkgState {
        &self.dkg_state
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.dkg_state, DkgState::Completed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.dkg_state, DkgState::Failed { .. })
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.dkg_state, DkgState::Idle)
    }

    pub fn is_running(&self) -> bool {
        matches!(self.dkg_state, DkgState::Running { .. })
    }

    async fn start(&mut self) -> DkgResult<()> {
        match &self.dkg_state {
            DkgState::Idle => {
                let mut dealer_states = BTreeMap::new();
                let now = Instant::now();
                for validator in &self.dkg_config.validators {
                    dealer_states.insert(
                        validator.address.clone(),
                        DealerState::WaitingForShare { start_time: now },
                    );
                }
                self.dkg_state = DkgState::Running {
                    start_time: now,
                    dealer_states,
                };
                Ok(())
            }
            _ => Err(DkgError::ProtocolFailed(
                "Cannot start: already in progress".to_string(),
            )),
        }
    }

    async fn publish_pending_certificates(&mut self) -> DkgResult<()>
    where
        O: crate::communication::OrderedBroadcastChannel<OrderedBroadcastMessage>,
    {
        if let Some(ref mut channel) = self.ordered_broadcast_channel {
            let required_approvals = self.dkg_config.required_dkg_signatures();

            // Check all dealers that have enough approvals
            let dealers_to_publish: Vec<ValidatorAddress> = self
                .share_approvals
                .iter()
                .filter_map(|(dealer, approvers)| {
                    if approvers.len() >= required_approvals
                        && *dealer == self.validator_info.address
                    {
                        Some(dealer.clone())
                    } else {
                        None
                    }
                })
                .collect();

            for dealer in dealers_to_publish {
                if let Some(approvers) = self.share_approvals.get(&dealer) {
                    let signatures: Vec<ValidatorSignature> = approvers
                        .iter()
                        .map(|approver| ValidatorSignature {
                            validator: approver.clone(),
                            signature: vec![], // TODO: Store actual signatures from approvals
                        })
                        .collect();

                    // Create the certificate
                    // TODO: Calculate actual message hash from the dealer's share
                    let message_hash = [0u8; 32];

                    // For now, use the collected signatures as DKG signatures
                    // In practice, we'd separate DA and DKG signatures
                    let certificate = crate::dkg::types::DkgCertificate {
                        dealer: dealer.clone(),
                        message_hash,
                        data_availability_signatures: vec![], // TODO: Collect from data_availability_sigs
                        dkg_signatures: signatures,
                        session_context: self.session_context.clone(),
                    };

                    // Publish to ordered broadcast channel
                    let message = OrderedBroadcastMessage::CertificateV1(certificate);
                    channel.publish(message).await.map_err(|e| {
                        DkgError::ProtocolFailed(format!("Failed to publish certificate: {}", e))
                    })?;

                    // Remove from pending after publishing
                    self.share_approvals.remove(&dealer);
                }
            }
        }
        Ok(())
    }

    fn handle_timeout(&mut self) {
        if self.check_timeout()
            && let DkgState::Running { dealer_states, .. } = &self.dkg_state
        {
            let mut timed_out_dealers = Vec::new();
            for (dealer_id, dealer_state) in dealer_states.iter() {
                if let DealerState::WaitingForShare { start_time } = dealer_state
                    && start_time.elapsed() > self.coordinator_config.phase_timeout
                {
                    timed_out_dealers.push(dealer_id.clone());
                }
            }

            if !timed_out_dealers.is_empty() {
                self.dkg_state = DkgState::Failed {
                    reason: format!(
                        "Timeout waiting for shares from dealers: {:?}",
                        timed_out_dealers
                    ),
                };
            } else {
                self.dkg_state = DkgState::Failed {
                    reason: "Timeout in DKG protocol".to_string(),
                };
            }
        }
    }

    async fn handle_ordered_message(&mut self, message: OrderedBroadcastMessage) -> DkgResult<()> {
        match message {
            OrderedBroadcastMessage::CertificateV1(_cert) => {
                // TODO: Implement certificate handling
                // Certificates prove that 2f+1 validators approved a share
                // They complete the AVSS protocol for a dealer's share
                // Will need to:
                // 1. Verify the certificate signatures
                // 2. Store the certificate as proof of share validity
                // 3. Update protocol state accordingly
                Ok(())
            }
            OrderedBroadcastMessage::PresignatureV1 {
                sender: _,
                session_context: _,
                data: _,
            } => {
                // TODO: Implement presignature handling
                // Presignatures are used in the signing protocol
                // Will need to:
                // 1. Verify the presignature is valid
                // 2. Store it for the signing phase
                // 3. Check if we have enough presignatures to proceed
                Ok(())
            }
        }
    }

    async fn handle_share(
        &mut self,
        dealer: ValidatorAddress,
        message: avss::Message,
    ) -> DkgResult<()> {
        match &mut self.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                if let Some(dealer_state) = dealer_states.get_mut(&dealer) {
                    match dealer_state {
                        DealerState::WaitingForShare { .. } => {
                            self.received_messages.insert(dealer.clone(), message);
                            *dealer_state = DealerState::Processing {
                                received_at: Instant::now(),
                            };

                            // TODO: Implement the full AVSS protocol flow here:
                            // 1. Process the AVSS message (decrypt share with ECIES private key)
                            // 2. Verify the share against the commitment
                            // 3. If valid, send an approval signature back to the dealer
                            // 4. The dealer will collect 2f+1 approvals and create a certificate
                            // 5. The certificate will be broadcast via OrderedBroadcastChannel

                            self.check_progress().await?;
                            Ok(())
                        }
                        _ => Err(DkgError::InvalidMessage {
                            sender: dealer,
                            reason: "Already processed share from this dealer".to_string(),
                        }),
                    }
                } else {
                    Err(DkgError::InvalidMessage {
                        sender: dealer,
                        reason: "Unknown dealer".to_string(),
                    })
                }
            }
            _ => Err(DkgError::InvalidMessage {
                sender: dealer,
                reason: "Not in running state".to_string(),
            }),
        }
    }

    async fn handle_complaint(
        &mut self,
        accuser: ValidatorAddress,
        _complaint: complaint::Complaint,
    ) -> DkgResult<()> {
        match &mut self.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                // TODO: Get actual dealer ID from complaint structure
                // This is a placeholder - the actual complaint structure should identify the dealer
                for (_dealer_id, dealer_state) in dealer_states.iter_mut() {
                    match dealer_state {
                        DealerState::Processing { .. } => {
                            *dealer_state = DealerState::ComplaintHandling {
                                complaint_time: Instant::now(),
                                complaint_count: 1,
                                response_count: 0,
                            };

                            // TODO: Implement complaint verification and response:
                            // 1. Verify the complaint is valid (check the proof)
                            // 2. If we're the accused dealer, create and send a complaint response
                            //    revealing the share for the complaining party
                            // 3. If we're a receiver, verify the complaint and potentially
                            //    mark the accused dealer as faulty
                            // 4. Broadcast our own complaint response if needed

                            break;
                        }
                        DealerState::ComplaintHandling {
                            complaint_count, ..
                        } => {
                            *complaint_count += 1;
                            break;
                        }
                        _ => continue,
                    }
                }
                Ok(())
            }
            _ => Err(DkgError::InvalidMessage {
                sender: accuser,
                reason: "Cannot handle complaint in current state".to_string(),
            }),
        }
    }

    async fn handle_complaint_response(
        &mut self,
        responder: ValidatorAddress,
        _response: complaint::ComplaintResponse,
    ) -> DkgResult<()> {
        match &mut self.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                // TODO: Identify which dealer this response is for
                for dealer_state in dealer_states.values_mut() {
                    if let DealerState::ComplaintHandling { response_count, .. } = dealer_state {
                        *response_count += 1;

                        // TODO: Process complaint response:
                        // 1. Verify the response is valid (check revealed share matches commitment)
                        // 2. If we're the original complainer, use the revealed share to recover
                        //    our missing/invalid share
                        // 3. All receivers can verify the response to ensure the dealer is honest
                        // 4. If response is invalid, mark the dealer as faulty
                        // 5. Once all complaints are resolved, transition back to processing

                        break;
                    }
                }
                self.check_complaint_resolution().await
            }
            _ => Err(DkgError::InvalidMessage {
                sender: responder,
                reason: "Not in running state".to_string(),
            }),
        }
    }

    async fn check_progress(&mut self) -> DkgResult<()> {
        if let DkgState::Running { dealer_states, .. } = &self.dkg_state {
            let completed_count = dealer_states
                .values()
                .filter(|state| matches!(state, DealerState::Completed))
                .count();
            if completed_count >= self.required_shares() {
                self.check_completion().await?;
            }
        }
        Ok(())
    }

    pub async fn check_completion(&mut self) -> DkgResult<()> {
        if self.processed_shares.len() >= self.required_shares() {
            // TODO: Compute from the polynomial commitments when implementing the full protocol flow
            // Use zero element as placeholder for now
            let public_key = G::zero();
            // Create empty shares for now - would be filled from processed data
            let key_shares = avss::SharesForNode { shares: vec![] };
            let output = DkgOutput {
                public_key,
                key_shares,
                commitments: vec![],
                session_context: self.session_context.clone(),
            };
            self.dkg_state = DkgState::Completed {
                output: output.clone(),
            };
            if let Some(storage) = &self.storage
                && self.coordinator_config.enable_persistence
            {
                storage.save_output(&self.session_context, &output).await?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    async fn handle_approval(
        &mut self,
        sender: ValidatorAddress,
        approval: MessageApproval,
    ) -> DkgResult<()> {
        // TODO: Verify the approval signature
        // For now, just track that we received an approval

        if !self.received_messages.contains_key(&approval.approver) {
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Approval for unknown share".to_string(),
            });
        }
        self.share_approvals
            .entry(approval.approver.clone())
            .or_default()
            .insert(sender);

        // Check if we have enough approvals to create a certificate
        let required_approvals = self.dkg_config.required_dkg_signatures();
        if let Some(approvers) = self.share_approvals.get(&approval.approver)
            && approvers.len() >= required_approvals
            && approval.approver == self.validator_info.address
        {
            // TODO: Create and publish certificate via OrderedBroadcastChannel
            // This will be called from the run() method where we have the trait bound
            // For now, just mark that we're ready to publish
        }
        Ok(())
    }

    async fn handle_data_availability_signature(
        &mut self,
        signer: ValidatorAddress,
        dealer: ValidatorAddress,
        _message_hash: [u8; 32],
        signature: Vec<u8>,
    ) -> DkgResult<()> {
        self.require_valid_dealer(&dealer, &signer)?;
        let sig = ValidatorSignature {
            validator: signer,
            signature,
        };
        self.data_availability_signatures
            .entry(dealer.clone())
            .or_default()
            .push(sig);

        // Check if we have enough signatures for data availability
        let required = self.dkg_config.required_data_availability_signatures();
        if let Some(sigs) = self.data_availability_signatures.get(&dealer)
            && sigs.len() >= required
        {
            // TODO: Mark this dealer's share as having sufficient data availability
        }
        Ok(())
    }

    async fn handle_dkg_signature(
        &mut self,
        signer: ValidatorAddress,
        dealer: ValidatorAddress,
        _message_hash: [u8; 32],
        signature: Vec<u8>,
    ) -> DkgResult<()> {
        self.require_valid_dealer(&dealer, &signer)?;
        let sig = ValidatorSignature {
            validator: signer,
            signature,
        };
        self.dkg_signatures
            .entry(dealer.clone())
            .or_default()
            .push(sig);

        // Check if we have enough DKG signatures to proceed
        let required = self.dkg_config.required_dkg_signatures();
        if let Some(sigs) = self.dkg_signatures.get(&dealer)
            && sigs.len() >= required
        {
            // TODO: Create a certificate for this dealer's share
            // The certificate can then be broadcast via OrderedBroadcastChannel
            if let DkgState::Running { dealer_states, .. } = &mut self.dkg_state
                && let Some(dealer_state) = dealer_states.get_mut(&dealer)
            {
                // Mark this dealer as completed if we have enough signatures
                *dealer_state = DealerState::Completed;
            }
            self.check_progress().await?;
        }
        Ok(())
    }

    async fn handle_share_request(
        &mut self,
        requester: ValidatorAddress,
        dealer: ValidatorAddress,
        _message_hash: [u8; 32],
    ) -> DkgResult<()> {
        // Check if we are the dealer being requested from
        if dealer == self.validator_info.address {
            // Check if we have the share for this requester
            if let Some(_avss_message) = self.received_messages.get(&dealer) {
                // TODO: Extract and send the encrypted share for the requester
                // This would involve:
                // 1. Getting the encrypted share for the requester from the AVSS message
                // 2. Sending it via P2P channel
                // For now, just acknowledge the request
            } else {
                return Err(DkgError::InvalidMessage {
                    sender: requester,
                    reason: "Share not available".to_string(),
                });
            }
        }

        // If we're not the dealer, we can optionally help by forwarding
        // our copy of the share if we have it (for redundancy)

        Ok(())
    }

    async fn check_complaint_resolution(&mut self) -> DkgResult<()> {
        // TODO: Implement the actual complaint verification when adding complaint handling for all protocols
        if let DkgState::Running { dealer_states, .. } = &mut self.dkg_state {
            // Check if any dealers are still in complaint handling with sufficient responses
            for dealer_state in dealer_states.values_mut() {
                if let DealerState::ComplaintHandling { response_count, .. } = dealer_state
                    && *response_count > 0
                {
                    // For now, assume successful resolution
                    *dealer_state = DealerState::Completed;
                }
            }
        }
        self.check_progress().await
    }

    fn required_shares(&self) -> usize {
        self.dkg_config
            .validators
            .len()
            .saturating_sub(self.dkg_config.max_faulty as usize)
    }

    fn validate_session_id(
        &self,
        authenticated_sender: &ValidatorAddress,
        session_id: &SessionId,
    ) -> DkgResult<()> {
        if *session_id != self.session_context.session_id() {
            return Err(DkgError::InvalidMessage {
                sender: authenticated_sender.clone(),
                reason: "Session ID mismatch".to_string(),
            });
        }
        Ok(())
    }

    fn validate_dealer(&self, dealer: &ValidatorAddress) -> bool {
        self.dkg_config
            .validators
            .iter()
            .any(|v| v.address == *dealer)
    }

    fn require_valid_dealer(
        &self,
        dealer: &ValidatorAddress,
        sender: &ValidatorAddress,
    ) -> DkgResult<()> {
        if !self.validate_dealer(dealer) {
            return Err(DkgError::InvalidMessage {
                sender: sender.clone(),
                reason: format!("Unknown dealer: {:?}", dealer),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::InMemoryP2PChannels;
    use crate::dkg::interfaces::DkgStorage;
    use crate::dkg::types::{
        DkgConfig, DkgOutput, DkgProtocolState, DkgResult, ProtocolType, SessionContext,
        ValidatorInfo,
    };
    use crate::types::ValidatorAddress;
    use async_trait::async_trait;
    use fastcrypto::groups::GroupElement;
    use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn create_test_validator(party_id: u16) -> ValidatorInfo {
        use fastcrypto::groups::ristretto255::RistrettoPoint;

        let private_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_private_key(&private_key);
        ValidatorInfo {
            address: ValidatorAddress([party_id as u8; 32]),
            party_id,
            weight: 1,
            ecies_public_key: public_key,
        }
    }

    #[derive(Clone)]
    struct MockStorage {
        save_count: Arc<AtomicUsize>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                save_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    struct TestSetup {
        validators: Vec<ValidatorInfo>,
        config: DkgConfig,
        session: SessionContext,
        storage: MockStorage,
    }

    impl TestSetup {
        fn single_validator() -> Self {
            Self::with_validators(1, 1, 0)
        }

        fn with_validators(num_validators: u16, threshold: u16, max_faulty: u16) -> Self {
            let validators: Vec<ValidatorInfo> =
                (0..num_validators).map(create_test_validator).collect();
            let config = DkgConfig::new(1, validators.clone(), threshold, max_faulty).unwrap();
            let session =
                SessionContext::new(1, ProtocolType::DkgKeyGeneration, "testnet".to_string());
            let storage = MockStorage::new();
            Self {
                validators,
                config,
                session,
                storage,
            }
        }

        /// Create a coordinator for the first validator
        fn create_coordinator(
            &self,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage> {
            self.create_coordinator_with_config(CoordinatorConfig::default())
        }

        /// Create a coordinator with custom config
        fn create_coordinator_with_config(
            &self,
            coordinator_config: CoordinatorConfig,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage> {
            let validator_addresses: Vec<ValidatorAddress> =
                self.validators.iter().map(|v| v.address.clone()).collect();
            let channels = InMemoryP2PChannels::new_network(validator_addresses);
            let p2p_channel = channels.into_iter().next().unwrap().1;
            DkgCoordinator::new(
                self.validators[0].clone(),
                self.config.clone(),
                self.session.clone(),
                coordinator_config,
                p2p_channel,
                None, // No ordered broadcast channel for tests currently
                Some(self.storage.clone()),
            )
        }
    }

    #[async_trait]
    impl DkgStorage for MockStorage {
        async fn save_output(
            &self,
            _session: &SessionContext,
            _output: &DkgOutput,
        ) -> DkgResult<()> {
            self.save_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn load_output(&self, _session: &SessionContext) -> DkgResult<Option<DkgOutput>> {
            Ok(None)
        }

        async fn save_checkpoint(
            &self,
            _session: &SessionContext,
            _state: &DkgProtocolState,
        ) -> DkgResult<()> {
            self.save_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn load_checkpoint(
            &self,
            _session: &SessionContext,
        ) -> DkgResult<Option<DkgProtocolState>> {
            Ok(None)
        }

        async fn list_sessions(&self) -> DkgResult<Vec<SessionContext>> {
            Ok(vec![])
        }

        async fn cleanup_session(&self, _session: &SessionContext) -> DkgResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_coordinator_creation() {
        let setup = TestSetup::single_validator();
        let coordinator = setup.create_coordinator();

        assert!(coordinator.is_idle());
    }

    #[tokio::test]
    async fn test_coordinator_start() {
        let setup = TestSetup::single_validator();
        let mut coordinator = setup.create_coordinator();

        assert!(coordinator.is_idle());

        coordinator.start().await.unwrap();

        // Should transition to Running state
        assert!(coordinator.is_running());

        // All dealers should be in WaitingForShare state
        if let DkgState::Running { dealer_states, .. } = coordinator.current_state() {
            assert_eq!(dealer_states.len(), 1); // Single validator setup
            for state in dealer_states.values() {
                assert!(matches!(state, DealerState::WaitingForShare { .. }));
            }
        }
    }

    #[tokio::test]
    async fn test_timeout_detection() {
        let setup = TestSetup::single_validator();

        // Set a short timeout
        let coordinator_config = CoordinatorConfig {
            phase_timeout: Duration::from_millis(50),
            enable_persistence: false,
            max_send_retries: 3,
        };

        let mut coordinator = setup.create_coordinator_with_config(coordinator_config);
        coordinator.start().await.unwrap();

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check and handle timeout
        coordinator.handle_timeout();
        assert!(coordinator.is_failed());
    }

    #[tokio::test]
    async fn test_multiple_start_calls() {
        let setup = TestSetup::single_validator();
        let mut coordinator = setup.create_coordinator();

        // First start should succeed
        coordinator.start().await.unwrap();

        // Second start should fail
        let result = coordinator.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_required_shares_calculation() {
        let num_validators = 5;
        let threshold = 3;
        let max_faulty = 1;
        let setup = TestSetup::with_validators(num_validators, threshold, max_faulty);
        let coordinator = setup.create_coordinator();
        assert_eq!(
            coordinator.required_shares(),
            (num_validators - max_faulty) as usize
        );

        let setup2 = TestSetup::with_validators(7, 4, 1);
        let coordinator2 = setup2.create_coordinator();
        assert_eq!(coordinator2.required_shares(), 6);
    }

    #[tokio::test]
    async fn test_transition_to_completed() {
        use fastcrypto_tbls::threshold_schnorr::avss;
        use std::time::Instant;

        let num_validators = 4;
        let threshold = 2;
        let max_faulty = 1;
        let setup = TestSetup::with_validators(num_validators, threshold, max_faulty);
        let mut coordinator = setup.create_coordinator();

        for i in 0..3 {
            let validator_id = setup.validators[i as usize].address.clone();
            coordinator
                .processed_shares
                .insert(validator_id.clone(), avss::SharesForNode { shares: vec![] });
            coordinator
                .processed_commitments
                .insert(validator_id, vec![]);
        }

        // Set state to Running with all dealers marked as completed
        let mut dealer_states = BTreeMap::new();
        for i in 0..num_validators {
            dealer_states.insert(
                setup.validators[i as usize].address.clone(),
                DealerState::Completed,
            );
        }
        coordinator.dkg_state = DkgState::Running {
            start_time: Instant::now(),
            dealer_states,
        };

        // Check progress should transition to Completed
        coordinator.check_progress().await.unwrap();
        assert!(matches!(coordinator.dkg_state, DkgState::Completed { .. }));

        // Verify output has correct session context
        if let DkgState::Completed { output } = &coordinator.dkg_state {
            assert_eq!(output.session_context.epoch, setup.session.epoch);
        }
    }

    #[tokio::test]
    async fn test_storage_persistence() {
        use fastcrypto_tbls::threshold_schnorr::avss;

        let setup = TestSetup::single_validator();
        let save_count_clone = setup.storage.save_count.clone();
        let coordinator_config = CoordinatorConfig {
            phase_timeout: Duration::from_secs(30),
            enable_persistence: true,
            max_send_retries: 3,
        };
        let mut coordinator = setup.create_coordinator_with_config(coordinator_config);

        coordinator.start().await.unwrap();

        if let Some(storage) = &coordinator.storage
            && coordinator.coordinator_config.enable_persistence
        {
            storage
                .save_output(
                    &setup.session,
                    &DkgOutput {
                        public_key: G::zero(),
                        key_shares: avss::SharesForNode { shares: vec![] },
                        commitments: vec![],
                        session_context: setup.session.clone(),
                    },
                )
                .await
                .unwrap();
        }

        assert!(save_count_clone.load(Ordering::SeqCst) > 0);
    }

    #[tokio::test]
    async fn test_handle_approval() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        let dealer = setup.validators[1].address.clone();
        let sender = setup.validators[2].address.clone();

        // Test approval for unknown share (should fail)
        let approval = MessageApproval {
            message_hash: [0u8; 32],
            approver: dealer.clone(),
            signature: vec![1, 2, 3],
            timestamp: 1000,
        };
        let result = coordinator
            .handle_approval(sender.clone(), approval.clone())
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Approval for unknown share")
        );

        // Now simulate having received a share from the dealer
        // We mark the dealer as Processing in the state machine
        if let DkgState::Running { dealer_states, .. } = &mut coordinator.dkg_state {
            dealer_states.insert(
                dealer.clone(),
                DealerState::Processing {
                    received_at: std::time::Instant::now(),
                },
            );
        }
        coordinator
            .share_approvals
            .entry(dealer.clone())
            .or_default()
            .insert(sender.clone());
        assert!(coordinator.share_approvals.contains_key(&dealer));
        assert!(
            coordinator
                .share_approvals
                .get(&dealer)
                .unwrap()
                .contains(&sender)
        );
    }

    #[tokio::test]
    async fn test_handle_data_availability_signature() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        let dealer = setup.validators[0].address.clone();
        let signer = setup.validators[1].address.clone();
        let signature = vec![1, 2, 3, 4];
        let message_hash = [5u8; 32];

        // Test valid signature
        coordinator
            .handle_data_availability_signature(
                signer.clone(),
                dealer.clone(),
                message_hash,
                signature.clone(),
            )
            .await
            .unwrap();
        assert!(
            coordinator
                .data_availability_signatures
                .contains_key(&dealer)
        );
        let sigs = coordinator
            .data_availability_signatures
            .get(&dealer)
            .unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].validator, signer);
        assert_eq!(sigs[0].signature, signature);

        // Test with unknown dealer
        let unknown_dealer = ValidatorAddress([99; 32]);
        let result = coordinator
            .handle_data_availability_signature(signer, unknown_dealer, message_hash, vec![6, 7, 8])
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handle_dkg_signature() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        let dealer = setup.validators[0].address.clone();
        let message_hash = [5u8; 32];

        // Add enough signatures to complete the dealer
        let required_sigs = setup.config.required_dkg_signatures();
        for i in 1..=required_sigs {
            let signer = setup.validators[i % setup.validators.len()].address.clone();
            let signature = vec![i as u8, 2, 3, 4];

            coordinator
                .handle_dkg_signature(signer.clone(), dealer.clone(), message_hash, signature)
                .await
                .unwrap();
        }

        assert!(coordinator.dkg_signatures.contains_key(&dealer));
        let sigs = coordinator.dkg_signatures.get(&dealer).unwrap();
        assert_eq!(sigs.len(), required_sigs);
        if let DkgState::Running { dealer_states, .. } = &coordinator.dkg_state {
            assert!(matches!(
                dealer_states.get(&dealer),
                Some(DealerState::Completed)
            ));
        }
    }

    #[tokio::test]
    async fn test_handle_share_request() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        let dealer = setup.validators[0].address.clone();
        let requester = setup.validators[1].address.clone();
        let message_hash = [5u8; 32];

        // Test request when we're not the dealer - should succeed (we just don't respond)
        let other_dealer = setup.validators[2].address.clone();
        let result = coordinator
            .handle_share_request(requester.clone(), other_dealer, message_hash)
            .await;
        assert!(result.is_ok());

        // Test request when we are the dealer but don't have the share - should fail
        let result = coordinator
            .handle_share_request(requester.clone(), dealer.clone(), message_hash)
            .await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Share not available")
        );
    }

    #[tokio::test]
    async fn test_message_validation() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        let dealer = setup.validators[0].address.clone();
        let wrong_sender = setup.validators[1].address.clone();
        let claimed_signer = setup.validators[2].address.clone();
        let session_id = setup.session.session_id();

        // Test DataAvailabilitySignatureV1 with sender mismatch
        let msg = P2PMessage::DataAvailabilitySignatureV1 {
            session_id,
            signer: claimed_signer.clone(),
            dealer: dealer.clone(),
            message_hash: [0u8; 32],
            signature: vec![1, 2, 3],
        };
        let result = coordinator.handle_message(wrong_sender.clone(), msg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Signer mismatch"));

        // Test DkgSignatureV1 with wrong session ID
        let wrong_session =
            SessionContext::new(99, ProtocolType::DkgKeyGeneration, "testnet".to_string());
        let msg = P2PMessage::DkgSignatureV1 {
            session_id: wrong_session.session_id(),
            signer: wrong_sender.clone(),
            dealer: dealer.clone(),
            message_hash: [0u8; 32],
            signature: vec![1, 2, 3],
        };
        let result = coordinator.handle_message(wrong_sender.clone(), msg).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Session ID mismatch")
        );

        // Test ShareRequestV1 with requester mismatch
        let msg = P2PMessage::ShareRequestV1 {
            session_id,
            requester: claimed_signer,
            dealer,
            message_hash: [0u8; 32],
        };
        let result = coordinator.handle_message(wrong_sender, msg).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Requester mismatch")
        );
    }

    #[tokio::test]
    async fn test_threshold_tracking() {
        let setup = TestSetup::with_validators(7, 3, 2);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();
        let dealer = setup.validators[0].address.clone();

        // Track that we need 2f+1 = 5 signatures for both types
        let required_da = setup.config.required_data_availability_signatures();
        let required_dkg = setup.config.required_dkg_signatures();
        assert_eq!(required_da, 5);
        assert_eq!(required_dkg, 5);

        // Add data availability signatures
        for i in 1..=required_da {
            let signer = setup.validators[i].address.clone();
            coordinator
                .handle_data_availability_signature(
                    signer,
                    dealer.clone(),
                    [0u8; 32],
                    vec![i as u8],
                )
                .await
                .unwrap();
        }
        // Add DKG signatures
        for i in 1..=required_dkg {
            let signer = setup.validators[i].address.clone();
            coordinator
                .handle_dkg_signature(signer, dealer.clone(), [0u8; 32], vec![i as u8 + 10])
                .await
                .unwrap();
        }

        // Verify we have the right number of signatures
        assert_eq!(
            coordinator
                .data_availability_signatures
                .get(&dealer)
                .unwrap()
                .len(),
            required_da
        );
        assert_eq!(
            coordinator.dkg_signatures.get(&dealer).unwrap().len(),
            required_dkg
        );

        // Verify dealer is marked as completed after getting enough DKG signatures
        if let DkgState::Running { dealer_states, .. } = &coordinator.dkg_state {
            assert!(matches!(
                dealer_states.get(&dealer),
                Some(DealerState::Completed)
            ));
        }
    }
}
