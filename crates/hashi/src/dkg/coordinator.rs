//! DKG coordinator that manages the protocol state machine

use crate::communication::{
    AuthenticatedMessage, ChannelError, OrderedBroadcastChannel, P2PChannel,
};
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
use tokio::select;
use tracing::{error, warn};

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

#[derive(Debug, Clone)]
pub enum DealerState {
    /// Waiting for share from this dealer
    WaitingForShare,
    /// Received share, now processing/verifying
    Processing,
    /// Handling complaint about this dealer's share
    ComplaintHandling {
        complaint_count: usize,
        response_count: usize,
    },
    /// Successfully processed this dealer's share
    Completed,
    /// Failed to get valid share from this dealer
    Failed { reason: String },
}

// TODO: Consider add timeout for each DKG phase
#[derive(Debug, Clone)]
pub enum DkgState {
    /// Initial state, waiting to start
    Idle,
    /// Running phase - tracking each dealer's state separately
    Running {
        /// State for each dealer's DKG instance
        dealer_states: BTreeMap<ValidatorAddress, DealerState>,
    },
    /// Success state - DKG completed successfully
    Completed { output: Box<DkgOutput> },
    /// Failed state - DKG failed
    Failed { reason: String },
}

#[derive(Clone, Debug)]
pub struct DkgConfiguration {
    pub validator_info: ValidatorInfo,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
}

impl DkgConfiguration {
    pub fn new(
        validator_info: ValidatorInfo,
        dkg_config: DkgConfig,
        session_context: SessionContext,
    ) -> Self {
        Self {
            validator_info,
            dkg_config,
            session_context,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DkgProtocolData {
    pub received_messages: BTreeMap<ValidatorAddress, avss::Message>,
    pub processed_shares: BTreeMap<ValidatorAddress, avss::SharesForNode>,
    pub processed_commitments: BTreeMap<ValidatorAddress, Vec<Eval<G>>>,
}

impl DkgProtocolData {
    pub fn new() -> Self {
        Self {
            received_messages: BTreeMap::new(),
            processed_shares: BTreeMap::new(),
            processed_commitments: BTreeMap::new(),
        }
    }
}

impl Default for DkgProtocolData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct DkgSignatureTracker {
    pub data_availability_signatures: BTreeMap<ValidatorAddress, Vec<ValidatorSignature>>,
    pub dkg_signatures: BTreeMap<ValidatorAddress, Vec<ValidatorSignature>>,
    pub share_approvals: BTreeMap<ValidatorAddress, HashSet<ValidatorAddress>>,
}

impl DkgSignatureTracker {
    pub fn new() -> Self {
        Self {
            data_availability_signatures: BTreeMap::new(),
            dkg_signatures: BTreeMap::new(),
            share_approvals: BTreeMap::new(),
        }
    }
}

impl Default for DkgSignatureTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DkgCommunicationChannels<P, O> {
    pub p2p: P,
    pub ordered_broadcast: Option<O>,
}

impl<P, O> DkgCommunicationChannels<P, O> {
    pub fn new(p2p: P, ordered_broadcast: Option<O>) -> Self {
        Self {
            p2p,
            ordered_broadcast,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DkgRuntimeState {
    pub dkg_state: DkgState,
    pub protocol_data: DkgProtocolData,
    pub signature_tracker: DkgSignatureTracker,
}

impl DkgRuntimeState {
    pub fn new() -> Self {
        Self {
            dkg_state: DkgState::Idle,
            protocol_data: DkgProtocolData::new(),
            signature_tracker: DkgSignatureTracker::new(),
        }
    }
}

impl Default for DkgRuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DkgCoordinator<P, O, S: DkgStorage> {
    pub config: DkgConfiguration,
    pub state: DkgRuntimeState,
    pub channels: DkgCommunicationChannels<P, O>,
    pub storage: Option<S>,
}

impl<P, O, S: DkgStorage> DkgCoordinator<P, O, S> {
    pub fn new(
        config: DkgConfiguration,
        state: DkgRuntimeState,
        channels: DkgCommunicationChannels<P, O>,
        storage: Option<S>,
    ) -> Self {
        Self {
            config,
            state,
            channels,
            storage,
        }
    }

    // TODO: Add unit tests after all the other to-do's are completed
    pub async fn run<'a>(&'a mut self) -> DkgResult<()>
    where
        P: P2PChannel<P2PMessage> + 'a,
        O: OrderedBroadcastChannel<OrderedBroadcastMessage> + 'a,
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
            if self.is_complete() || self.is_failed() {
                break;
            }
            self.publish_pending_certificates().await?;
            select! {
                p2p_result = self.channels.p2p.receive() => {
                    match p2p_result {
                        Ok(AuthenticatedMessage { sender, message }) => {
                            if let Err(e) = self.handle_message(sender.clone(), message).await {
                                self.handle_dkg_error(
                                    e,
                                    format!("P2P message from {:?}", sender),
                                ).await?;
                            }
                        }
                        Err(ChannelError::Timeout) => {
                            // Continue waiting
                        }
                        Err(ChannelError::Closed) => {
                            return Err(DkgError::ProtocolFailed("P2P channel closed".to_string()));
                        }
                        Err(e) => {
                            self.handle_channel_error(e, "P2P channel").await?;
                        }
                    }
                }
                ordered_result = async {
                    if let Some(ref mut channel) = self.channels.ordered_broadcast {
                        channel.receive().await
                    } else {
                        // If no ordered channel, just wait forever
                        std::future::pending().await
                    }
                }, if self.channels.ordered_broadcast.is_some() => {
                    match ordered_result {
                        Ok(AuthenticatedMessage { sender, message }) => {
                            if let Err(e) = self.handle_ordered_message(message).await {
                                self.handle_dkg_error(
                                    e,
                                    format!("Ordered broadcast message from {:?}", sender),
                                ).await?;
                            }
                        }
                        Err(ChannelError::Timeout) => {
                            // Continue waiting
                        }
                        Err(ChannelError::Closed) => {
                            return Err(DkgError::ProtocolFailed("Ordered broadcast channel closed".to_string()));
                        }
                        Err(e) => {
                            self.handle_channel_error(e, "Ordered broadcast channel").await?;
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

    pub fn current_state(&self) -> &DkgState {
        &self.state.dkg_state
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state.dkg_state, DkgState::Completed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state.dkg_state, DkgState::Failed { .. })
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state.dkg_state, DkgState::Idle)
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state.dkg_state, DkgState::Running { .. })
    }

    async fn start(&mut self) -> DkgResult<()> {
        match &self.state.dkg_state {
            DkgState::Idle => {
                let mut dealer_states = BTreeMap::new();
                for validator in &self.config.dkg_config.validators {
                    dealer_states.insert(validator.address.clone(), DealerState::WaitingForShare);
                }
                self.state.dkg_state = DkgState::Running { dealer_states };
                Ok(())
            }
            _ => Err(DkgError::ProtocolFailed(
                "Cannot start: already in progress".to_string(),
            )),
        }
    }

    async fn publish_pending_certificates(&mut self) -> DkgResult<()>
    where
        O: OrderedBroadcastChannel<OrderedBroadcastMessage>,
    {
        if let Some(ref mut channel) = self.channels.ordered_broadcast {
            let required_approvals = self.config.dkg_config.required_dkg_signatures();
            let dealers_to_publish: Vec<ValidatorAddress> = self
                .state
                .signature_tracker
                .share_approvals
                .iter()
                .filter_map(|(dealer, approvers)| {
                    if approvers.len() >= required_approvals
                        && *dealer == self.config.validator_info.address
                    {
                        Some(dealer.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for dealer in dealers_to_publish {
                if let Some(approvers) = self.state.signature_tracker.share_approvals.get(&dealer) {
                    let signatures: Vec<ValidatorSignature> = approvers
                        .iter()
                        .map(|approver| ValidatorSignature {
                            validator: approver.clone(),
                            signature: vec![], // TODO: Store actual signatures from approvals
                        })
                        .collect();

                    // Create the certificate
                    // TODO: Retrieve actual message hash from the AVSS message we received as dealer
                    let message_hash = [0u8; 32];

                    // For now, use the collected signatures as DKG signatures
                    // In practice, we'd separate DA and DKG signatures
                    let certificate = crate::dkg::types::DkgCertificate {
                        dealer: dealer.clone(),
                        message_hash,
                        data_availability_signatures: vec![], // TODO: Collect from data_availability_signatures in signature_tracker
                        dkg_signatures: signatures,
                        session_context: self.config.session_context.clone(),
                    };

                    // Publish to ordered broadcast channel
                    let message = OrderedBroadcastMessage::CertificateV1(certificate);
                    channel.publish(message).await.map_err(|e| {
                        DkgError::ProtocolFailed(format!("Failed to publish certificate: {}", e))
                    })?;

                    // Remove from pending after publishing
                    self.state.signature_tracker.share_approvals.remove(&dealer);
                }
            }
        }
        Ok(())
    }

    async fn handle_ordered_message(&mut self, message: OrderedBroadcastMessage) -> DkgResult<()> {
        match message {
            OrderedBroadcastMessage::CertificateV1(_cert) => {
                // TODO: Implement certificate verification and processing
                Ok(())
            }
            OrderedBroadcastMessage::PresignatureV1 {
                sender: _,
                session_context: _,
                data: _,
            } => {
                // TODO: Implement presignature handling for threshold signing phase
                Ok(())
            }
        }
    }

    async fn handle_share(
        &mut self,
        dealer: ValidatorAddress,
        message: avss::Message,
    ) -> DkgResult<()> {
        match &mut self.state.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                if let Some(dealer_state) = dealer_states.get_mut(&dealer) {
                    match dealer_state {
                        DealerState::WaitingForShare => {
                            self.state
                                .protocol_data
                                .received_messages
                                .insert(dealer.clone(), message);
                            *dealer_state = DealerState::Processing;
                            // TODO: Implement the full AVSS protocol flow
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
        match &mut self.state.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                // TODO: Extract dealer ID from complaint.accused_id field
                for (_dealer_id, dealer_state) in dealer_states.iter_mut() {
                    match dealer_state {
                        DealerState::Processing => {
                            *dealer_state = DealerState::ComplaintHandling {
                                complaint_count: 1,
                                response_count: 0,
                            };

                            // TODO: Implement complaint verification and response

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
        match &mut self.state.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                // TODO: Extract dealer ID from the AVSS message that the complaint/response relates to
                for dealer_state in dealer_states.values_mut() {
                    if let DealerState::ComplaintHandling { response_count, .. } = dealer_state {
                        *response_count += 1;

                        // TODO: Process complaint response

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
        if let DkgState::Running { dealer_states, .. } = &self.state.dkg_state {
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
        if self.state.protocol_data.processed_shares.len() >= self.required_shares() {
            // TODO: Compute from the polynomial commitments when implementing the full protocol flow
            // Use zero element as placeholder for now
            let public_key = G::zero();
            // Create empty shares for now - would be filled from processed data
            let key_shares = avss::SharesForNode { shares: vec![] };
            let output = DkgOutput {
                public_key,
                key_shares,
                commitments: vec![],
                session_context: self.config.session_context.clone(),
            };
            self.state.dkg_state = DkgState::Completed {
                output: Box::new(output.clone()),
            };
            if let Some(storage) = &self.storage {
                storage
                    .save_output(&self.config.session_context, &output)
                    .await?;
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
        if !self
            .state
            .protocol_data
            .received_messages
            .contains_key(&approval.approver)
        {
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Approval for unknown share".to_string(),
            });
        }
        self.state
            .signature_tracker
            .share_approvals
            .entry(approval.approver.clone())
            .or_default()
            .insert(sender);

        // Check if we have enough approvals to create a certificate
        let required_approvals = self.config.dkg_config.required_dkg_signatures();
        if let Some(approvers) = self
            .state
            .signature_tracker
            .share_approvals
            .get(&approval.approver)
            && approvers.len() >= required_approvals
            && approval.approver == self.config.validator_info.address
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
        self.state
            .signature_tracker
            .data_availability_signatures
            .entry(dealer.clone())
            .or_default()
            .push(sig);

        // Check if we have enough signatures for data availability
        let required = self
            .config
            .dkg_config
            .required_data_availability_signatures();
        if let Some(sigs) = self
            .state
            .signature_tracker
            .data_availability_signatures
            .get(&dealer)
            && sigs.len() >= required
        {
            // TODO: Update DealerState to track data availability status
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
        self.state
            .signature_tracker
            .dkg_signatures
            .entry(dealer.clone())
            .or_default()
            .push(sig);
        let required = self.config.dkg_config.required_dkg_signatures();
        if let Some(sigs) = self.state.signature_tracker.dkg_signatures.get(&dealer)
            && sigs.len() >= required
        {
            if let DkgState::Running { dealer_states, .. } = &mut self.state.dkg_state
                && let Some(dealer_state) = dealer_states.get_mut(&dealer)
            {
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
        if dealer == self.config.validator_info.address {
            // Check if we have the share for this requester
            if let Some(_avss_message) = self.state.protocol_data.received_messages.get(&dealer) {
                // TODO: Implement share recovery assistance
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
        // TODO: Properly track complaint resolution:
        // Need to check if we have received t valid ComplaintResponses
        // and call receiver.recover() to reconstruct the share
        if let DkgState::Running { dealer_states, .. } = &mut self.state.dkg_state {
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
        self.config
            .dkg_config
            .validators
            .len()
            .saturating_sub(self.config.dkg_config.max_faulty as usize)
    }

    fn validate_session_id(
        &self,
        authenticated_sender: &ValidatorAddress,
        session_id: &SessionId,
    ) -> DkgResult<()> {
        if *session_id != self.config.session_context.session_id() {
            return Err(DkgError::InvalidMessage {
                sender: authenticated_sender.clone(),
                reason: "Session ID mismatch".to_string(),
            });
        }
        Ok(())
    }

    fn validate_dealer(&self, dealer: &ValidatorAddress) -> bool {
        self.config
            .dkg_config
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

    async fn handle_dkg_error(&mut self, error: DkgError, context: String) -> DkgResult<()> {
        match &error {
            DkgError::InvalidMessage { sender, reason } => {
                warn!(
                    sender = ?sender,
                    reason = %reason,
                    context = %context,
                    "Invalid message received"
                );
            }
            DkgError::ProtocolFailed(msg) => {
                error!(
                    message = %msg,
                    context = %context,
                    "Protocol failure"
                );
            }
            _ => {
                warn!(
                    error = ?error,
                    context = %context,
                    "Processing error"
                );
            }
        }
        // Always log and continue - resilient to Byzantine behavior
        Ok(())
    }

    async fn handle_channel_error(
        &mut self,
        error: ChannelError,
        channel_name: &str,
    ) -> DkgResult<()> {
        warn!(
            channel = %channel_name,
            error = ?error,
            "Channel error occurred"
        );
        // Continue processing - channel errors are typically transient
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

        fn create_coordinator(
            &self,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage> {
            let validator_addresses: Vec<ValidatorAddress> =
                self.validators.iter().map(|v| v.address.clone()).collect();
            let channels = InMemoryP2PChannels::new_network(validator_addresses);
            let p2p_channel = channels.into_iter().next().unwrap().1;
            let config = DkgConfiguration::new(
                self.validators[0].clone(),
                self.config.clone(),
                self.session.clone(),
            );
            let state = DkgRuntimeState::new();
            let communication_channels = DkgCommunicationChannels::new(p2p_channel, None);
            DkgCoordinator::new(
                config,
                state,
                communication_channels,
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
                assert!(matches!(state, DealerState::WaitingForShare));
            }
        }
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

        let num_validators = 4;
        let threshold = 2;
        let max_faulty = 1;
        let setup = TestSetup::with_validators(num_validators, threshold, max_faulty);
        let mut coordinator = setup.create_coordinator();

        for i in 0..3 {
            let validator_id = setup.validators[i as usize].address.clone();
            coordinator
                .state
                .protocol_data
                .processed_shares
                .insert(validator_id.clone(), avss::SharesForNode { shares: vec![] });
            coordinator
                .state
                .protocol_data
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
        coordinator.state.dkg_state = DkgState::Running { dealer_states };

        // Check progress should transition to Completed
        coordinator.check_progress().await.unwrap();
        assert!(matches!(
            coordinator.state.dkg_state,
            DkgState::Completed { .. }
        ));

        // Verify output has correct session context
        if let DkgState::Completed { output } = &coordinator.state.dkg_state {
            assert_eq!(output.session_context.epoch, setup.session.epoch);
        }
    }

    #[tokio::test]
    async fn test_storage_persistence() {
        use fastcrypto_tbls::threshold_schnorr::avss;

        let setup = TestSetup::single_validator();
        let save_count_clone = setup.storage.save_count.clone();
        let mut coordinator = setup.create_coordinator();

        coordinator.start().await.unwrap();

        if let Some(storage) = &coordinator.storage {
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
        if let DkgState::Running { dealer_states, .. } = &mut coordinator.state.dkg_state {
            dealer_states.insert(dealer.clone(), DealerState::Processing);
        }
        coordinator
            .state
            .signature_tracker
            .share_approvals
            .entry(dealer.clone())
            .or_default()
            .insert(sender.clone());
        assert!(
            coordinator
                .state
                .signature_tracker
                .share_approvals
                .contains_key(&dealer)
        );
        assert!(
            coordinator
                .state
                .signature_tracker
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
                .state
                .signature_tracker
                .data_availability_signatures
                .contains_key(&dealer)
        );
        let sigs = coordinator
            .state
            .signature_tracker
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

        assert!(
            coordinator
                .state
                .signature_tracker
                .dkg_signatures
                .contains_key(&dealer)
        );
        let sigs = coordinator
            .state
            .signature_tracker
            .dkg_signatures
            .get(&dealer)
            .unwrap();
        assert_eq!(sigs.len(), required_sigs);
        if let DkgState::Running { dealer_states, .. } = &coordinator.state.dkg_state {
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
                .state
                .signature_tracker
                .data_availability_signatures
                .get(&dealer)
                .unwrap()
                .len(),
            required_da
        );
        assert_eq!(
            coordinator
                .state
                .signature_tracker
                .dkg_signatures
                .get(&dealer)
                .unwrap()
                .len(),
            required_dkg
        );

        // Verify dealer is marked as completed after getting enough DKG signatures
        if let DkgState::Running { dealer_states, .. } = &coordinator.state.dkg_state {
            assert!(matches!(
                dealer_states.get(&dealer),
                Some(DealerState::Completed)
            ));
        }
    }

    #[tokio::test]
    async fn test_error_handling() {
        let setup = TestSetup::with_validators(2, 1, 0);

        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();

        // Test that invalid messages are handled gracefully
        let invalid_sender = ValidatorAddress([99; 32]);
        let result = coordinator
            .handle_message(
                invalid_sender.clone(),
                P2PMessage::ApprovalV1(MessageApproval {
                    message_hash: [0u8; 32],
                    approver: invalid_sender.clone(),
                    signature: vec![],
                    timestamp: 0,
                }),
            )
            .await;

        // Should return error (invalid validator)
        assert!(result.is_err());

        // But coordinator should still be running
        assert!(coordinator.is_running());

        // Test that errors are handled gracefully without crashing
        for i in 0..5 {
            let error = DkgError::InvalidMessage {
                sender: ValidatorAddress([i as u8; 32]),
                reason: format!("test error {}", i),
            };
            // Should handle errors without panicking
            let result = coordinator
                .handle_dkg_error(error, format!("test context {}", i))
                .await;
            assert!(result.is_ok());
        }
    }
}
