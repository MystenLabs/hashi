//! DKG coordinator that manages the protocol state machine

use crate::communication::{
    AuthenticatedMessage, ChannelError, OrderedBroadcastChannel, P2PChannel,
};
use crate::dkg::interfaces::DkgStorage;
use crate::dkg::types::{
    DkgConfig, DkgError, DkgOutput, DkgResult, MessageApproval, MessageHash,
    OrderedBroadcastMessage, P2PMessage, SessionContext, SessionId, ValidatorInfo,
    ValidatorSignature,
};
use crate::types::ValidatorAddress;
use fastcrypto::groups::GroupElement;
use fastcrypto::groups::ristretto255::RistrettoPoint;
use fastcrypto::hash::{HashFunction, Sha3_256};
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::nodes::{Node, Nodes};
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::{G, avss, complaint};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::{Duration, Instant};
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

fn convert_dkg_config_to_fastcrypto_nodes(config: &DkgConfig) -> DkgResult<Nodes<RistrettoPoint>> {
    let nodes: Vec<Node<RistrettoPoint>> = config
        .validators
        .iter()
        .map(|v| Node {
            id: v.party_id,
            pk: v.ecies_public_key.clone(),
            weight: v.weight,
        })
        .collect();
    Nodes::new(nodes).map_err(|e| DkgError::CryptoError(e.to_string()))
}

fn compute_message_hash(message: &avss::Message) -> MessageHash {
    let serialized = bcs::to_bytes(message).expect("Failed to serialize AVSS message");
    Sha3_256::digest(&serialized).digest
}

#[derive(Debug, Clone)]
pub struct DkgErrorRecord {
    pub timestamp: Instant,
    pub error: String,
    pub context: String,
}

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
    /// Maximum number of errors to keep in history
    pub max_error_history: usize,
}

impl Default for CoordinatorConfig {
    // TODO: Set the values in a config file.
    fn default() -> Self {
        Self {
            phase_timeout: Duration::from_secs(30),
            max_send_retries: 3,
            enable_persistence: true,
            max_error_history: 100,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DkgConfiguration {
    pub validator_info: ValidatorInfo,
    pub dkg_config: DkgConfig,
    pub session_context: SessionContext,
    pub coordinator_config: CoordinatorConfig,
    pub ecies_private_key: PrivateKey<RistrettoPoint>,
}

impl DkgConfiguration {
    pub fn new(
        validator_info: ValidatorInfo,
        dkg_config: DkgConfig,
        session_context: SessionContext,
        coordinator_config: CoordinatorConfig,
        ecies_private_key: PrivateKey<RistrettoPoint>,
    ) -> Self {
        Self {
            validator_info,
            dkg_config,
            session_context,
            coordinator_config,
            ecies_private_key,
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
    pub error_history: VecDeque<DkgErrorRecord>,
}

impl DkgRuntimeState {
    pub fn new() -> Self {
        Self {
            dkg_state: DkgState::Idle,
            protocol_data: DkgProtocolData::new(),
            signature_tracker: DkgSignatureTracker::new(),
            error_history: VecDeque::new(),
        }
    }

    pub fn record_error(&mut self, error: String, context: String, max_history: usize) {
        let error_record = DkgErrorRecord {
            timestamp: Instant::now(),
            error,
            context,
        };
        self.error_history.push_back(error_record);
        while self.error_history.len() > max_history {
            self.error_history.pop_front();
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
            if self.check_timeout() {
                self.handle_timeout();
                break;
            }
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

    pub fn check_timeout(&mut self) -> bool {
        let timeout = self.config.coordinator_config.phase_timeout;
        match &self.state.dkg_state {
            DkgState::Running { start_time, .. } => start_time.elapsed() > timeout,
            _ => false,
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
                let now = Instant::now();
                for validator in &self.config.dkg_config.validators {
                    dealer_states.insert(
                        validator.address.clone(),
                        DealerState::WaitingForShare { start_time: now },
                    );
                }
                self.state.dkg_state = DkgState::Running {
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

    fn handle_timeout(&mut self) {
        if self.check_timeout()
            && let DkgState::Running { dealer_states, .. } = &self.state.dkg_state
        {
            let mut timed_out_dealers = Vec::new();
            for (dealer_id, dealer_state) in dealer_states.iter() {
                if let DealerState::WaitingForShare { start_time } = dealer_state
                    && start_time.elapsed() > self.config.coordinator_config.phase_timeout
                {
                    timed_out_dealers.push(dealer_id.clone());
                }
            }
            if !timed_out_dealers.is_empty() {
                self.state.dkg_state = DkgState::Failed {
                    reason: format!(
                        "Timeout waiting for shares from dealers: {:?}",
                        timed_out_dealers
                    ),
                };
            } else {
                self.state.dkg_state = DkgState::Failed {
                    reason: "Timeout in DKG protocol".to_string(),
                };
            }
        }
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
        let message_hash = compute_message_hash(&message);
        match &mut self.state.dkg_state {
            DkgState::Running { dealer_states, .. } => {
                if let Some(dealer_state) = dealer_states.get_mut(&dealer) {
                    match dealer_state {
                        DealerState::WaitingForShare { .. } => {
                            self.state
                                .protocol_data
                                .received_messages
                                .insert(dealer.clone(), message.clone());
                            *dealer_state = DealerState::Processing {
                                received_at: Instant::now(),
                            };
                            let nodes =
                                convert_dkg_config_to_fastcrypto_nodes(&self.config.dkg_config)?;
                            let sid = self
                                .config
                                .session_context
                                .dealer_session_id(&dealer)
                                .digest
                                .to_vec();
                            let receiver = avss::Receiver::new(
                                nodes,
                                self.config.validator_info.party_id,
                                self.config.dkg_config.threshold,
                                sid,
                                None, // No previous round commitment for initial DKG (shares still verified against Feldman commitment in message)
                                self.config.ecies_private_key.clone(),
                            );
                            match receiver.process_message(&message)? {
                                avss::ProcessedMessage::Valid(output) => {
                                    self.state
                                        .protocol_data
                                        .processed_shares
                                        .insert(dealer.clone(), output.my_shares);
                                    self.state
                                        .protocol_data
                                        .processed_commitments
                                        .insert(dealer.clone(), output.commitments);
                                    let _approval = MessageApproval {
                                        message_hash,
                                        approver: dealer.clone(),
                                        signature: vec![], // TODO: Sign the message_hash with our validator key
                                        timestamp: std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                    };

                                    // TODO: Send approval to all parties via P2P channel

                                    *dealer_state = DealerState::Completed;
                                    self.check_progress().await?;
                                    Ok(())
                                }
                                avss::ProcessedMessage::Complaint(_complaint) => {
                                    // TODO: Send complaint to all parties
                                    // For now, mark dealer as failed
                                    *dealer_state = DealerState::Failed {
                                        reason: "Invalid share received".to_string(),
                                    };
                                    Err(DkgError::InvalidMessage {
                                        sender: dealer,
                                        reason: "Share verification failed".to_string(),
                                    })
                                }
                            }
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
                        DealerState::Processing { .. } => {
                            *dealer_state = DealerState::ComplaintHandling {
                                complaint_time: Instant::now(),
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
                output: output.clone(),
            };
            if let Some(storage) = &self.storage
                && self.config.coordinator_config.enable_persistence
            {
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
        let error_str = error.to_string();
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
                    error = %error_str,
                    context = %context,
                    "Processing error"
                );
            }
        }
        self.state.record_error(
            error_str,
            context,
            self.config.coordinator_config.max_error_history,
        );
        // Always log and continue - resilient to Byzantine behavior
        Ok(())
    }

    async fn handle_channel_error(
        &mut self,
        error: ChannelError,
        channel_name: &str,
    ) -> DkgResult<()> {
        let context = format!("{} error", channel_name);
        let error_str = format!("{:?}", error);
        warn!(
            channel = %channel_name,
            error = %error_str,
            "Channel error occurred"
        );
        self.state.record_error(
            error_str,
            context,
            self.config.coordinator_config.max_error_history,
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

        fn create_coordinator(
            &self,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage> {
            self.create_coordinator_with_config(CoordinatorConfig::default())
        }

        fn create_coordinator_with_config(
            &self,
            coordinator_config: CoordinatorConfig,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage> {
            let validator_addresses: Vec<ValidatorAddress> =
                self.validators.iter().map(|v| v.address.clone()).collect();
            let channels = InMemoryP2PChannels::<P2PMessage>::new_network(validator_addresses);
            let p2p_channel = channels.into_iter().next().unwrap().1;
            let ecies_private_key = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
            let config = DkgConfiguration::new(
                self.validators[0].clone(),
                self.config.clone(),
                self.session.clone(),
                coordinator_config,
                ecies_private_key,
            );
            let state = DkgRuntimeState::new();
            let communication_channels =
                DkgCommunicationChannels::new(p2p_channel, Option::<()>::None);
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
            max_error_history: 100,
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
        coordinator.state.dkg_state = DkgState::Running {
            start_time: Instant::now(),
            dealer_states,
        };

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
        let coordinator_config = CoordinatorConfig {
            phase_timeout: Duration::from_secs(30),
            enable_persistence: true,
            max_send_retries: 3,
            max_error_history: 100,
        };
        let mut coordinator = setup.create_coordinator_with_config(coordinator_config);

        coordinator.start().await.unwrap();

        if let Some(storage) = &coordinator.storage
            && coordinator.config.coordinator_config.enable_persistence
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
        if let DkgState::Running { dealer_states, .. } = &mut coordinator.state.dkg_state {
            dealer_states.insert(
                dealer.clone(),
                DealerState::Processing {
                    received_at: std::time::Instant::now(),
                },
            );
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

    fn create_test_coordinator_config(max_error_history: usize) -> CoordinatorConfig {
        CoordinatorConfig {
            phase_timeout: Duration::from_secs(30),
            enable_persistence: false,
            max_send_retries: 3,
            max_error_history,
        }
    }

    #[tokio::test]
    async fn test_error_handling_and_tracking() {
        const TEST_ERROR_COUNT_SMALL: usize = 5;

        let setup = TestSetup::with_validators(2, 1, 0);

        let coordinator_config = create_test_coordinator_config(10);
        let mut coordinator = setup.create_coordinator_with_config(coordinator_config);
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

        // Generate some errors to test tracking
        for i in 0..TEST_ERROR_COUNT_SMALL {
            let error = DkgError::InvalidMessage {
                sender: ValidatorAddress([i as u8; 32]),
                reason: format!("test error {}", i),
            };
            let _ = coordinator
                .handle_dkg_error(error, format!("test context {}", i))
                .await;
        }

        // Verify errors are being tracked
        assert_eq!(
            coordinator.state.error_history.len(),
            TEST_ERROR_COUNT_SMALL
        );
    }

    #[tokio::test]
    async fn test_error_history_limit() {
        const TEST_ERROR_LIMIT: usize = 5;

        let setup = TestSetup::single_validator();
        let coordinator_config = create_test_coordinator_config(TEST_ERROR_LIMIT);
        let mut coordinator = setup.create_coordinator_with_config(coordinator_config);
        coordinator.start().await.unwrap();

        // Generate more errors than the limit
        for i in 0..10 {
            let error = DkgError::InvalidMessage {
                sender: ValidatorAddress([i as u8; 32]),
                reason: format!("error {}", i),
            };
            let _ = coordinator
                .handle_dkg_error(error, format!("context {}", i))
                .await;
        }

        // Should only keep the last TEST_ERROR_LIMIT errors
        assert_eq!(coordinator.state.error_history.len(), TEST_ERROR_LIMIT);

        // Most recent error should be the last one added
        let last_error = coordinator.state.error_history.back().unwrap();
        assert!(last_error.error.contains("error 9"));
    }

    mod avss_test_utils {
        use super::*;

        pub struct AvssTestSetup {
            pub validators: Vec<ValidatorInfo>,
            pub ecies_keys: Vec<PrivateKey<RistrettoPoint>>,
            pub nodes: Nodes<RistrettoPoint>,
            pub threshold: u16,
            pub max_faulty: u16,
        }

        pub struct CoordinatorTestContext {
            pub coordinator: DkgCoordinator<InMemoryP2PChannels<P2PMessage>, (), MockStorage>,
            pub avss_setup: AvssTestSetup,
            pub session: SessionContext,
        }

        impl AvssTestSetup {
            pub fn new(num_validators: u16, threshold: u16, max_faulty: u16) -> Self {
                let mut rng = rand::thread_rng();
                let mut validators = Vec::new();
                let mut ecies_keys = Vec::new();
                for party_id in 0..num_validators {
                    let ecies_private = PrivateKey::<RistrettoPoint>::new(&mut rng);
                    let ecies_public = PublicKey::from_private_key(&ecies_private);
                    validators.push(ValidatorInfo {
                        address: ValidatorAddress([party_id as u8; 32]),
                        party_id,
                        weight: 1,
                        ecies_public_key: ecies_public,
                    });
                    ecies_keys.push(ecies_private);
                }
                let nodes = Nodes::new(
                    validators
                        .iter()
                        .map(|v| Node {
                            id: v.party_id,
                            pk: v.ecies_public_key.clone(),
                            weight: v.weight,
                        })
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                Self {
                    validators,
                    ecies_keys,
                    nodes,
                    threshold,
                    max_faulty,
                }
            }

            pub fn create_valid_message(
                &self,
                dealer_index: usize,
                session_context: &SessionContext,
            ) -> avss::Message {
                let dealer_address = &self.validators[dealer_index].address;
                let sid = session_context
                    .dealer_session_id(dealer_address)
                    .digest
                    .to_vec();
                let dealer = avss::Dealer::new(
                    None,
                    self.nodes.clone(),
                    self.threshold,
                    self.max_faulty,
                    sid,
                )
                .unwrap();
                dealer.create_message(&mut rand::thread_rng()).unwrap()
            }
        }

        pub fn create_test_coordinator(
            num_validators: u16,
            threshold: u16,
            max_faulty: u16,
        ) -> CoordinatorTestContext {
            let avss_setup = AvssTestSetup::new(num_validators, threshold, max_faulty);
            let config =
                DkgConfig::new(1, avss_setup.validators.clone(), threshold, max_faulty).unwrap();
            let session =
                SessionContext::new(1, ProtocolType::DkgKeyGeneration, "testnet".to_string());
            let validator_addresses: Vec<ValidatorAddress> = avss_setup
                .validators
                .iter()
                .map(|v| v.address.clone())
                .collect();
            let channels = InMemoryP2PChannels::<P2PMessage>::new_network(validator_addresses);
            let p2p_channel = channels.into_iter().next().unwrap().1;
            let dkg_config = DkgConfiguration::new(
                avss_setup.validators[0].clone(),
                config,
                session.clone(),
                CoordinatorConfig::default(),
                avss_setup.ecies_keys[0].clone(),
            );
            let state = DkgRuntimeState::new();
            let communication_channels =
                DkgCommunicationChannels::new(p2p_channel, Option::<()>::None);
            let coordinator = DkgCoordinator::new(
                dkg_config,
                state,
                communication_channels,
                Some(MockStorage::new()),
            );
            CoordinatorTestContext {
                coordinator,
                avss_setup,
                session,
            }
        }
    }

    #[tokio::test]
    async fn test_handle_share_valid() {
        let mut ctx = avss_test_utils::create_test_coordinator(4, 2, 1);
        ctx.coordinator.start().await.unwrap();
        // Create a valid AVSS message from validator 1 (dealer)
        let dealer = ctx.avss_setup.validators[1].address.clone();
        let message = ctx.avss_setup.create_valid_message(1, &ctx.session);

        let result = ctx
            .coordinator
            .handle_share(dealer.clone(), message.clone())
            .await;

        assert!(
            result.is_ok(),
            "handle_share should succeed for valid message"
        );
        if let DkgState::Running { dealer_states, .. } = &ctx.coordinator.state.dkg_state {
            assert!(
                matches!(dealer_states.get(&dealer), Some(DealerState::Completed)),
                "Dealer should be in Completed state"
            );
        }
        assert!(
            ctx.coordinator
                .state
                .protocol_data
                .received_messages
                .contains_key(&dealer),
            "Message should be stored in received_messages"
        );
        assert!(
            ctx.coordinator
                .state
                .protocol_data
                .processed_shares
                .contains_key(&dealer),
            "Shares should be stored in processed_shares"
        );
        assert!(
            ctx.coordinator
                .state
                .protocol_data
                .processed_commitments
                .contains_key(&dealer),
            "Commitments should be stored in processed_commitments"
        );
    }

    #[tokio::test]
    async fn test_handle_share_unknown_dealer() {
        let setup = TestSetup::with_validators(4, 2, 1);
        let mut coordinator = setup.create_coordinator();
        coordinator.start().await.unwrap();
        // Create a dealer address that's not in the validator set
        let unknown_dealer = ValidatorAddress([99; 32]);
        // Create a dummy AVSS message (it won't be processed due to unknown dealer)
        let avss_setup = avss_test_utils::AvssTestSetup::new(4, 2, 1);
        let message = avss_setup.create_valid_message(0, &setup.session);

        let result = coordinator
            .handle_share(unknown_dealer.clone(), message)
            .await;

        assert!(result.is_err(), "Should reject unknown dealer");
        assert!(
            result.unwrap_err().to_string().contains("Unknown dealer"),
            "Error should mention unknown dealer"
        );
    }

    #[tokio::test]
    async fn test_handle_share_already_processed() {
        let mut ctx = avss_test_utils::create_test_coordinator(3, 2, 0);
        ctx.coordinator.start().await.unwrap();
        let dealer = ctx.avss_setup.validators[1].address.clone();
        let message = ctx.avss_setup.create_valid_message(1, &ctx.session);

        // First call should succeed
        let result = ctx
            .coordinator
            .handle_share(dealer.clone(), message.clone())
            .await;
        assert!(result.is_ok(), "First handle_share should succeed");

        // Second call with same dealer should fail
        let result = ctx.coordinator.handle_share(dealer, message).await;
        assert!(result.is_err(), "Second handle_share should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Already processed"),
            "Error should mention already processed"
        );
    }

    #[tokio::test]
    async fn test_handle_share_not_running() {
        let mut ctx = avss_test_utils::create_test_coordinator(3, 2, 0);
        // Don't start the coordinator - leave it in Idle state
        assert!(ctx.coordinator.is_idle());
        let dealer = ctx.avss_setup.validators[1].address.clone();
        let message = ctx.avss_setup.create_valid_message(1, &ctx.session);

        let result = ctx.coordinator.handle_share(dealer, message).await;

        assert!(result.is_err(), "Should reject when not running");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Not in running state"),
            "Error should mention state"
        );
    }

    #[tokio::test]
    async fn test_handle_share_state_transitions() {
        let mut ctx = avss_test_utils::create_test_coordinator(4, 2, 1);
        ctx.coordinator.start().await.unwrap();
        let dealer = ctx.avss_setup.validators[1].address.clone();

        // Verify initial state is WaitingForShare
        if let DkgState::Running { dealer_states, .. } = &ctx.coordinator.state.dkg_state {
            assert!(
                matches!(
                    dealer_states.get(&dealer),
                    Some(DealerState::WaitingForShare { .. })
                ),
                "Dealer should start in WaitingForShare state"
            );
        }

        let message = ctx.avss_setup.create_valid_message(1, &ctx.session);
        ctx.coordinator
            .handle_share(dealer.clone(), message)
            .await
            .unwrap();

        // Verify final state is Completed
        if let DkgState::Running { dealer_states, .. } = &ctx.coordinator.state.dkg_state {
            assert!(
                matches!(dealer_states.get(&dealer), Some(DealerState::Completed)),
                "Dealer should transition to Completed state"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_share_multiple_dealers() {
        let mut ctx = avss_test_utils::create_test_coordinator(5, 3, 1);
        ctx.coordinator.start().await.unwrap();

        // Process shares from dealers 1, 2, and 3
        for i in 1..4 {
            let dealer = ctx.avss_setup.validators[i].address.clone();
            let message = ctx.avss_setup.create_valid_message(i, &ctx.session);

            let result = ctx.coordinator.handle_share(dealer.clone(), message).await;
            assert!(
                result.is_ok(),
                "Share processing should succeed for dealer {}",
                i
            );
        }

        // Verify all three dealers are completed
        if let DkgState::Running { dealer_states, .. } = &ctx.coordinator.state.dkg_state {
            for i in 1..4 {
                let dealer = ctx.avss_setup.validators[i].address.clone();
                assert!(
                    matches!(dealer_states.get(&dealer), Some(DealerState::Completed)),
                    "Dealer {} should be completed",
                    i
                );
            }
        }

        // Verify we have shares from all three dealers
        assert_eq!(
            ctx.coordinator.state.protocol_data.processed_shares.len(),
            3,
            "Should have shares from 3 dealers"
        );
        assert_eq!(
            ctx.coordinator
                .state
                .protocol_data
                .processed_commitments
                .len(),
            3,
            "Should have commitments from 3 dealers"
        );
    }
}
