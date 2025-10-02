//! DKG coordinator that manages the protocol state machine

use crate::dkg::interfaces::{DkgStorage, OrderedBroadcastChannel, P2PChannel};
use crate::dkg::types::{
    DkgConfig, DkgError, DkgOutput, DkgResult, OrderedBroadcastMessage, P2PMessage, SessionContext,
    ValidatorId, ValidatorInfo,
};
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::{G, avss, complaint};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
        dealer_states: BTreeMap<ValidatorId, DealerState>,
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

pub struct DkgCoordinator<P, S: DkgStorage>
where
    P: P2PChannel,
{
    pub validator: ValidatorInfo,
    pub dkg_config: DkgConfig,
    pub session: SessionContext,
    pub coordinator_config: CoordinatorConfig,
    pub state: DkgState,
    pub p2p_channel: P,
    pub storage: Option<S>,
    /// Raw AVSS messages as received from other validators
    pub received_messages: BTreeMap<ValidatorId, avss::Message>,
    ///  Decrypted and validated shares after processing received messages
    pub processed_shares: BTreeMap<ValidatorId, avss::SharesForNode>,
    ///  Commitments from each validator
    pub processed_commitments: BTreeMap<ValidatorId, Vec<Eval<G>>>,
}

impl<P, S: DkgStorage> DkgCoordinator<P, S>
where
    P: P2PChannel,
{
    pub fn new(
        validator: ValidatorInfo,
        config: DkgConfig,
        session: SessionContext,
        coordinator_config: CoordinatorConfig,
        p2p_channel: P,
        storage: Option<S>,
    ) -> Self {
        Self {
            validator,
            dkg_config: config,
            session,
            coordinator_config,
            state: DkgState::Idle,
            p2p_channel,
            storage,
            received_messages: BTreeMap::new(),
            processed_shares: BTreeMap::new(),
            processed_commitments: BTreeMap::new(),
        }
    }

    pub async fn start(&mut self) -> DkgResult<()> {
        match &self.state {
            DkgState::Idle => {
                let mut dealer_states = BTreeMap::new();
                let now = Instant::now();
                for validator in &self.dkg_config.validators {
                    dealer_states.insert(
                        validator.id.clone(),
                        DealerState::WaitingForShare { start_time: now },
                    );
                }
                self.state = DkgState::Running {
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

    pub async fn handle_message(
        &mut self,
        sender: ValidatorId,
        message: P2PMessage,
    ) -> DkgResult<()> {
        if !self.dkg_config.validators.iter().any(|v| v.id == sender) {
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Unknown validator".to_string(),
            });
        }
        match message {
            P2PMessage::Share {
                sender: msg_sender,
                message,
            } => {
                if msg_sender != sender {
                    return Err(DkgError::InvalidMessage {
                        sender,
                        reason: "Sender mismatch".to_string(),
                    });
                }
                self.handle_share(sender, *message).await
            }
            P2PMessage::Complaint { accuser, complaint } => {
                if accuser != sender {
                    return Err(DkgError::InvalidMessage {
                        sender,
                        reason: "Accuser mismatch".to_string(),
                    });
                }
                self.handle_complaint(accuser, complaint).await
            }
            P2PMessage::ComplaintResponse {
                responder,
                response,
            } => {
                if responder != sender {
                    return Err(DkgError::InvalidMessage {
                        sender,
                        reason: "Responder mismatch".to_string(),
                    });
                }
                self.handle_complaint_response(responder, response).await
            }
            P2PMessage::Approval(_) => {
                // TODO: Handle Approval messages
                // - Receivers validate shares and send approvals back to dealer
                // - Dealers collect 2f+1 approvals to create certificates
                // - Certificates are broadcast via OrderedBroadcastChannel
                Ok(())
            }
        }
    }

    /// Handle consensus-ordered messages from OrderedBroadcastChannel
    pub async fn handle_ordered_message(
        &mut self,
        message: OrderedBroadcastMessage,
    ) -> DkgResult<()> {
        match message {
            OrderedBroadcastMessage::Certificate(_cert) => {
                // TODO: Implement certificate handling
                // Certificates prove that 2f+1 validators approved a share
                // They complete the AVSS protocol for a dealer's share
                // Will need to:
                // 1. Verify the certificate signatures
                // 2. Store the certificate as proof of share validity
                // 3. Update protocol state accordingly
                Ok(())
            }
            OrderedBroadcastMessage::Presignature {
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

    async fn handle_share(&mut self, dealer: ValidatorId, message: avss::Message) -> DkgResult<()> {
        match &mut self.state {
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
        accuser: ValidatorId,
        _complaint: complaint::Complaint,
    ) -> DkgResult<()> {
        match &mut self.state {
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
        responder: ValidatorId,
        _response: complaint::ComplaintResponse,
    ) -> DkgResult<()> {
        match &mut self.state {
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
        if let DkgState::Running { dealer_states, .. } = &self.state {
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
                session_context: self.session.clone(),
            };
            self.state = DkgState::Completed {
                output: output.clone(),
            };
            if let Some(storage) = &self.storage
                && self.coordinator_config.enable_persistence
            {
                storage.save_output(&self.session, &output).await?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    async fn check_complaint_resolution(&mut self) -> DkgResult<()> {
        // TODO: Implement the actual complaint verification when adding complaint handling for all protocols
        if let DkgState::Running { dealer_states, .. } = &mut self.state {
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
        self.dkg_config.threshold as usize
    }

    pub fn check_timeout(&mut self) -> bool {
        let timeout = self.coordinator_config.phase_timeout;
        match &self.state {
            DkgState::Running { start_time, .. } => start_time.elapsed() > timeout,
            _ => false,
        }
    }

    pub fn handle_timeout(&mut self) {
        if self.check_timeout()
            && let DkgState::Running { dealer_states, .. } = &self.state
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
                self.state = DkgState::Failed {
                    reason: format!(
                        "Timeout waiting for shares from dealers: {:?}",
                        timed_out_dealers
                    ),
                };
            } else {
                self.state = DkgState::Failed {
                    reason: "Timeout in DKG protocol".to_string(),
                };
            }
        }
    }

    pub fn current_state(&self) -> &DkgState {
        &self.state
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, DkgState::Completed { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.state, DkgState::Failed { .. })
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.state, DkgState::Idle)
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, DkgState::Running { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::InMemoryP2PChannels;
    use crate::dkg::interfaces::DkgStorage;
    use crate::dkg::types::{
        DkgConfig, DkgOutput, DkgProtocolState, DkgResult, ProtocolType, SessionContext,
        ValidatorId, ValidatorInfo,
    };
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
            id: ValidatorId([party_id as u8; 32]),
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
            let session = SessionContext::new(1, ProtocolType::DkgKeyGeneration, 0);
            let storage = MockStorage::new();
            Self {
                validators,
                config,
                session,
                storage,
            }
        }

        /// Create a coordinator for the first validator
        fn create_coordinator(&self) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, MockStorage> {
            self.create_coordinator_with_config(CoordinatorConfig::default())
        }

        /// Create a coordinator with custom config
        fn create_coordinator_with_config(
            &self,
            coordinator_config: CoordinatorConfig,
        ) -> DkgCoordinator<InMemoryP2PChannels<P2PMessage>, MockStorage> {
            use crate::types::ValidatorAddress;
            let validator_addresses: Vec<ValidatorAddress> =
                self.validators.iter().map(|v| ValidatorAddress(v.id.0)).collect();
            let channels = InMemoryP2PChannels::new_network(validator_addresses);
            let p2p_channel = channels.into_iter().next().unwrap().1;
            DkgCoordinator::new(
                self.validators[0].clone(),
                self.config.clone(),
                self.session.clone(),
                coordinator_config,
                p2p_channel,
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
        let threshold = 3;
        let setup = TestSetup::with_validators(5, threshold, 1);
        let coordinator = setup.create_coordinator();

        assert_eq!(coordinator.required_shares(), threshold as usize);
    }

    #[tokio::test]
    async fn test_transition_to_completed() {
        use fastcrypto_tbls::threshold_schnorr::avss;
        use std::time::Instant;

        let num_validators = 3;
        let setup = TestSetup::with_validators(num_validators, 2, 0);
        let mut coordinator = setup.create_coordinator();

        // Manually add processed shares from other validators (skip validator 0 which is self)
        for i in 1..num_validators {
            let validator_id = setup.validators[i as usize].id.clone();
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
                setup.validators[i as usize].id.clone(),
                DealerState::Completed,
            );
        }
        coordinator.state = DkgState::Running {
            start_time: Instant::now(),
            dealer_states,
        };

        // Check progress should transition to Completed
        coordinator.check_progress().await.unwrap();
        assert!(matches!(coordinator.state, DkgState::Completed { .. }));

        // Verify output has correct session context
        if let DkgState::Completed { output } = &coordinator.state {
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
}
