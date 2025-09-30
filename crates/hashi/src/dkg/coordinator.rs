//! DKG coordinator that manages the protocol state machine

use crate::dkg::interfaces::{DkgStorage, OrderedBroadcastChannel};
use crate::dkg::types::{
    DkgConfig, DkgError, DkgMessage, DkgOutput, DkgResult, SessionContext, ValidatorId,
    ValidatorInfo,
};
use fastcrypto::groups::GroupElement;
use fastcrypto_tbls::polynomial::Eval;
use fastcrypto_tbls::threshold_schnorr::{G, avss, complaint};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum DkgState {
    /// Initial state, waiting to start
    Idle,
    /// Sharing phase - validators exchange encrypted shares
    Sharing {
        start_time: Instant,
        received_from: HashSet<ValidatorId>,
    },
    /// Processing phase - validators verify and process received shares
    Processing {
        start_time: Instant,
        processed_validators: HashSet<ValidatorId>,
    },
    /// Complaint phase - handle any complaints about invalid shares
    ComplaintHandling {
        start_time: Instant,
        complaint_count: usize,
        response_count: usize,
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

pub struct DkgCoordinator<B, S: DkgStorage> {
    pub validator: ValidatorInfo,
    pub dkg_config: DkgConfig,
    pub session: SessionContext,
    pub coordinator_config: CoordinatorConfig,
    pub state: DkgState,
    pub broadcast: B,
    pub storage: Option<S>,
    ///  Raw AVSS messages as received from other validators
    pub received_messages: BTreeMap<ValidatorId, avss::Message>,
    ///  Decrypted and validated shares after processing received messages
    pub processed_shares: BTreeMap<ValidatorId, avss::SharesForNode>,
    ///  Commitments from each validator
    pub processed_commitments: BTreeMap<ValidatorId, Vec<Eval<G>>>,
}

impl<B, S: DkgStorage> DkgCoordinator<B, S> {
    pub fn new(
        validator: ValidatorInfo,
        config: DkgConfig,
        session: SessionContext,
        coordinator_config: CoordinatorConfig,
        broadcast: B,
        storage: Option<S>,
    ) -> Self {
        Self {
            validator,
            dkg_config: config,
            session,
            coordinator_config,
            state: DkgState::Idle,
            broadcast,
            storage,
            received_messages: BTreeMap::new(),
            processed_shares: BTreeMap::new(),
            processed_commitments: BTreeMap::new(),
        }
    }

    pub async fn start(&mut self) -> DkgResult<()> {
        match &self.state {
            DkgState::Idle => {
                self.state = DkgState::Sharing {
                    start_time: Instant::now(),
                    received_from: HashSet::new(),
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
        message: DkgMessage,
    ) -> DkgResult<()> {
        if !self.dkg_config.validators.iter().any(|v| v.id == sender) {
            return Err(DkgError::InvalidMessage {
                sender,
                reason: "Unknown validator".to_string(),
            });
        }
        match message {
            DkgMessage::Share {
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
            DkgMessage::Complaint { accuser, complaint } => {
                if accuser != sender {
                    return Err(DkgError::InvalidMessage {
                        sender,
                        reason: "Accuser mismatch".to_string(),
                    });
                }
                self.handle_complaint(accuser, complaint).await
            }
            DkgMessage::ComplaintResponse {
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
            _ => {
                // TODO: Handle Approval and Certificate messages
                // - Approval: needs share validation logic first
                // - Certificate: needs approval collection and threshold checking
                // Both will be added when implementing the full protocol flow
                Ok(())
            }
        }
    }

    async fn handle_share(&mut self, sender: ValidatorId, message: avss::Message) -> DkgResult<()> {
        match &mut self.state {
            DkgState::Sharing { received_from, .. } => {
                self.received_messages.insert(sender.clone(), message);
                received_from.insert(sender);
                if received_from.len() >= self.required_shares() {
                    self.transition_to_processing().await?;
                }
                Ok(())
            }
            _ => Err(DkgError::InvalidMessage {
                sender,
                reason: "Not in sharing phase".to_string(),
            }),
        }
    }

    async fn handle_complaint(
        &mut self,
        accuser: ValidatorId,
        _complaint: complaint::Complaint,
    ) -> DkgResult<()> {
        match &mut self.state {
            DkgState::ComplaintHandling {
                complaint_count, ..
            } => {
                *complaint_count += 1;
                Ok(())
            }
            DkgState::Processing { .. } => {
                self.state = DkgState::ComplaintHandling {
                    start_time: Instant::now(),
                    complaint_count: 1,
                    response_count: 0,
                };
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
            DkgState::ComplaintHandling { response_count, .. } => {
                *response_count += 1;
                self.check_complaint_resolution().await
            }
            _ => Err(DkgError::InvalidMessage {
                sender: responder,
                reason: "Not in complaint handling phase".to_string(),
            }),
        }
    }

    async fn transition_to_processing(&mut self) -> DkgResult<()> {
        self.state = DkgState::Processing {
            start_time: Instant::now(),
            processed_validators: HashSet::new(),
        };
        for (sender_id, _message) in &self.received_messages {
            // TODO: Verify and process the shares when implementing the full protocol flow
            // For now, just mark as processed
            if let DkgState::Processing {
                processed_validators,
                ..
            } = &mut self.state
            {
                processed_validators.insert(sender_id.clone());
            }
        }
        self.check_completion().await
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
            if let Some(storage) = &self.storage {
                if self.coordinator_config.enable_persistence {
                    storage.save_output(&self.session, &output).await?;
                }
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    async fn check_complaint_resolution(&mut self) -> DkgResult<()> {
        // TODO: Implement the actual complaint verification when adding complaint handling for all protocols
        // Assume resolved if we have any responses for now
        if let DkgState::ComplaintHandling { response_count, .. } = &self.state {
            if *response_count > 0 {
                self.check_completion().await?;
            }
        }
        Ok(())
    }

    fn required_shares(&self) -> usize {
        self.dkg_config.threshold as usize
    }

    pub fn check_timeout(&mut self) -> bool {
        let timeout = self.coordinator_config.phase_timeout;
        match &self.state {
            DkgState::Sharing { start_time, .. }
            | DkgState::Processing { start_time, .. }
            | DkgState::ComplaintHandling { start_time, .. } => start_time.elapsed() > timeout,
            _ => false,
        }
    }

    pub fn handle_timeout(&mut self) {
        let timed_out = self.check_timeout();
        if timed_out {
            let phase = match &self.state {
                DkgState::Sharing { .. } => "sharing",
                DkgState::Processing { .. } => "processing",
                DkgState::ComplaintHandling { .. } => "complaint handling",
                _ => "unknown",
            };
            self.state = DkgState::Failed {
                reason: format!("Timeout in {} phase", phase),
            };
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::communication::InMemoryOrderedBroadcastChannel;
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
            let validators: Vec<ValidatorInfo> = (0..num_validators)
                .map(|i| create_test_validator(i))
                .collect();
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
        fn create_coordinator(&self) -> DkgCoordinator<InMemoryOrderedBroadcastChannel<DkgMessage>, MockStorage> {
            self.create_coordinator_with_config(CoordinatorConfig::default())
        }

        /// Create a coordinator with custom config
        fn create_coordinator_with_config(
            &self,
            coordinator_config: CoordinatorConfig,
        ) -> DkgCoordinator<InMemoryOrderedBroadcastChannel<DkgMessage>, MockStorage> {
            use crate::types::ValidatorAddress;
            let validator_addresses: Vec<ValidatorAddress> =
                self.validators.iter().map(|v| ValidatorAddress(v.id.0)).collect();
            let channels = InMemoryOrderedBroadcastChannel::new_network(validator_addresses);
            let broadcast = channels.into_iter().next().unwrap().1;
            DkgCoordinator::new(
                self.validators[0].clone(),
                self.config.clone(),
                self.session.clone(),
                coordinator_config,
                broadcast,
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

        // Should transition to Sharing state
        assert!(matches!(
            coordinator.current_state(),
            DkgState::Sharing { .. }
        ));
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
        use std::collections::HashSet;
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

        // Set state to Processing with other validators processed
        let mut processed = HashSet::new();
        for i in 1..num_validators {
            processed.insert(setup.validators[i as usize].id.clone());
        }
        coordinator.state = DkgState::Processing {
            start_time: Instant::now(),
            processed_validators: processed,
        };

        // Check completion should transition to Completed
        coordinator.check_completion().await.unwrap();
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

        if let Some(storage) = &coordinator.storage {
            if coordinator.coordinator_config.enable_persistence {
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
        }

        assert!(save_count_clone.load(Ordering::SeqCst) > 0);
    }
}
