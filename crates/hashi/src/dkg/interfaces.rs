//! Interfaces for DKG protocol components

use crate::dkg::types::{
    DkgOutput, DkgProtocolState, DkgResult, OrderedBroadcastMessage, P2PMessage, SessionContext,
    ValidatorAddress,
};
use async_trait::async_trait;
use fastcrypto_tbls::threshold_schnorr::avss;

/// Point-to-point channel for direct validator-to-validator messaging
#[async_trait]
pub trait P2PChannel: Send + Sync {
    async fn send_to(&self, recipient: &ValidatorAddress, message: P2PMessage) -> DkgResult<()>;

    /// Send the same message to all validators (each receives it as a separate P2P message)
    /// This is NOT consensus-ordered broadcast
    async fn broadcast(&self, message: P2PMessage) -> DkgResult<()>;

    /// Receive the next available message from any validator
    async fn receive(&mut self) -> DkgResult<P2PMessage>;

    async fn try_receive_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> DkgResult<Option<P2PMessage>>;

    fn pending_messages(&self) -> Option<usize> {
        None
    }
}

/// Ordered broadcast channel for consensus-critical messages
#[async_trait]
pub trait OrderedBroadcastChannel: Send + Sync {
    /// Broadcast a message with guaranteed ordering across all validators
    async fn broadcast(&self, message: OrderedBroadcastMessage) -> DkgResult<()>;

    /// Receive the next message in the total order
    async fn receive(&mut self) -> DkgResult<OrderedBroadcastMessage>;

    async fn try_receive_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> DkgResult<Option<OrderedBroadcastMessage>>;

    fn pending_messages(&self) -> Option<usize> {
        None
    }
}

#[async_trait]
pub trait DkgStorage: Send + Sync {
    async fn save_output(&self, session_id: &SessionContext, output: &DkgOutput) -> DkgResult<()>;

    async fn load_output(&self, session_id: &SessionContext) -> DkgResult<Option<DkgOutput>>;

    async fn save_checkpoint(
        &self,
        session_id: &SessionContext,
        state: &DkgProtocolState,
    ) -> DkgResult<()>;

    async fn load_checkpoint(
        &self,
        session_id: &SessionContext,
    ) -> DkgResult<Option<DkgProtocolState>>;

    async fn list_sessions(&self) -> DkgResult<Vec<SessionContext>>;

    async fn cleanup_session(&self, session_id: &SessionContext) -> DkgResult<()>;
}

pub trait Signer: Send + Sync {
    fn sign(&self, message_hash: &[u8; 32]) -> Vec<u8>;

    fn verify(&self, message_hash: &[u8; 32], signature: &[u8], signer: &ValidatorAddress) -> bool;

    fn validator_address(&self) -> ValidatorAddress;
}

#[async_trait]
pub trait CryptoOperations: Send + Sync {
    async fn create_dealer(
        &self,
        secret: Option<Vec<u8>>,
        session_id: SessionContext,
    ) -> DkgResult<Box<dyn DealerOperations>>;

    async fn create_receiver(
        &self,
        session_id: SessionContext,
    ) -> DkgResult<Box<dyn ReceiverOperations>>;
}

#[async_trait]
pub trait DealerOperations: Send + Sync {
    async fn create_message(&self) -> DkgResult<Vec<u8>>;
}

#[async_trait]
pub trait ReceiverOperations: Send + Sync {
    async fn process_message(&self, message: &[u8]) -> DkgResult<avss::ProcessedMessage>;

    async fn handle_complaint(&self, complaint: &[u8]) -> DkgResult<Vec<u8>>;

    async fn recover(&self, responses: &[Vec<u8>]) -> DkgResult<avss::ReceiverOutput>;
}

pub trait DkgMonitor: Send + Sync {
    fn on_start(&self, session_id: &SessionContext);

    fn on_message_received(&self, from: &ValidatorAddress, message_type: &str);

    fn on_message_sent(&self, message_type: &str);

    fn on_success(&self, session_id: &SessionContext, duration: std::time::Duration);

    fn on_failure(&self, session_id: &SessionContext, error: &str);
}
