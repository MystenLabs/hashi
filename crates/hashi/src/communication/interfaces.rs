//! Communication channel interfaces

use crate::dkg::{
    RetrieveMessageRequest, RetrieveMessageResponse, SendShareRequest, SendShareResponse,
};
use crate::types::ValidatorAddress;
use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Result type for channel operations
pub type ChannelResult<T> = Result<T, ChannelError>;

/// Error type for channel operations
#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive timeout")]
    Timeout,

    #[error("Channel closed")]
    Closed,

    #[error("Channel error: {0}")]
    Other(String),
}

/// Point-to-point channel for direct validator-to-validator messaging
// TODO: Implement authentication for receiver to verify caller
#[async_trait]
pub trait P2PChannel: Send + Sync {
    async fn send_share(
        &self,
        recipient: &ValidatorAddress,
        request: &SendShareRequest,
    ) -> ChannelResult<SendShareResponse>;

    async fn retrieve_message(
        &self,
        party: &ValidatorAddress,
        request: &RetrieveMessageRequest,
    ) -> ChannelResult<RetrieveMessageResponse>;
}

/// Ordered broadcast channel for consensus-critical messages
///
/// This is a generic interface that provides total ordering guarantees:
/// all validators see messages in the same order.
#[async_trait]
pub trait OrderedBroadcastChannel<M>: Send + Sync
where
    M: Clone + Send + Sync + 'static,
{
    /// Broadcast a message with guaranteed ordering across all validators
    async fn publish(&self, message: M) -> ChannelResult<()>;

    /// Receive the next message in the total order
    async fn receive(&mut self) -> ChannelResult<M>;

    async fn try_receive_timeout(&mut self, timeout: Duration) -> ChannelResult<Option<M>>;

    fn pending_messages(&self) -> Option<usize> {
        None
    }
}
