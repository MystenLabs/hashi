//! Generic communication channel interfaces

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

/// An authenticated message with cryptographically verified sender
///
/// The `sender` field is verified by the channel layer. The protocol layer should verify
/// that the authenticated sender matches any sender claims in the message payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedMessage<M> {
    pub sender: ValidatorAddress,
    pub message: M,
}

/// Point-to-point channel for direct validator-to-validator messaging
///
/// This is a generic interface that can work with any message type.
/// Messages are not guaranteed to be delivered in any particular order.
#[async_trait]
pub trait P2PChannel<M>: Send + Sync
where
    M: Clone + Send + Sync + 'static,
{
    /// Send a message to a specific validator
    async fn send_to(&self, recipient: &ValidatorAddress, message: M) -> ChannelResult<()>;

    /// Send the same message to all validators (each receives it as a separate P2P message)
    /// This is NOT consensus-ordered broadcast
    async fn broadcast(&self, message: M) -> ChannelResult<()>;

    /// Receive the next available message with authenticated sender
    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>>;

    /// Try to receive an authenticated message with a timeout
    async fn try_receive_timeout(
        &mut self,
        timeout: Duration,
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>>;

    /// Get the number of pending messages in the queue, if available
    fn pending_messages(&self) -> Option<usize> {
        None
    }
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

    /// Receive the next message in the total order with authenticated sender
    async fn receive(&mut self) -> ChannelResult<AuthenticatedMessage<M>>;

    /// Try to receive an authenticated message with a timeout
    async fn try_receive_timeout(
        &mut self,
        timeout: Duration,
    ) -> ChannelResult<Option<AuthenticatedMessage<M>>>;

    /// Get the number of pending messages in the queue, if available
    fn pending_messages(&self) -> Option<usize> {
        None
    }
}
