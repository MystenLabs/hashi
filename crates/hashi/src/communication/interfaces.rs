//! Generic communication channel interfaces

use crate::communication::error::ChannelResult;
use crate::types::ValidatorAddress;
use async_trait::async_trait;
use std::time::Duration;

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

    /// Receive the next available message from any validator
    async fn receive(&mut self) -> ChannelResult<M>;

    /// Try to receive a message with a timeout
    async fn try_receive_timeout(&mut self, timeout: Duration) -> ChannelResult<Option<M>>;

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
    async fn broadcast(&self, message: M) -> ChannelResult<()>;

    /// Receive the next message in the total order
    async fn receive(&mut self) -> ChannelResult<M>;

    /// Try to receive a message with a timeout
    async fn try_receive_timeout(&mut self, timeout: Duration) -> ChannelResult<Option<M>>;

    /// Get the number of pending messages in the queue, if available
    fn pending_messages(&self) -> Option<usize> {
        None
    }
}
