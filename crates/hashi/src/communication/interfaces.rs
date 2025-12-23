//! Communication channel interfaces

use crate::dkg::ComplainRequest;
use crate::dkg::ComplainResponse;
use crate::dkg::RetrieveMessageRequest;
use crate::dkg::RetrieveMessageResponse;
use crate::dkg::RetrieveRotationMessagesRequest;
use crate::dkg::RetrieveRotationMessagesResponse;
use crate::dkg::SendMessageRequest;
use crate::dkg::SendMessageResponse;
use crate::dkg::SendRotationMessagesRequest;
use crate::dkg::SendRotationMessagesResponse;
use async_trait::async_trait;
use std::time::Duration;
use sui_sdk_types::Address;
use thiserror::Error;

/// Result type for channel operations
pub type ChannelResult<T> = Result<T, ChannelError>;

/// Error type for channel operations
#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Receive timeout")]
    Timeout,

    #[error("Channel closed")]
    Closed,

    #[error("Channel error: {0}")]
    Other(String),
}

/// Point-to-point channel for direct validator-to-validator messaging
#[async_trait]
pub trait P2PChannel: Send + Sync {
    async fn send_dkg_message(
        &self,
        recipient: &Address,
        request: &SendMessageRequest,
    ) -> ChannelResult<SendMessageResponse>;

    async fn retrieve_message(
        &self,
        party: &Address,
        request: &RetrieveMessageRequest,
    ) -> ChannelResult<RetrieveMessageResponse>;

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplainResponse>;

    async fn send_rotation_messages(
        &self,
        recipient: &Address,
        request: &SendRotationMessagesRequest,
    ) -> ChannelResult<SendRotationMessagesResponse>;

    async fn retrieve_rotation_messages(
        &self,
        party: &Address,
        request: &RetrieveRotationMessagesRequest,
    ) -> ChannelResult<RetrieveRotationMessagesResponse>;
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

    /// The total weight of certificates already available on the channel
    fn existing_certificate_weight(&self) -> u32 {
        0
    }
}
