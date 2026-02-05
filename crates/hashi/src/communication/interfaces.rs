//! Communication channel interfaces

use crate::mpc::ComplainRequest;
use crate::mpc::ComplaintResponses;
use crate::mpc::GetPublicDkgOutputRequest;
use crate::mpc::GetPublicDkgOutputResponse;
use crate::mpc::RetrieveMessagesRequest;
use crate::mpc::RetrieveMessagesResponse;
use crate::mpc::SendMessagesRequest;
use crate::mpc::SendMessagesResponse;
use async_trait::async_trait;
use sui_sdk_types::Address;
use thiserror::Error;

/// Result type for channel operations
pub type ChannelResult<T> = Result<T, ChannelError>;

/// Error type for channel operations
#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Client not found for address {0}")]
    ClientNotFound(Address),

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
    async fn send_messages(
        &self,
        recipient: &Address,
        request: &SendMessagesRequest,
    ) -> ChannelResult<SendMessagesResponse>;

    async fn retrieve_messages(
        &self,
        party: &Address,
        request: &RetrieveMessagesRequest,
    ) -> ChannelResult<RetrieveMessagesResponse>;

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplaintResponses>;

    async fn get_public_dkg_output(
        &self,
        party: &Address,
        request: &GetPublicDkgOutputRequest,
    ) -> ChannelResult<GetPublicDkgOutputResponse>;
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

    /// The total weight of certificates already available on the channel
    fn existing_certificate_weight(&self) -> u32 {
        0
    }
}
