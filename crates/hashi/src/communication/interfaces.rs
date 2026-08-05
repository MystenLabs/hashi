// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Communication channel interfaces

use crate::mpc::ComplainRequest;
use crate::mpc::ComplaintResponse;
use crate::mpc::GetPublicMpcOutputRequest;
use crate::mpc::GetPublicMpcOutputResponse;
use crate::mpc::RetrieveMessagesRequest;
use crate::mpc::RetrieveMessagesResponse;
use crate::mpc::SendMessagesRequest;
use crate::mpc::SendMessagesResponse;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
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

    /// The peer explicitly answered that it is up but not ready to serve
    /// yet (e.g. still reconciling its signing manager right after an epoch
    /// change). Distinguished from [`ChannelError::RequestFailed`] so
    /// callers can treat it as "retry shortly" rather than as peer failure.
    /// Deliberately narrow: transport failures that gRPC also reports as
    /// `Unavailable` do NOT map here.
    #[error("Peer not ready: {0}")]
    NotReady(String),

    #[error("Client not found for address {0}")]
    ClientNotFound(Address),

    #[error("Receive timeout")]
    Timeout,

    #[error("Wait superseded: {0}")]
    Superseded(String),

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
    ) -> ChannelResult<ComplaintResponse>;

    async fn get_public_mpc_output(
        &self,
        party: &Address,
        request: &GetPublicMpcOutputRequest,
    ) -> ChannelResult<GetPublicMpcOutputResponse>;

    async fn get_partial_signatures(
        &self,
        party: &Address,
        request: &GetPartialSignaturesRequest,
    ) -> ChannelResult<GetPartialSignaturesResponse>;
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// This call's transaction created the entry.
    Landed,
    /// A message with the same hash was already present when this call checked. An earlier
    /// attempt of this same call may have been the one that submitted it.
    AlreadyPresent,
    /// This call created nothing and a re-read did not find our message in the slot: either a
    /// different one from this sender, or nothing at all.
    Diverged,
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
    async fn publish(&self, message: M) -> ChannelResult<PublishOutcome>;

    /// Receive the next message in the total order
    async fn receive(&mut self) -> ChannelResult<M>;

    /// Fetch existing certificates, paired with their dealer. Callers must
    /// verify them before acting on their weight.
    async fn certified_dealers(&mut self) -> Vec<(Address, M)>;
}
