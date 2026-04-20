// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::communication::ChannelError;
use crate::communication::ChannelResult;
use crate::communication::P2PChannel;
use crate::grpc::Client;
use crate::metrics::Metrics;
use crate::mpc::types::ComplainRequest;
use crate::mpc::types::ComplaintResponses;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::GetPublicMpcOutputRequest;
use crate::mpc::types::GetPublicMpcOutputResponse;
use crate::mpc::types::RetrieveMessagesRequest;
use crate::mpc::types::RetrieveMessagesResponse;
use crate::mpc::types::SendMessagesRequest;
use crate::mpc::types::SendMessagesResponse;
use crate::onchain::OnchainState;
use async_trait::async_trait;
use sui_sdk_types::Address;

pub struct RpcP2PChannel {
    onchain_state: OnchainState,
    epoch: u64,
    _metrics: Arc<Metrics>,
    protocol_label: &'static str,
}

impl RpcP2PChannel {
    pub fn new(
        onchain_state: OnchainState,
        epoch: u64,
        protocol_label: &'static str,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            onchain_state,
            epoch,
            _metrics: metrics,
            protocol_label,
        }
    }

    fn get_client(&self, address: &Address) -> ChannelResult<Client> {
        self.onchain_state
            .state()
            .hashi()
            .committees
            .client(address)
            .ok_or(ChannelError::ClientNotFound(*address))
    }
}

#[async_trait]
impl P2PChannel for RpcP2PChannel {
    async fn send_messages(
        &self,
        recipient: &Address,
        request: &SendMessagesRequest,
    ) -> ChannelResult<SendMessagesResponse> {
        let _ = self.protocol_label;
        self.get_client(recipient)?
            .send_messages(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn retrieve_messages(
        &self,
        party: &Address,
        request: &RetrieveMessagesRequest,
    ) -> ChannelResult<RetrieveMessagesResponse> {
        self.get_client(party)?
            .retrieve_messages(request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplaintResponses> {
        self.get_client(party)?
            .complain(request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn get_public_mpc_output(
        &self,
        party: &Address,
        request: &GetPublicMpcOutputRequest,
    ) -> ChannelResult<GetPublicMpcOutputResponse> {
        self.get_client(party)?
            .get_public_mpc_output(request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn get_partial_signatures(
        &self,
        party: &Address,
        request: &GetPartialSignaturesRequest,
    ) -> ChannelResult<GetPartialSignaturesResponse> {
        self.get_client(party)?
            .get_partial_signatures(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }
}
