// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::communication::ChannelError;
use crate::communication::ChannelResult;
use crate::communication::P2PChannel;
use crate::grpc::Client;
use crate::grpc::MPC_PROTOCOL_METADATA_KEY;
use crate::mpc::types::ComplainRequest;
use crate::mpc::types::ComplaintResponse;
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
use tonic::metadata::MetadataValue;

pub struct RpcP2PChannel {
    onchain_state: OnchainState,
    epoch: u64,
    protocol_label: &'static str,
}

impl RpcP2PChannel {
    pub fn new(onchain_state: OnchainState, epoch: u64, protocol_label: &'static str) -> Self {
        Self {
            onchain_state,
            epoch,
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

    /// Wrap a protobuf message in a `tonic::Request` tagged with the MPC
    /// protocol label, so the server-side metrics layer can attribute
    /// traffic to the originating protocol.
    fn build_request<T>(&self, message: T) -> tonic::Request<T> {
        let mut req = tonic::Request::new(message);
        req.metadata_mut().insert(
            MPC_PROTOCOL_METADATA_KEY,
            MetadataValue::from_static(self.protocol_label),
        );
        req
    }
}

fn map_status(status: tonic::Status) -> ChannelError {
    if status.code() == tonic::Code::Unavailable
        && status
            .message()
            .contains(crate::grpc::SIGNING_MANAGER_NOT_READY_MSG)
    {
        ChannelError::NotReady(status.to_string())
    } else {
        ChannelError::RequestFailed(status.to_string())
    }
}

#[async_trait]
impl P2PChannel for RpcP2PChannel {
    async fn send_messages(
        &self,
        recipient: &Address,
        request: &SendMessagesRequest,
    ) -> ChannelResult<SendMessagesResponse> {
        let client = self.get_client(recipient)?;
        let proto_request = self.build_request(request.to_proto(self.epoch));
        let response = client
            .mpc_service_client()
            .send_messages(proto_request)
            .await
            .map_err(map_status)?;
        SendMessagesResponse::try_from(response.get_ref())
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn retrieve_messages(
        &self,
        party: &Address,
        request: &RetrieveMessagesRequest,
    ) -> ChannelResult<RetrieveMessagesResponse> {
        let client = self.get_client(party)?;
        let proto_request = self.build_request(request.to_proto());
        let response = client
            .mpc_service_client()
            .retrieve_messages(proto_request)
            .await
            .map_err(map_status)?;
        RetrieveMessagesResponse::try_from(response.get_ref())
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplaintResponse> {
        let client = self.get_client(party)?;
        let proto_request = self.build_request(request.to_proto());
        let response = client
            .mpc_service_client()
            .complain(proto_request)
            .await
            .map_err(map_status)?;
        ComplaintResponse::try_from(response.get_ref())
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn get_public_mpc_output(
        &self,
        party: &Address,
        request: &GetPublicMpcOutputRequest,
    ) -> ChannelResult<GetPublicMpcOutputResponse> {
        let client = self.get_client(party)?;
        let proto_request = self.build_request(request.to_proto());
        let response = client
            .mpc_service_client()
            .get_public_mpc_output(proto_request)
            .await
            .map_err(map_status)?;
        GetPublicMpcOutputResponse::try_from(response.get_ref())
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn get_partial_signatures(
        &self,
        party: &Address,
        request: &GetPartialSignaturesRequest,
    ) -> ChannelResult<GetPartialSignaturesResponse> {
        let client = self.get_client(party)?;
        let proto_request = self.build_request(request.to_proto(self.epoch));
        let response = client
            .mpc_service_client()
            .get_partial_signatures(proto_request)
            .await
            .map_err(map_status)?;
        GetPartialSignaturesResponse::try_from(response.get_ref())
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_status_treats_only_the_not_ready_response_as_not_ready() {
        let not_ready = tonic::Status::unavailable(format!(
            "{} for epoch 7; retry",
            crate::grpc::SIGNING_MANAGER_NOT_READY_MSG
        ));
        assert!(matches!(map_status(not_ready), ChannelError::NotReady(_)));

        let refused = tonic::Status::unavailable("error trying to connect: connection refused");
        assert!(matches!(
            map_status(refused),
            ChannelError::RequestFailed(_)
        ));

        let not_found = tonic::Status::not_found("WithdrawalTransaction not found on-chain");
        assert!(matches!(
            map_status(not_found),
            ChannelError::RequestFailed(_)
        ));
    }
}
