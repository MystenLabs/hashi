// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::proto_conversions::partial_sigs_response_limit;
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
use hashi_types::proto;
use sui_sdk_types::Address;
use tonic::metadata::MetadataValue;

pub struct RpcP2PChannel {
    onchain_state: OnchainState,
    epoch: u64,
    protocol_label: &'static str,
    max_owned_shares: Option<usize>,
}

impl RpcP2PChannel {
    pub fn new(onchain_state: OnchainState, epoch: u64, protocol_label: &'static str) -> Self {
        Self {
            onchain_state,
            epoch,
            protocol_label,
            max_owned_shares: None,
        }
    }

    pub fn with_max_owned_shares(mut self, shares: usize) -> Self {
        self.max_owned_shares = Some(shares);
        self
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

fn reject_over_answer(
    party: &Address,
    requested: usize,
    response: &proto::GetPartialSignaturesResponse,
) -> ChannelResult<()> {
    if response.partial_sigs.len() > requested || response.signing_nonces.len() > requested {
        return Err(ChannelError::RequestFailed(format!(
            "{party} answered {requested} requested id(s) with {} partial-signature and {} nonce \
             entries",
            response.partial_sigs.len(),
            response.signing_nonces.len(),
        )));
    }
    Ok(())
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
        let mut client = self.get_client(party)?;
        if let Some(max_owned) = self.max_owned_shares {
            client = client.tighten_max_decoding_message_size(partial_sigs_response_limit(
                request.signing_ids.len(),
                max_owned,
            ));
        }
        let proto_request = self.build_request(request.to_proto(self.epoch));
        let response = client
            .mpc_service_client()
            .get_partial_signatures(proto_request)
            .await
            .map_err(map_status)?;
        let response = response.get_ref();
        reject_over_answer(party, request.signing_ids.len(), response)?;
        GetPartialSignaturesResponse::try_from(response)
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(sigs: usize, nonces: usize) -> proto::GetPartialSignaturesResponse {
        let entries = |n: usize| {
            (0..n)
                .map(|i| (format!("0x{i:064x}"), Default::default()))
                .collect()
        };
        proto::GetPartialSignaturesResponse {
            partial_sigs: entries(sigs),
            signing_nonces: entries(nonces),
        }
    }

    #[test]
    fn over_answering_a_poll_is_refused_before_its_payloads_are_deserialized() {
        let party = Address::new([9u8; 32]);
        assert!(reject_over_answer(&party, 2, &response(2, 2)).is_ok());
        assert!(reject_over_answer(&party, 2, &response(1, 0)).is_ok());
        assert!(reject_over_answer(&party, 2, &response(3, 2)).is_err());
        assert!(reject_over_answer(&party, 2, &response(2, 3)).is_err());
    }

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
