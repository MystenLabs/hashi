use crate::communication::ChannelError;
use crate::communication::ChannelResult;
use crate::communication::P2PChannel;
use crate::grpc::Client;
use crate::mpc::types::ComplainRequest;
use crate::mpc::types::ComplaintResponses;
use crate::mpc::types::GetPartialSignaturesRequest;
use crate::mpc::types::GetPartialSignaturesResponse;
use crate::mpc::types::GetPublicDkgOutputRequest;
use crate::mpc::types::GetPublicDkgOutputResponse;
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
}

impl RpcP2PChannel {
    pub fn new(onchain_state: OnchainState, epoch: u64) -> Self {
        Self {
            onchain_state,
            epoch,
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
            .retrieve_messages(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplaintResponses> {
        self.get_client(party)?
            .complain(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn get_public_dkg_output(
        &self,
        party: &Address,
        request: &GetPublicDkgOutputRequest,
    ) -> ChannelResult<GetPublicDkgOutputResponse> {
        self.get_client(party)?
            .get_public_dkg_output(request)
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
