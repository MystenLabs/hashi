use crate::communication::ChannelError;
use crate::communication::ChannelResult;
use crate::communication::P2PChannel;
use crate::dkg::types::ComplainRequest;
use crate::dkg::types::ComplainResponse;
use crate::dkg::types::GetPublicDkgOutputRequest;
use crate::dkg::types::GetPublicDkgOutputResponse;
use crate::dkg::types::RetrieveMessageRequest;
use crate::dkg::types::RetrieveMessageResponse;
use crate::dkg::types::RetrieveRotationMessagesRequest;
use crate::dkg::types::RetrieveRotationMessagesResponse;
use crate::dkg::types::RotationComplainRequest;
use crate::dkg::types::RotationComplainResponse;
use crate::dkg::types::SendMessageRequest;
use crate::dkg::types::SendMessageResponse;
use crate::dkg::types::SendRotationMessagesRequest;
use crate::dkg::types::SendRotationMessagesResponse;
use crate::grpc::Client;
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
    async fn send_dkg_message(
        &self,
        recipient: &Address,
        request: &SendMessageRequest,
    ) -> ChannelResult<SendMessageResponse> {
        self.get_client(recipient)?
            .send_message(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn retrieve_message(
        &self,
        party: &Address,
        request: &RetrieveMessageRequest,
    ) -> ChannelResult<RetrieveMessageResponse> {
        self.get_client(party)?
            .retrieve_message(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn complain(
        &self,
        party: &Address,
        request: &ComplainRequest,
    ) -> ChannelResult<ComplainResponse> {
        self.get_client(party)?
            .complain(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn send_rotation_messages(
        &self,
        recipient: &Address,
        request: &SendRotationMessagesRequest,
    ) -> ChannelResult<SendRotationMessagesResponse> {
        self.get_client(recipient)?
            .send_rotation_messages(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }

    async fn retrieve_rotation_messages(
        &self,
        party: &Address,
        request: &RetrieveRotationMessagesRequest,
    ) -> ChannelResult<RetrieveRotationMessagesResponse> {
        self.get_client(party)?
            .retrieve_rotation_messages(self.epoch, request)
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

    async fn rotation_complain(
        &self,
        party: &Address,
        request: &RotationComplainRequest,
    ) -> ChannelResult<RotationComplainResponse> {
        self.get_client(party)?
            .rotation_complain(self.epoch, request)
            .await
            .map_err(|e| ChannelError::RequestFailed(e.to_string()))
    }
}
