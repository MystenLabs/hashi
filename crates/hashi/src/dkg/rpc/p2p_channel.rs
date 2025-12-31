use crate::communication::ChannelError;
use crate::communication::ChannelResult;
use crate::communication::P2PChannel;
use crate::dkg::rpc::DkgRpcClient;
use crate::dkg::types::ComplainRequest;
use crate::dkg::types::ComplainResponse;
use crate::dkg::types::RetrieveMessageRequest;
use crate::dkg::types::RetrieveMessageResponse;
use crate::dkg::types::RetrieveRotationMessagesRequest;
use crate::dkg::types::RetrieveRotationMessagesResponse;
use crate::dkg::types::SendMessageRequest;
use crate::dkg::types::SendMessageResponse;
use crate::dkg::types::SendRotationMessagesRequest;
use crate::dkg::types::SendRotationMessagesResponse;
use async_trait::async_trait;
use std::collections::HashMap;
use sui_sdk_types::Address;

// TODO: Centralize client management in `OnchainState` to handle TLS key/address rotation.
pub struct RpcP2PChannel {
    clients: HashMap<Address, DkgRpcClient>,
    epoch: u64,
}

impl RpcP2PChannel {
    pub fn new(clients: HashMap<Address, DkgRpcClient>, epoch: u64) -> Self {
        Self { clients, epoch }
    }

    fn get_client(&self, address: &Address) -> ChannelResult<&DkgRpcClient> {
        self.clients.get(address).ok_or_else(|| {
            ChannelError::RequestFailed(format!("no client for address {}", address))
        })
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
        _recipient: &Address,
        _request: &SendRotationMessagesRequest,
    ) -> ChannelResult<SendRotationMessagesResponse> {
        // TODO: Implement when `KeyRotationRpcClient` is available
        Err(ChannelError::Other(
            "rotation not yet implemented".to_string(),
        ))
    }

    async fn retrieve_rotation_messages(
        &self,
        _party: &Address,
        _request: &RetrieveRotationMessagesRequest,
    ) -> ChannelResult<RetrieveRotationMessagesResponse> {
        // TODO: Implement when `KeyRotationRpcClient` is available
        Err(ChannelError::Other(
            "rotation not yet implemented".to_string(),
        ))
    }
}
