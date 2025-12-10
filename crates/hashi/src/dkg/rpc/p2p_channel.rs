use crate::communication::{ChannelError, ChannelResult, P2PChannel};
use crate::dkg::rpc::DkgRpcClient;
use crate::dkg::types::{
    ComplainRequest, ComplainResponse, RetrieveMessageRequest, RetrieveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
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
}
