use crate::dkg::types::{
    ComplainRequest, ComplainResponse, RetrieveMessageRequest, RetrieveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
use crate::proto::dkg_service_client::DkgServiceClient;
use tonic::transport::Channel;

pub type Result<T, E = tonic::Status> = std::result::Result<T, E>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone)]
pub struct DkgRpcClient(DkgServiceClient<Channel>);

impl DkgRpcClient {
    pub async fn new<T>(uri: T) -> Result<Self, BoxError>
    where
        T: TryInto<tonic::transport::Uri>,
        T::Error: Into<BoxError>,
    {
        let uri = uri.try_into().map_err(Into::into)?;
        let channel = Channel::builder(uri).connect().await?;
        Ok(Self(DkgServiceClient::new(channel)))
    }

    pub async fn send_message(
        &self,
        epoch: u64,
        request: &SendMessageRequest,
    ) -> Result<SendMessageResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self.0.clone().send_message(proto_request).await?;
        SendMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn retrieve_message(
        &self,
        epoch: u64,
        request: &RetrieveMessageRequest,
    ) -> Result<RetrieveMessageResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self.0.clone().retrieve_message(proto_request).await?;
        RetrieveMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn complain(
        &self,
        epoch: u64,
        request: &ComplainRequest,
    ) -> Result<ComplainResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self.0.clone().complain(proto_request).await?;
        ComplainResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}
