use crate::dkg::types::{
    ComplainRequest, ComplainResponse, RetrieveMessageRequest, RetrieveMessageResponse,
    SendMessageRequest, SendMessageResponse,
};
use crate::proto;
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
        &mut self,
        epoch: u64,
        request: &SendMessageRequest,
    ) -> Result<SendMessageResponse> {
        let mut proto_request = proto::SendMessageRequest::from(request);
        proto_request.epoch = Some(epoch);
        let response = self.0.send_message(proto_request).await?;
        SendMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn retrieve_message(
        &mut self,
        epoch: u64,
        request: &RetrieveMessageRequest,
    ) -> Result<RetrieveMessageResponse> {
        let mut proto_request = proto::RetrieveMessageRequest::from(request);
        proto_request.epoch = Some(epoch);
        let response = self.0.retrieve_message(proto_request).await?;
        RetrieveMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn complain(
        &mut self,
        epoch: u64,
        request: &ComplainRequest,
    ) -> Result<ComplainResponse> {
        let mut proto_request = proto::ComplainRequest::from(request);
        proto_request.epoch = Some(epoch);
        let response = self.0.complain(proto_request).await?;
        ComplainResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}
