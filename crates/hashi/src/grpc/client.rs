use std::time::Duration;

use axum::http;
use tonic::Response;
use tonic_rustls::Channel;
use tonic_rustls::Endpoint;

use crate::dkg::types::ComplainRequest;
use crate::dkg::types::ComplainResponse;
use crate::dkg::types::GetPublicDkgOutputRequest;
use crate::dkg::types::GetPublicDkgOutputResponse;
use crate::dkg::types::RetrieveMessageRequest;
use crate::dkg::types::RetrieveMessageResponse;
use crate::dkg::types::SendMessageRequest;
use crate::dkg::types::SendMessageResponse;
use crate::proto::GetServiceInfoRequest;
use crate::proto::GetServiceInfoResponse;
use crate::proto::bridge_service_client::BridgeServiceClient;
use crate::proto::dkg_service_client::DkgServiceClient;
use crate::proto::key_rotation_service_client::KeyRotationServiceClient;
use crate::tls::make_client_config_no_verification;

type Result<T, E = tonic::Status> = std::result::Result<T, E>;
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Clone, Debug)]
pub struct Client {
    uri: http::Uri,
    channel: Channel,
}

impl Client {
    pub fn new<T>(uri: T, tls_config: rustls::ClientConfig) -> Result<Self>
    where
        T: TryInto<http::Uri>,
        T::Error: Into<BoxError>,
    {
        let uri = uri
            .try_into()
            .map_err(Into::into)
            .map_err(tonic::Status::from_error)?;
        if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
            return Err(tonic::Status::from_error(
                "only https endpoints are supported".into(),
            ));
        }
        let channel = Endpoint::from(uri.clone())
            .tls_config(tls_config)
            .map_err(Into::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .connect_lazy();

        Ok(Self { uri, channel })
    }

    pub fn new_no_auth<T>(uri: T) -> Result<Self>
    where
        T: TryInto<http::Uri>,
        T::Error: Into<BoxError>,
    {
        Self::new(uri, make_client_config_no_verification())
    }

    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    pub fn bridge_service_client(&self) -> BridgeServiceClient<Channel> {
        BridgeServiceClient::new(self.channel.clone())
    }

    pub fn dkg_service_client(&self) -> DkgServiceClient<Channel> {
        DkgServiceClient::new(self.channel.clone())
    }

    pub fn key_rotation_service_client(&self) -> KeyRotationServiceClient<Channel> {
        KeyRotationServiceClient::new(self.channel.clone())
    }

    pub async fn get_service_info(&self) -> Result<Response<GetServiceInfoResponse>> {
        self.bridge_service_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
    }

    pub async fn send_message(
        &self,
        epoch: u64,
        request: &SendMessageRequest,
    ) -> Result<SendMessageResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self
            .dkg_service_client()
            .send_message(proto_request)
            .await?;
        SendMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn retrieve_message(
        &self,
        epoch: u64,
        request: &RetrieveMessageRequest,
    ) -> Result<RetrieveMessageResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self
            .dkg_service_client()
            .retrieve_message(proto_request)
            .await?;
        RetrieveMessageResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn complain(
        &self,
        epoch: u64,
        request: &ComplainRequest,
    ) -> Result<ComplainResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self.dkg_service_client().complain(proto_request).await?;
        ComplainResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn get_public_dkg_output(
        &self,
        request: &GetPublicDkgOutputRequest,
    ) -> Result<GetPublicDkgOutputResponse> {
        let proto_request = request.to_proto();
        let response = self
            .key_rotation_service_client()
            .get_public_dkg_output(proto_request)
            .await?;
        GetPublicDkgOutputResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }
}
