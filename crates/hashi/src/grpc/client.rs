use std::time::Duration;

use axum::http;
use tonic::Response;
use tonic_rustls::Channel;
use tonic_rustls::Endpoint;

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
use crate::tls::make_client_config_no_verification;
use hashi_types::proto::GetReconfigCompletionSignatureRequest;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::bridge_service_client::BridgeServiceClient;
use hashi_types::proto::mpc_service_client::MpcServiceClient;

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

    pub fn mpc_service_client(&self) -> MpcServiceClient<Channel> {
        MpcServiceClient::new(self.channel.clone())
    }

    pub async fn get_service_info(&self) -> Result<Response<GetServiceInfoResponse>> {
        self.bridge_service_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
    }

    pub async fn send_messages(
        &self,
        epoch: u64,
        request: &SendMessagesRequest,
    ) -> Result<SendMessagesResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self
            .mpc_service_client()
            .send_messages(proto_request)
            .await?;
        SendMessagesResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn retrieve_messages(
        &self,
        epoch: u64,
        request: &RetrieveMessagesRequest,
    ) -> Result<RetrieveMessagesResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self
            .mpc_service_client()
            .retrieve_messages(proto_request)
            .await?;
        RetrieveMessagesResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn complain(
        &self,
        epoch: u64,
        request: &ComplainRequest,
    ) -> Result<ComplaintResponses> {
        let proto_request = request.to_proto(epoch);
        let response = self.mpc_service_client().complain(proto_request).await?;
        ComplaintResponses::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn get_public_dkg_output(
        &self,
        request: &GetPublicDkgOutputRequest,
    ) -> Result<GetPublicDkgOutputResponse> {
        let proto_request = request.to_proto();
        let response = self
            .mpc_service_client()
            .get_public_dkg_output(proto_request)
            .await?;
        GetPublicDkgOutputResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn get_partial_signatures(
        &self,
        epoch: u64,
        request: &GetPartialSignaturesRequest,
    ) -> Result<GetPartialSignaturesResponse> {
        let proto_request = request.to_proto(epoch);
        let response = self
            .mpc_service_client()
            .get_partial_signatures(proto_request)
            .await?;
        GetPartialSignaturesResponse::try_from(response.get_ref())
            .map_err(|e| tonic::Status::internal(e.to_string()))
    }

    pub async fn get_reconfig_completion_signature(&self, epoch: u64) -> Result<Vec<u8>> {
        let request = GetReconfigCompletionSignatureRequest { epoch: Some(epoch) };
        let response = self
            .mpc_service_client()
            .get_reconfig_completion_signature(request)
            .await?;
        response
            .into_inner()
            .signature
            .map(|b| b.to_vec())
            .ok_or_else(|| tonic::Status::internal("response missing signature field"))
    }
}
