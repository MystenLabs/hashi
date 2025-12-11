use std::time::Duration;

use axum::http;
use tonic::Response;
use tonic_rustls::Channel;
use tonic_rustls::Endpoint;

use crate::proto::GetServiceInfoRequest;
use crate::proto::GetServiceInfoResponse;
use crate::proto::bridge_service_client::BridgeServiceClient;
use crate::proto::dkg_service_client::DkgServiceClient;
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

    pub async fn get_service_info(&self) -> Result<Response<GetServiceInfoResponse>> {
        self.bridge_service_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
    }
}
