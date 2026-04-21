// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use axum::http;
use tonic::Response;
use tonic::body::Body;
use tonic_rustls::Channel;
use tonic_rustls::Endpoint;
use tower::ServiceBuilder;
use tower::util::BoxCloneService;

use sui_http::middleware::callback::CallbackLayer;

use crate::grpc::metrics_layer::RpcMetricsMakeCallbackHandler;
use crate::metrics::Metrics;
use crate::tls::make_client_config_no_verification;
use hashi_types::proto::GetReconfigCompletionSignatureRequest;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::bridge_service_client::BridgeServiceClient;
use hashi_types::proto::mpc_service_client::MpcServiceClient;

type Result<T, E = tonic::Status> = std::result::Result<T, E>;
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Type-erased transport handed to tonic-generated clients. Using a single
/// boxed type keeps `Client` cloneable regardless of whether the metrics
/// tower layer is attached.
pub type BoxedChannel = BoxCloneService<http::Request<Body>, http::Response<Body>, tonic::Status>;

const DEFAULT_MAX_DECODING_MESSAGE_SIZE: usize = 4 * 1024 * 1024;

/// Metadata key used to tag outbound MPC RPCs with the originating protocol
/// (e.g. DKG, signing). Set by `mpc::rpc::p2p_channel::RpcP2PChannel` and
/// read by metrics middleware to label per-protocol traffic.
pub const MPC_PROTOCOL_METADATA_KEY: &str = "x-hashi-mpc-protocol";

#[derive(Clone)]
pub struct Client {
    uri: http::Uri,
    channel: Channel,
    max_decoding_message_size: usize,
    metrics: Option<Arc<Metrics>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Skip the prometheus registry — it has no meaningful Debug impl
        // and it would bloat every `{:?}` containing a `Client`.
        f.debug_struct("Client")
            .field("uri", &self.uri)
            .field("max_decoding_message_size", &self.max_decoding_message_size)
            .field("metrics_enabled", &self.metrics.is_some())
            .finish()
    }
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
            .timeout(Duration::from_secs(40))
            .http2_keep_alive_interval(Duration::from_secs(5))
            .connect_lazy();

        Ok(Self {
            uri,
            channel,
            max_decoding_message_size: DEFAULT_MAX_DECODING_MESSAGE_SIZE,
            metrics: None,
        })
    }

    pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
        self.max_decoding_message_size = limit;
        self
    }

    /// Attach the metrics registry so outbound RPCs are observed by
    /// [`RpcMetricsMakeCallbackHandler`] via `sui_http`'s callback layer.
    /// Without this, the client emits no RPC traffic metrics.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
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

    /// Build a boxed transport, applying the metrics callback layer when
    /// a registry is configured.
    ///
    /// `CallbackLayer` wraps the request body in `RequestBody<_, _>` and
    /// the response body in `ResponseBody<_, _>`. `tonic_rustls::Channel`
    /// is monomorphic over `tonic::body::Body`, so we rebox each side
    /// back to `tonic::body::Body` before/after the channel sees it. The
    /// inner `tonic_rustls::Error` is mapped to `tonic::Status` so
    /// tonic's generated clients receive the error type they expect.
    fn boxed_channel(&self) -> BoxedChannel {
        let channel = self.channel.clone();
        match &self.metrics {
            Some(metrics) => {
                let svc = ServiceBuilder::new()
                    .map_err(tonic::Status::from_error)
                    .map_response(|resp: http::Response<_>| resp.map(Body::new))
                    .layer(CallbackLayer::new(RpcMetricsMakeCallbackHandler::client(
                        metrics.clone(),
                    )))
                    .map_request(|req: http::Request<_>| req.map(Body::new))
                    .map_err(|e: tonic_rustls::Error| -> BoxError { Box::new(e) })
                    .service(channel);
                BoxCloneService::new(svc)
            }
            None => {
                let svc = ServiceBuilder::new()
                    .map_err(|e: tonic_rustls::Error| tonic::Status::from_error(Box::new(e)))
                    .service(channel);
                BoxCloneService::new(svc)
            }
        }
    }

    pub fn bridge_service_client(&self) -> BridgeServiceClient<BoxedChannel> {
        BridgeServiceClient::new(self.boxed_channel())
            .max_decoding_message_size(self.max_decoding_message_size)
    }

    pub fn mpc_service_client(&self) -> MpcServiceClient<BoxedChannel> {
        MpcServiceClient::new(self.boxed_channel())
            .max_decoding_message_size(self.max_decoding_message_size)
    }

    pub async fn get_service_info(&self) -> Result<Response<GetServiceInfoResponse>> {
        self.bridge_service_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await
    }

    pub async fn get_reconfig_completion_signature(&self, epoch: u64) -> Result<Option<Vec<u8>>> {
        let request = GetReconfigCompletionSignatureRequest { epoch: Some(epoch) };
        let response = self
            .mpc_service_client()
            .get_reconfig_completion_signature(request)
            .await?;
        Ok(response.into_inner().signature.map(|b| b.to_vec()))
    }
}
