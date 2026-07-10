// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use axum::http;
use sui_http::middleware::callback::CallbackLayer;
use tonic::body::Body;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
use tower::ServiceBuilder;
use tower::util::BoxCloneService;

use crate::grpc::metrics_layer::RpcMetricsMakeCallbackHandler;
use crate::metrics::Metrics;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Boxed transport handed to the tonic-generated `GuardianServiceClient`.
/// Same shape as `crate::grpc::Client::BoxedChannel`, so the metrics
/// callback layer wraps validator-validator and validator-guardian RPCs
/// identically.
pub type BoxedChannel = BoxCloneService<http::Request<Body>, http::Response<Body>, tonic::Status>;

/// Lazy gRPC channel to a `hashi-guardian`.
#[derive(Clone)]
pub struct GuardianClient {
    endpoint: String,
    channel: Channel,
    metrics: Option<Arc<Metrics>>,
}

impl std::fmt::Debug for GuardianClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianClient")
            .field("endpoint", &self.endpoint)
            .field("metrics_enabled", &self.metrics.is_some())
            .finish()
    }
}

impl GuardianClient {
    pub fn new(endpoint: &str) -> Result<Self, tonic::Status> {
        let mut builder = Endpoint::from_shared(endpoint.to_string())
            .map_err(Into::<BoxError>::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5));
        // A public guardian/proxy endpoint is HTTPS (CA-signed at the ALB). tonic
        // rejects an https:// URI with no TLS config (HttpsUriWithoutTlsSupport),
        // which fails limiter bootstrap + committee reconcile. Enable webpki roots
        // for https; http:// (in-cluster, local, tests) stays plaintext h2c.
        if endpoint.starts_with("https://") {
            builder = builder
                .tls_config(ClientTlsConfig::new().with_webpki_roots())
                .map_err(Into::<BoxError>::into)
                .map_err(tonic::Status::from_error)?;
        }
        let channel = builder.connect_lazy();
        Ok(Self {
            endpoint: endpoint.to_string(),
            channel,
            metrics: None,
        })
    }

    /// Attach the metrics registry so outbound guardian RPCs are observed
    /// by [`RpcMetricsMakeCallbackHandler`] via `sui_http`'s callback
    /// layer. Without this, the client emits no RPC traffic metrics.
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build a boxed transport, applying the metrics callback layer when
    /// a registry is configured. Mirrors `crate::grpc::client::Client::boxed_channel`
    /// so guardian RPCs surface under the same `hashi_requests_total` /
    /// `hashi_request_latency_seconds` metrics as validator-validator
    /// traffic.
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
                    .map_err(|e: tonic::transport::Error| -> BoxError { Box::new(e) })
                    .service(channel);
                BoxCloneService::new(svc)
            }
            None => {
                let svc = ServiceBuilder::new()
                    .map_err(|e: tonic::transport::Error| tonic::Status::from_error(Box::new(e)))
                    .service(channel);
                BoxCloneService::new(svc)
            }
        }
    }

    pub fn guardian_service_client(&self) -> GuardianServiceClient<BoxedChannel> {
        GuardianServiceClient::new(self.boxed_channel())
    }

    pub async fn get_guardian_info(
        &self,
    ) -> Result<hashi_types::proto::GetGuardianInfoResponse, tonic::Status> {
        let response = self
            .guardian_service_client()
            .get_guardian_info(hashi_types::proto::GetGuardianInfoRequest {})
            .await?;
        Ok(response.into_inner())
    }

    pub async fn standard_withdrawal(
        &self,
        request: hashi_types::proto::SignedStandardWithdrawalRequest,
    ) -> Result<hashi_types::proto::SignedStandardWithdrawalResponse, tonic::Status> {
        let response = self
            .guardian_service_client()
            .standard_withdrawal(request)
            .await?;
        Ok(response.into_inner())
    }

    pub async fn update_committee(
        &self,
        request: hashi_types::proto::SignedCommitteeTransition,
    ) -> Result<hashi_types::proto::UpdateCommitteeResponse, tonic::Status> {
        let response = self
            .guardian_service_client()
            .update_committee(request)
            .await?;
        Ok(response.into_inner())
    }

    pub async fn update_committee_chain(
        &self,
        request: hashi_types::proto::UpdateCommitteeChainRequest,
    ) -> Result<hashi_types::proto::UpdateCommitteeResponse, tonic::Status> {
        let response = self
            .guardian_service_client()
            .update_committee_chain(request)
            .await?;
        Ok(response.into_inner())
    }
}
