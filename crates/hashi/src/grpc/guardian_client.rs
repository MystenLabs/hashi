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
use tonic::transport::Identity;
use tower::ServiceBuilder;
use tower::util::BoxCloneService;

use crate::grpc::metrics_layer::RpcMetricsMakeCallbackHandler;
use crate::metrics::Metrics;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

const GET_GUARDIAN_INFO_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// Over TLS the client presents the node's registered TLS key as its
    /// certificate: the guardian proxy serves node RPCs only to committee members.
    pub fn new(
        endpoint: &str,
        tls_private_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, tonic::Status> {
        Self::with_tls_config(
            endpoint,
            tls_private_key,
            ClientTlsConfig::new().with_webpki_roots(),
        )
    }

    fn with_tls_config(
        endpoint: &str,
        tls_private_key: &ed25519_dalek::SigningKey,
        tls_config: ClientTlsConfig,
    ) -> Result<Self, tonic::Status> {
        let mut builder = Endpoint::from_shared(endpoint.to_string())
            .map_err(Into::<BoxError>::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5));
        // tonic rejects an https:// endpoint without a TLS config; http:// stays plaintext.
        if endpoint.starts_with("https://") {
            let (cert, key) = crate::tls::make_identity_pem(tls_private_key);
            builder = builder
                .tls_config(tls_config.identity(Identity::from_pem(cert, key.as_bytes())))
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
        let mut client = self.guardian_service_client();
        let response = tokio::time::timeout(
            GET_GUARDIAN_INFO_TIMEOUT,
            client.get_guardian_info(hashi_types::proto::GetGuardianInfoRequest {}),
        )
        .await
        .map_err(|_| tonic::Status::deadline_exceeded("GetGuardianInfo timed out"))??;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tonic::transport::Certificate;

    type SeenKeys = Arc<Mutex<Vec<ed25519_dalek::VerifyingKey>>>;

    /// A TLS server built like a node's, recording each caller's certificate key
    /// and answering `Unimplemented`.
    fn spawn_tls_stub() -> (sui_http::ServerHandle, Certificate, SeenKeys) {
        crate::init_crypto_provider();
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let seen = SeenKeys::default();
        let recorder = seen.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let key = request
                .extensions()
                .get::<sui_http::PeerCertificates>()
                .and_then(|certs| certs.peer_certs().first().cloned())
                .map(|cert| crate::tls::public_key_from_certificate(&cert).unwrap());
            recorder.lock().unwrap().extend(key);
            async { tonic::Status::unimplemented("stub").into_http::<axum::body::Body>() }
        });
        let server = sui_http::Builder::new()
            .tls_config(crate::tls::make_server_config(server_key.clone()))
            .serve("127.0.0.1:0", app)
            .unwrap();
        let (server_cert, _) = crate::tls::make_identity_pem(&server_key);
        (server, Certificate::from_pem(server_cert), seen)
    }

    #[tokio::test]
    async fn presents_the_tls_key_as_its_client_certificate() {
        let (server, server_cert, seen) = spawn_tls_stub();
        let tls_private_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let client = GuardianClient::with_tls_config(
            &format!("https://{}", server.local_addr()),
            &tls_private_key,
            ClientTlsConfig::new()
                .ca_certificate(server_cert)
                .domain_name("hashi"),
        )
        .unwrap();

        let status = client.get_guardian_info(false).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unimplemented);
        let status = client
            .standard_withdrawal(Default::default())
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unimplemented);
        assert_eq!(*seen.lock().unwrap(), [tls_private_key.verifying_key(); 2]);
    }
}
