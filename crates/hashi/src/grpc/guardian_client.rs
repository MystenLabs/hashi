// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use axum::http;
use sui_http::middleware::callback::CallbackLayer;
use sui_sdk_types::Address;
use tonic::body::Body;
use tonic::metadata::MetadataMap;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Endpoint;
use tower::ServiceBuilder;
use tower::util::BoxCloneService;

use crate::grpc::metrics_layer::RpcMetricsMakeCallbackHandler;
use crate::metrics::Metrics;
use hashi_types::guardian::member_auth::MEMBER_AUTH_METADATA_KEY;
use hashi_types::guardian::member_auth::MemberAuth;
use hashi_types::guardian::now_timestamp_ms;
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
    member_auth: MemberAuthSigner,
}

impl std::fmt::Debug for GuardianClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianClient")
            .field("endpoint", &self.endpoint)
            .field("metrics_enabled", &self.metrics.is_some())
            .finish()
    }
}

#[derive(Clone)]
struct MemberAuthSigner {
    tls_private_key: Arc<ed25519_dalek::SigningKey>,
    hashi_object_id: Address,
}

impl MemberAuthSigner {
    fn attach(&self, mut request: http::Request<Body>) -> http::Request<Body> {
        let auth = MemberAuth::sign(
            &self.tls_private_key,
            self.hashi_object_id,
            request.uri().path(),
            now_timestamp_ms(),
        );
        let mut metadata = MetadataMap::new();
        metadata.insert_bin(
            MEMBER_AUTH_METADATA_KEY,
            MetadataValue::from_bytes(&auth.to_bytes()),
        );
        request.headers_mut().extend(metadata.into_headers());
        request
    }
}

impl GuardianClient {
    /// Every RPC carries a [`MemberAuth`] signed with this node's registered
    /// TLS key, which the guardian proxy requires on node RPCs.
    pub fn new(
        endpoint: &str,
        tls_private_key: ed25519_dalek::SigningKey,
        hashi_object_id: Address,
    ) -> Result<Self, tonic::Status> {
        let mut builder = Endpoint::from_shared(endpoint.to_string())
            .map_err(Into::<BoxError>::into)
            .map_err(tonic::Status::from_error)?
            .connect_timeout(Duration::from_secs(5))
            .http2_keep_alive_interval(Duration::from_secs(5));
        // tonic rejects an https:// endpoint without a TLS config; http:// stays plaintext.
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
            member_auth: MemberAuthSigner {
                tls_private_key: Arc::new(tls_private_key),
                hashi_object_id,
            },
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
        let member_auth = self.member_auth.clone();
        let attach_member_auth = move |request: http::Request<Body>| member_auth.attach(request);
        match &self.metrics {
            Some(metrics) => {
                let svc = ServiceBuilder::new()
                    .map_request(attach_member_auth)
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
                    .map_request(attach_member_auth)
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

    type Seen = Arc<Mutex<Vec<(String, http::HeaderMap)>>>;

    /// Records each request's path and headers and answers `Unimplemented`.
    async fn spawn_recording_stub() -> (String, Seen) {
        let seen = Seen::default();
        let recorder = seen.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            recorder
                .lock()
                .unwrap()
                .push((request.uri().path().to_string(), request.headers().clone()));
            async { tonic::Status::unimplemented("stub").into_http::<axum::body::Body>() }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), seen)
    }

    fn sent_member_auth(headers: &http::HeaderMap) -> MemberAuth {
        let value = MetadataMap::from_headers(headers.clone())
            .get_bin(MEMBER_AUTH_METADATA_KEY)
            .expect("member auth header")
            .to_bytes()
            .unwrap();
        MemberAuth::from_bytes(&value).unwrap()
    }

    #[tokio::test]
    async fn signs_each_rpc_with_the_tls_key() {
        let (endpoint, seen) = spawn_recording_stub().await;
        let tls_private_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let hashi_object_id = Address::new([9; 32]);

        for with_metrics in [false, true] {
            let mut client =
                GuardianClient::new(&endpoint, tls_private_key.clone(), hashi_object_id).unwrap();
            if with_metrics {
                client = client.with_metrics(Arc::new(Metrics::new_default()));
            }
            client.get_guardian_info(false).await.unwrap_err();
            client
                .standard_withdrawal(Default::default())
                .await
                .unwrap_err();

            let requests = std::mem::take(&mut *seen.lock().unwrap());
            let paths: Vec<&str> = requests.iter().map(|(path, _)| path.as_str()).collect();
            assert_eq!(
                paths,
                [
                    "/sui.hashi.v1alpha.GuardianService/GetGuardianInfo",
                    "/sui.hashi.v1alpha.GuardianService/StandardWithdrawal",
                ]
            );
            for (path, headers) in &requests {
                let auth = sent_member_auth(headers);
                assert_eq!(
                    auth.tls_public_key,
                    tls_private_key.verifying_key().to_bytes()
                );
                assert!(auth.verify_signature(hashi_object_id, path));
                assert!(auth.is_fresh(now_timestamp_ms()));
            }
        }
    }
}
