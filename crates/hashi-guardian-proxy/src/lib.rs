// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Out-of-enclave gRPC proxy for the hashi guardian. It fronts the enclave with
//! a stable, hardenable surface. [`forward`] forwards the `GuardianService` RPCs
//! to the enclave, rejecting operator/ceremony RPCs, and [`guardian_info`]
//! caches ordinary `GetGuardianInfo` for every caller. `GetAttestedGuardianInfo`
//! always forwards to the enclave without caching. The rest is grouped by who calls it:
//!
//! - [`node`]: [`node::cache`] makes `StandardWithdrawal` responses idempotent
//!   by `wid`. It answers from an index over the guardian's own S3 withdrawal
//!   log ([`node::widlog`]), which the proxy only reads.
//!   [`node::member_auth`] gates every route: node RPCs are served only to
//!   current or pending committee members ([`node::members`]), who present
//!   their registered TLS key as a client certificate. [`node::handoffs`]
//!   forwards a committee handoff only once the chain stores one between the
//!   same two epochs.
//! - [`kp`]: [`kp::relay`] serves `GuardianRelayService`: key provisioners
//!   submit one share each — authenticated against the ceremony's committed
//!   roster read from the S3 share log ([`kp::roster`]) — and the relay batches
//!   a threshold-many into the guardian's `ProvisionerInit`.
//! - [`public`]: [`public::info`] serves a read-only HTTP `/info` + `/health`
//!   JSON surface (a curated limiter/identity view, with CORS) so browser /
//!   `fetch` clients can read limiter status the gRPC surface only exposes to
//!   nodes — on the same port as gRPC, so the guardian exposes one interface.
//!
//! Nodes call it on a second listener, where the proxy terminates TLS itself,
//! requires their registered TLS key as a client certificate ([`tls`]), and
//! serves only node RPCs and `GetGuardianInfo`.
//!
//! The proxy is liveness-only in the trust model: it can stall but never forge a
//! withdrawal or read a KP share (shares are end-to-end encrypted to the enclave).

pub mod config;
pub mod forward;
pub mod guardian_info;
pub mod kp;
pub mod log_store;
pub mod metrics;
pub mod node;
pub mod public;
pub mod remote_write;
pub mod tls;

use std::sync::Arc;

use hashi_types::proto::guardian_relay_service_server::GuardianRelayServiceServer;
use hashi_types::proto::guardian_service_server::GuardianServiceServer;
use tonic_health::pb::health_server::Health;
use tonic_health::pb::health_server::HealthServer;

pub use config::Config;
pub use forward::Forwarding;
pub use kp::relay::Relay;
pub use node::cache::CachingGuardianGrpc;
pub use node::member_auth::MemberGate;

use crate::log_store::LogStore;

/// Everything the proxy serves: gRPC (forwarder, relay, health) and the HTTP
/// `/info` + `/health`. Both listeners mount it, and the member gate picks what
/// each one serves. `Router::layer` only wraps the routes added before it, so
/// the member gate goes last.
pub fn router<L: LogStore, H: Health>(
    guardian: CachingGuardianGrpc<Forwarding<L>, L>,
    relay: Relay<L>,
    health: HealthServer<H>,
    info: public::info::InfoState,
    gate: Arc<MemberGate>,
) -> axum::Router {
    axum::Router::new()
        .add_grpc_service(health)
        .add_grpc_service(GuardianServiceServer::new(guardian))
        .add_grpc_service(GuardianRelayServiceServer::new(relay))
        .merge(public::info::router(info))
        .layer(axum::middleware::from_fn_with_state(
            gate,
            node::member_auth::require_committee_member,
        ))
}

/// Mount a tonic gRPC service as an axum route-service at `/{ServiceName}/*`, so
/// gRPC and plain-HTTP routes share one router. Mirrors `crates/hashi/src/grpc/mod.rs`.
trait RouterExt {
    fn add_grpc_service<S>(self, svc: S) -> Self
    where
        S: tower::Service<
                axum::extract::Request,
                Response: axum::response::IntoResponse,
                Error = std::convert::Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static;
}

impl RouterExt for axum::Router {
    fn add_grpc_service<S>(self, svc: S) -> Self
    where
        S: tower::Service<
                axum::extract::Request,
                Response: axum::response::IntoResponse,
                Error = std::convert::Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        self.route_service(&format!("/{}/{{*rest}}", S::NAME), svc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::test_utils::mock_request;
    use crate::forward::test_utils::spawn_stub;
    use crate::forward::test_utils::StubGuardian;
    use crate::kp::roster::RosterCache;
    use crate::log_store::test_store::MemStore;
    use crate::metrics::ProxyMetrics;
    use crate::node::handoffs::test_utils::gate_over;
    use crate::node::members::test_utils::snapshot;
    use crate::node::members::MemberAllowlist;
    use crate::node::widlog::WidLogIndex;
    use crate::tls::test_utils::node_identity;
    use crate::tls::test_utils::test_cert;
    use crate::tls::test_utils::TestCert;
    use axum::body::Body;
    use axum::http::Method;
    use axum::http::StatusCode;
    use hashi_types::proto;
    use hashi_types::proto::guardian_relay_service_client::GuardianRelayServiceClient;
    use hashi_types::proto::guardian_service_client::GuardianServiceClient;
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tonic::transport::Certificate;
    use tonic::transport::Channel;
    use tonic::transport::ClientTlsConfig;
    use tonic::transport::Endpoint;
    use tonic::Code;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::health_client::HealthClient;
    use tonic_health::pb::HealthCheckRequest;
    use tower::ServiceExt;

    fn member_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
    }

    /// The stub answers attested info only with the metadata it checks was
    /// forwarded.
    fn attested<T>(message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request
            .metadata_mut()
            .insert("x-attestation-test", "forwarded".parse().unwrap());
        request
    }

    struct Proxy {
        stub: StubGuardian,
        app: axum::Router,
        public_addr: SocketAddr,
        node_server: sui_http::ServerHandle,
        cert: TestCert,
    }

    impl Proxy {
        /// The plaintext listener the load balancer forwards to.
        fn public(&self) -> Channel {
            Endpoint::from_shared(format!("http://{}", self.public_addr))
                .unwrap()
                .connect_lazy()
        }

        /// The node listener, presenting `key`'s certificate.
        fn node_channel(&self, key: &ed25519_dalek::SigningKey) -> Channel {
            let tls = ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&self.cert.cert_pem))
                .domain_name("localhost")
                .identity(node_identity(key));
            Endpoint::from_shared(format!("https://{}", self.node_server.local_addr()))
                .unwrap()
                .tls_config(tls)
                .unwrap()
                .connect_lazy()
        }

        fn node(&self, key: &ed25519_dalek::SigningKey) -> GuardianServiceClient<Channel> {
            GuardianServiceClient::new(self.node_channel(key))
        }
    }

    /// The real router over a stub guardian, on both listeners, with
    /// `member_key` on the allowlist.
    async fn spawn_proxy() -> Proxy {
        let (stub, backend) = spawn_stub().await;
        let metrics = Arc::new(ProxyMetrics::new());
        let roster = Arc::new(RosterCache::new(MemStore::default()));
        let guardian = CachingGuardianGrpc::new(
            Forwarding::new(
                backend.clone(),
                backend.clone(),
                roster.clone(),
                gate_over(&[]),
            ),
            WidLogIndex::ready_for_tests(MemStore::default(), metrics.clone()).await,
            metrics.clone(),
        );
        let relay = Relay::new(backend.clone(), roster);
        let (reporter, health) = tonic_health::server::health_reporter();
        reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        let info = public::info::InfoState::new(
            GuardianServiceClient::new(backend),
            Duration::from_secs(1),
        );
        let allowlist = Arc::new(MemberAllowlist::new(metrics.clone()));
        allowlist.store(snapshot(&[&member_key()]));
        let app = router(
            guardian,
            relay,
            health,
            info,
            Arc::new(MemberGate::new(allowlist, metrics.clone())),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let public_addr = listener.local_addr().unwrap();
        tokio::spawn({
            let app = app.clone();
            async move { axum::serve(listener, app).await.unwrap() }
        });
        let cert = test_cert();
        let served = tls::ServerCert::load(&cert.source, &metrics).await.unwrap();
        let node_server = sui_http::Builder::new()
            .tls_config(tls::server_config(served).unwrap())
            .serve("127.0.0.1:0", app.clone())
            .unwrap();
        Proxy {
            stub,
            app,
            public_addr,
            node_server,
            cert,
        }
    }

    #[tokio::test]
    async fn node_rpcs_need_the_node_listener_even_for_a_cached_wid() {
        let proxy = spawn_proxy().await;
        let mut public = GuardianServiceClient::new(proxy.public());

        let refused = public
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated);
        assert_eq!(
            proxy.stub.standard_withdrawal_calls.load(Ordering::SeqCst),
            0
        );

        // A member's call on the node listener reaches the guardian and fills
        // the wid cache.
        proxy
            .node(&member_key())
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap();
        assert_eq!(
            proxy.stub.standard_withdrawal_calls.load(Ordering::SeqCst),
            1
        );

        // The gate runs before the cache, so the cached wid is no way in.
        let replay = public
            .standard_withdrawal(mock_request([0x11; 32], 1))
            .await
            .unwrap_err();
        assert_eq!(replay.code(), Code::Unauthenticated);

        let update = public
            .update_committee_chain(proto::UpdateCommitteeChainRequest::default())
            .await
            .unwrap_err();
        assert_eq!(update.code(), Code::Unauthenticated);
        let update = public
            .update_committee(proto::SignedCommitteeTransition::default())
            .await
            .unwrap_err();
        assert_eq!(update.code(), Code::Unauthenticated);
    }

    #[tokio::test]
    async fn refuses_certificates_outside_the_committee() {
        let proxy = spawn_proxy().await;
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);

        let refused = proxy
            .node(&outsider)
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap_err();
        assert_eq!(refused.code(), Code::PermissionDenied);
        assert_eq!(
            proxy.stub.standard_withdrawal_calls.load(Ordering::SeqCst),
            0
        );

        // Guardian info stays open to any node, member or not.
        proxy
            .node(&outsider)
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_node_listener_refuses_kp_and_status_routes_even_to_members() {
        let proxy = spawn_proxy().await;
        let channel = proxy.node_channel(&member_key());

        let confirm = GuardianServiceClient::new(channel.clone())
            .confirm_ceremony(proto::SignedCeremonyConfirmationRequest::default())
            .await
            .unwrap_err();
        assert_eq!(confirm.code(), Code::PermissionDenied);
        assert!(confirm.message().contains("guardian_url"), "{confirm:?}");

        let attested_info = GuardianServiceClient::new(channel.clone())
            .get_attested_guardian_info(attested(proto::GetAttestedGuardianInfoRequest {}))
            .await
            .unwrap_err();
        assert_eq!(attested_info.code(), Code::PermissionDenied);

        let relay = GuardianRelayServiceClient::new(channel.clone())
            .get_provisioning_target_info(attested(proto::GetProvisioningTargetInfoRequest {}))
            .await
            .unwrap_err();
        assert_eq!(relay.code(), Code::PermissionDenied);

        let health = HealthClient::new(channel)
            .check(HealthCheckRequest {
                service: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(health.code(), Code::PermissionDenied);

        assert_eq!(
            proxy
                .stub
                .get_attested_guardian_info_calls
                .load(Ordering::SeqCst),
            0
        );
    }

    #[tokio::test]
    async fn members_still_hit_the_operator_denial() {
        let proxy = spawn_proxy().await;

        let anonymous = GuardianServiceClient::new(proxy.public())
            .operator_init(proto::OperatorInitRequest::default())
            .await
            .unwrap_err();
        assert_eq!(anonymous.code(), Code::Unauthenticated);

        // The forwarder's refusal, not the gate's, which uses the same code.
        let member = proxy
            .node(&member_key())
            .operator_init(proto::OperatorInitRequest::default())
            .await
            .unwrap_err();
        assert_eq!(member.code(), Code::PermissionDenied);
        assert!(
            member
                .message()
                .contains("not served by the guardian proxy"),
            "{member:?}"
        );
    }

    #[tokio::test]
    async fn public_routes_stay_open_on_the_public_listener() {
        let proxy = spawn_proxy().await;
        let channel = proxy.public();
        let mut client = GuardianServiceClient::new(channel.clone());

        client
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await
            .unwrap();
        assert_eq!(proxy.stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);

        // Reaches the KP signature check, which rejects the empty request.
        let unsigned = client
            .confirm_ceremony(proto::SignedCeremonyConfirmationRequest::default())
            .await
            .unwrap_err();
        assert_eq!(unsigned.code(), Code::InvalidArgument);

        client
            .get_attested_guardian_info(attested(proto::GetAttestedGuardianInfoRequest {}))
            .await
            .unwrap();
        GuardianRelayServiceClient::new(channel.clone())
            .get_provisioning_target_info(attested(proto::GetProvisioningTargetInfoRequest {}))
            .await
            .unwrap();
        assert_eq!(
            proxy
                .stub
                .get_attested_guardian_info_calls
                .load(Ordering::SeqCst),
            2
        );

        let health = HealthClient::new(channel)
            .check(HealthCheckRequest {
                service: String::new(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(health.status(), ServingStatus::Serving);

        let info = reqwest::get(format!("http://{}/info", proxy.public_addr))
            .await
            .unwrap();
        assert_ne!(info.status(), reqwest::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn http_status_routes_stay_public_and_the_rest_is_refused() {
        let proxy = spawn_proxy().await;
        let status = |method: Method, uri: &str| {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("origin", "https://hashi.example")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap();
            let app = proxy.app.clone();
            async move { app.oneshot(request).await.unwrap().status() }
        };

        assert_eq!(status(Method::GET, "/health").await, StatusCode::OK);
        assert_eq!(status(Method::OPTIONS, "/info").await, StatusCode::OK);
        assert_ne!(status(Method::GET, "/info").await, StatusCode::FORBIDDEN);
        assert_eq!(status(Method::GET, "/metrics").await, StatusCode::FORBIDDEN);
    }
}
