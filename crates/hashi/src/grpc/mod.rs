// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use sui_futures::service::Service;
use sui_http::ServerHandle;
use tower::ServiceBuilder;

use crate::Hashi;

/// Marker for the app-level "signing manager not ready" unavailable
/// response, shared with the p2p client so it can tell this apart from
/// transport-generated `Unavailable` statuses (connection refused,
/// REFUSED_STREAM, 503/504), which must keep counting as peer failures.
pub(crate) const SIGNING_MANAGER_NOT_READY_MSG: &str = "SigningManager not available";

mod client;
pub use client::BoxedChannel;
pub use client::Client;
pub use client::MPC_PROTOCOL_METADATA_KEY;

pub mod bridge_service;
pub mod guardian_client;
pub mod metrics_layer;
pub mod screener_client;

/// Wrapper that triggers graceful HTTP server shutdown on drop.
///
/// The HTTP server is spawned on a detached tokio task by `sui_http::Builder::serve`.
/// This guard ensures that `trigger_shutdown` is called when the owning `Service` is
/// dropped (whether via explicit `Service::shutdown()` or implicit drop), so the server's
/// accept loop breaks and in-flight connections are drained.
struct ServerHandleGuard(Arc<ServerHandle>);

impl Drop for ServerHandleGuard {
    fn drop(&mut self) {
        self.0.trigger_shutdown();
    }
}

#[derive(Clone)]
pub struct HttpService {
    inner: Arc<Hashi>,
}

impl HttpService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self { inner: hashi }
    }

    pub(crate) fn metrics(&self) -> &crate::metrics::Metrics {
        &self.inner.metrics
    }

    pub async fn start(self) -> (std::net::SocketAddr, Service) {
        let router = {
            let max_decoding_message_size = self.inner.config.grpc_max_decoding_message_size();
            let bridge_service =
                hashi_types::proto::bridge_service_server::BridgeServiceServer::new(self.clone())
                    .max_decoding_message_size(max_decoding_message_size);
            let mpc_service =
                hashi_types::proto::mpc_service_server::MpcServiceServer::new(self.clone())
                    .max_decoding_message_size(max_decoding_message_size);

            let (health_reporter, health_service) = tonic_health::server::health_reporter();

            let mut reflection_v1 = tonic_reflection::server::Builder::configure();
            let mut reflection_v1alpha = tonic_reflection::server::Builder::configure();

            for file_descriptor_set in [
                sui_rpc::proto::google::protobuf::FILE_DESCRIPTOR_SET,
                sui_rpc::proto::google::rpc::FILE_DESCRIPTOR_SET,
                tonic_health::pb::FILE_DESCRIPTOR_SET,
                hashi_types::proto::FILE_DESCRIPTOR_SET,
            ] {
                reflection_v1 =
                    reflection_v1.register_encoded_file_descriptor_set(file_descriptor_set);
                reflection_v1alpha =
                    reflection_v1alpha.register_encoded_file_descriptor_set(file_descriptor_set);
            }

            let reflection_v1 = reflection_v1.build_v1().unwrap();
            let reflection_v1alpha = reflection_v1alpha.build_v1alpha().unwrap();

            fn service_name<S: tonic::server::NamedService>(_service: &S) -> &'static str {
                S::NAME
            }

            for service_name in [
                service_name(&bridge_service),
                service_name(&mpc_service),
                service_name(&reflection_v1),
                service_name(&reflection_v1alpha),
            ] {
                health_reporter
                    .set_service_status(service_name, tonic_health::ServingStatus::Serving)
                    .await;
            }

            axum::Router::new()
                .add_grpc_service(bridge_service)
                .add_grpc_service(mpc_service)
                .add_grpc_service(reflection_v1)
                .add_grpc_service(reflection_v1alpha)
                .add_grpc_service(health_service)
        };

        let hashi_for_ready = self.inner.clone();
        let health_endpoint = axum::Router::new()
            .route("/health", axum::routing::get(health))
            .route(
                "/ready",
                axum::routing::get(move || ready(hashi_for_ready.clone())),
            );

        let layers = ServiceBuilder::new()
            .layer(axum::middleware::from_fn_with_state(
                self.inner.clone(),
                require_known_validator,
            ))
            .layer(sui_http::middleware::callback::CallbackLayer::new(
                metrics_layer::RpcMetricsMakeCallbackHandler::server(self.inner.metrics.clone()),
            ));

        let router = router.merge(health_endpoint).layer(layers);

        let tls_config =
            crate::tls::make_server_config(self.inner.config.tls_private_key().unwrap());
        // let tls_config =
        //     crate::tls_rpk::make_server_config(self.inner.config.tls_private_key().unwrap());

        let server_handle = Arc::new(
            sui_http::Builder::new()
                // Recycle peer connections via a graceful max-age drain: a
                // long-lived multiplexed HTTP/2 connection accumulates state that
                // trips a connection-level GoAway(PROTOCOL_ERROR) under sustained
                // load, failing every in-flight request to that peer at once.
                .config(
                    sui_http::Config::default()
                        .max_connection_age(std::time::Duration::from_secs(120)),
                )
                .tls_config(tls_config)
                .serve(self.inner.config.listen_address(), router)
                .unwrap(),
        );
        let local_addr = *server_handle.local_addr();

        let guard = ServerHandleGuard(server_handle.clone());
        let service = Service::new()
            .spawn_aborting(async move {
                guard.0.wait_for_shutdown().await;
                Ok(())
            })
            .with_shutdown_signal(async move {
                server_handle.trigger_shutdown();
            });

        (local_addr, service)
    }

    pub fn mpc_manager(
        &self,
    ) -> Result<Arc<std::sync::RwLock<crate::mpc::MpcManager>>, tonic::Status> {
        self.inner
            .mpc_manager()
            .ok_or_else(|| tonic::Status::unavailable("DKG manager not yet initialized"))
    }

    pub fn signing_manager_for(
        &self,
        epoch: u64,
    ) -> Result<Arc<crate::mpc::SigningManager>, tonic::Status> {
        self.inner.signing_manager_for(epoch).ok_or_else(|| {
            tonic::Status::unavailable(format!(
                "{SIGNING_MANAGER_NOT_READY_MSG} for epoch {epoch}; retry"
            ))
        })
    }

    pub fn btc_monitor(&self) -> &crate::btc_monitor::monitor::MonitorClient {
        self.inner.btc_monitor()
    }

    pub fn get_reconfig_signature(&self, epoch: u64) -> Option<Vec<u8>> {
        self.inner.get_reconfig_signature(epoch)
    }
}

async fn health() -> impl axum::response::IntoResponse {
    (http::StatusCode::OK, "up")
}

async fn ready(hashi: Arc<Hashi>) -> impl axum::response::IntoResponse {
    let Some(onchain_state) = hashi.onchain_state_opt() else {
        return (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "on-chain state not yet initialized",
        );
    };
    // If the chain has moved past what this binary supports, report not-ready so
    // operators/orchestration surface it — the node has halted autonomous work
    // (see leader gate) and needs a binary upgrade. Details are in the
    // `hashi_package_version_unsupported` metric and the leader log.
    if matches!(
        onchain_state.autonomous_halt_reason(),
        Some(crate::onchain::HaltReason::BinaryUnsupported { .. })
    ) {
        return (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "binary does not support the enabled on-chain package version(s) — upgrade required",
        );
    }
    let epoch = onchain_state.epoch();
    // Treat genesis (no committee formed yet) as ready so OrderedReady can bring
    // up the rest of the StatefulSet to register keys and run the initial DKG.
    let awaiting_genesis = epoch == 0 && onchain_state.current_committee().is_none();
    if awaiting_genesis {
        (http::StatusCode::OK, "ready (awaiting genesis)")
    } else if hashi.signing_manager_for(epoch).is_some() {
        (http::StatusCode::OK, "ready")
    } else {
        (
            http::StatusCode::SERVICE_UNAVAILABLE,
            "SigningManager not yet initialized",
        )
    }
}

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

const ANONYMOUS_PATHS: &[&str] = &["/health", "/ready"];

async fn require_known_validator(
    axum::extract::State(hashi): axum::extract::State<Arc<Hashi>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match lookup_validator_address(&hashi, &request) {
        Ok(validator_address) => {
            request.extensions_mut().insert(validator_address);
        }
        Err(_) if ANONYMOUS_PATHS.contains(&request.uri().path()) => {}
        Err(reason) => {
            hashi
                .metrics
                .unknown_caller_refused_total
                .with_label_values(&[reason.as_str()])
                .inc();
            return refuse(&request);
        }
    }
    next.run(request).await
}

enum RefusalReason {
    NoClientCert,
    StateUnavailable,
    NotRegistered,
}

impl RefusalReason {
    fn as_str(&self) -> &'static str {
        match self {
            Self::NoClientCert => "no_client_cert",
            Self::StateUnavailable => "state_unavailable",
            Self::NotRegistered => "not_registered",
        }
    }
}

fn refuse<B>(request: &http::Request<B>) -> axum::response::Response {
    if is_grpc_content_type(request.headers()) {
        tonic::Status::permission_denied("unknown validator").into_http()
    } else {
        axum::response::IntoResponse::into_response((
            http::StatusCode::FORBIDDEN,
            "unknown validator",
        ))
    }
}

pub(super) fn is_grpc_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get(&http::header::CONTENT_TYPE)
        .is_some_and(|header| {
            header
                .as_bytes()
                .starts_with(tonic::metadata::GRPC_CONTENT_TYPE.as_bytes())
        })
}

fn lookup_validator_address<B>(
    hashi: &Hashi,
    request: &http::Request<B>,
) -> Result<sui_sdk_types::Address, RefusalReason> {
    let tls_public_key = request
        .extensions()
        .get::<sui_http::PeerCertificates>()
        .and_then(|peer_certs| peer_certs.peer_certs().first())
        .and_then(|cert| crate::tls::public_key_from_certificate(cert).ok())
        .ok_or(RefusalReason::NoClientCert)?;
    hashi
        .onchain_state_opt()
        .ok_or(RefusalReason::StateUnavailable)?
        .state()
        .hashi()
        .committees
        .lookup_address_by_tls_public_key(&tls_public_key)
        .ok_or(RefusalReason::NotRegistered)
}
