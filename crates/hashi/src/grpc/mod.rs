use std::sync::Arc;

use sui_futures::service::Service;
use sui_http::ServerHandle;
use tower::ServiceBuilder;

use crate::Hashi;

mod client;
pub use client::Client;

pub mod bridge_service;
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

    pub async fn start(self) -> (std::net::SocketAddr, Service) {
        let router = {
            let bridge_service =
                hashi_types::proto::bridge_service_server::BridgeServiceServer::new(self.clone());
            let mpc_service =
                hashi_types::proto::mpc_service_server::MpcServiceServer::new(self.clone());

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

        let health_endpoint = axum::Router::new().route("/health", axum::routing::get(health));

        let layers = ServiceBuilder::new()
            // Add middleware for mapping a request to a known validator
            .map_request(lookup_validator_middleware(self.inner.clone()))
            .layer(sui_http::middleware::callback::CallbackLayer::new(
                crate::metrics::RpcMetricsMakeCallbackHandler::new(self.inner.metrics.clone()),
            ));

        let router = router.merge(health_endpoint).layer(layers);

        let tls_config =
            crate::tls::make_server_config(self.inner.config.tls_private_key().unwrap());
        // let tls_config =
        //     crate::tls_rpk::make_server_config(self.inner.config.tls_private_key().unwrap());

        let server_handle = Arc::new(
            sui_http::Builder::new()
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

    pub fn signing_manager(&self) -> Arc<std::sync::RwLock<crate::mpc::SigningManager>> {
        self.inner.signing_manager()
    }

    pub fn btc_monitor(&self) -> &crate::btc_monitor::monitor::MonitorClient {
        self.inner.btc_monitor()
    }

    pub fn get_reconfig_signature(&self, epoch: u64) -> Option<Vec<u8>> {
        self.inner.get_reconfig_signature(epoch)
    }
}

async fn health() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::OK, "up")
}

trait RouterExt {
    /// Add a new grpc service.
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
    /// Add a new grpc service.
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

// Given a TLS client cert, pull out the ed25519 public key and map it to a validator
fn lookup_validator_middleware<B>(
    hashi: Arc<Hashi>,
) -> impl Fn(axum::http::Request<B>) -> axum::http::Request<B> + Clone {
    move |mut request| {
        if let Some(validator_address) = lookup_validator_address(&hashi, &request) {
            request.extensions_mut().insert(validator_address);
        }
        request
    }
}

fn lookup_validator_address<B>(
    hashi: &Hashi,
    request: &axum::http::Request<B>,
) -> Option<sui_sdk_types::Address> {
    let peer_certs = request.extensions().get::<sui_http::PeerCertificates>()?;
    let cert = peer_certs.peer_certs().first()?;
    let tls_public_key = crate::tls::public_key_from_certificate(cert).ok()?;
    hashi
        .onchain_state_opt()?
        .state()
        .hashi()
        .committees
        .lookup_address_by_tls_public_key(&tls_public_key)
}
