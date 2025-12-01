use std::sync::Arc;

use crate::Hashi;

pub mod bridge_service;

#[derive(Clone)]
pub struct HttpService {
    inner: Arc<Hashi>,
}

impl HttpService {
    pub fn new(hashi: Arc<Hashi>) -> Self {
        Self { inner: hashi }
    }

    pub async fn start(self) -> sui_http::ServerHandle {
        let router = {
            let bridge_service =
                crate::proto::bridge_service_server::BridgeServiceServer::new(self.clone());

            let (health_reporter, health_service) = tonic_health::server::health_reporter();

            let mut reflection_v1 = tonic_reflection::server::Builder::configure();
            let mut reflection_v1alpha = tonic_reflection::server::Builder::configure();

            for file_descriptor_set in [
                sui_rpc::proto::google::protobuf::FILE_DESCRIPTOR_SET,
                sui_rpc::proto::google::rpc::FILE_DESCRIPTOR_SET,
                tonic_health::pb::FILE_DESCRIPTOR_SET,
                crate::proto::FILE_DESCRIPTOR_SET,
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
                service_name(&reflection_v1),
                service_name(&reflection_v1alpha),
            ] {
                health_reporter
                    .set_service_status(service_name, tonic_health::ServingStatus::Serving)
                    .await;
            }

            axum::Router::new()
                .add_grpc_service(bridge_service)
                .add_grpc_service(reflection_v1)
                .add_grpc_service(reflection_v1alpha)
                .add_grpc_service(health_service)
        };

        let health_endpoint = axum::Router::new().route("/health", axum::routing::get(health));

        let router = router.merge(health_endpoint).layer(
            sui_http::middleware::callback::CallbackLayer::new(
                crate::metrics::RpcMetricsMakeCallbackHandler::new(self.inner.metrics.clone()),
            ),
        );

        let tls_config =
            crate::tls::make_server_config(self.inner.config.tls_private_key().unwrap());
        // let tls_config =
        //     crate::tls_rpk::make_server_config(self.inner.config.tls_private_key().unwrap());
        sui_http::Builder::new()
            .tls_config(tls_config)
            .serve(self.inner.config.https_address(), router)
            .unwrap()
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
