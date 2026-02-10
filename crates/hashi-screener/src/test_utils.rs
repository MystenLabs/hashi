//! Test utilities for spinning up a mock screener gRPC server.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use hashi_types::proto::screener::ApproveRequest;
use hashi_types::proto::screener::ApproveResponse;
use hashi_types::proto::screener::screener_service_server::ScreenerService;
use hashi_types::proto::screener::screener_service_server::ScreenerServiceServer;
use sui_futures::service::Service;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Server;

/// A mock screener service that auto-approves all requests.
pub struct MockScreenerService;

#[tonic::async_trait]
impl ScreenerService for MockScreenerService {
    async fn approve(
        &self,
        _request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        Ok(Response::new(ApproveResponse { approved: true }))
    }
}

/// A configurable mock that rejects requests involving blocked addresses.
pub struct ConfigurableMockScreenerService {
    pub blocked_addresses: Arc<HashSet<String>>,
}

#[tonic::async_trait]
impl ScreenerService for ConfigurableMockScreenerService {
    async fn approve(
        &self,
        request: Request<ApproveRequest>,
    ) -> Result<Response<ApproveResponse>, Status> {
        let req = request.into_inner();
        let approved = !self.blocked_addresses.contains(&req.destination_address);
        Ok(Response::new(ApproveResponse { approved }))
    }
}

/// Start a mock screener gRPC server that auto-approves all requests.
/// Returns the address and a handle to abort the server.
pub async fn start_mock_screener_server() -> (SocketAddr, Service) {
    start_screener_server_impl(ScreenerServiceServer::new(MockScreenerService)).await
}

/// Start a configurable mock screener gRPC server that rejects blocked addresses.
pub async fn start_configurable_mock_screener_server(
    blocked_addresses: HashSet<String>,
) -> (SocketAddr, Service) {
    let service = ConfigurableMockScreenerService {
        blocked_addresses: Arc::new(blocked_addresses),
    };
    start_screener_server_impl(ScreenerServiceServer::new(service)).await
}

async fn start_screener_server_impl(
    service: ScreenerServiceServer<impl ScreenerService>,
) -> (SocketAddr, Service) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let service = Service::new().spawn_aborting(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await?;
        Ok(())
    });

    // Brief pause to let the server start accepting connections
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (addr, service)
}
