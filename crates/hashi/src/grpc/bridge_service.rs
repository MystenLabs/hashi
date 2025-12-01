use crate::proto::GetServiceInfoRequest;
use crate::proto::GetServiceInfoResponse;
use crate::proto::bridge_service_server::BridgeService;

use super::HttpService;

#[tonic::async_trait]
impl BridgeService for HttpService {
    /// Query the service for general information about its current state.
    async fn get_service_info(
        &self,
        _request: tonic::Request<GetServiceInfoRequest>,
    ) -> Result<tonic::Response<GetServiceInfoResponse>, tonic::Status> {
        Ok(tonic::Response::new(GetServiceInfoResponse::default()))
    }
}
