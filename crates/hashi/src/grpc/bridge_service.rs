use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::onchain::types::DepositRequest;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use hashi_types::proto::bridge_service_server::BridgeService;

use super::HttpService;

#[tonic::async_trait]
impl BridgeService for HttpService {
    /// Query the service for general information about its current state.
    async fn get_service_info(
        &self,
        _request: Request<GetServiceInfoRequest>,
    ) -> Result<Response<GetServiceInfoResponse>, Status> {
        Ok(Response::new(GetServiceInfoResponse::default()))
    }

    /// Validate and sign a confirmation of a bitcoin deposit request.
    async fn sign_deposit_confirmation(
        &self,
        request: Request<SignDepositConfirmationRequest>,
    ) -> Result<Response<SignDepositConfirmationResponse>, Status> {
        let deposit_request = parse_deposit_request(request.get_ref());
        let member_signature = self
            .inner
            .validate_and_sign_deposit_confirmation(&deposit_request)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(SignDepositConfirmationResponse {
            member_signature: Some(member_signature),
        }))
    }
}

fn parse_deposit_request(request: &SignDepositConfirmationRequest) -> DepositRequest {
    use sui_sdk_types::Address;

    let id = Address::from_bytes(&request.id).expect("invalid id");
    let txid = Address::from_bytes(&request.txid).expect("invalid txid");
    let derivation_path = request
        .derivation_path
        .as_ref()
        .map(|bytes| Address::from_bytes(bytes).expect("invalid derivation_path"));

    DepositRequest {
        id,
        utxo: Utxo {
            id: UtxoId {
                txid,
                vout: request.vout,
            },
            amount: request.amount,
            derivation_path,
        },
        timestamp_ms: request.timestamp_ms,
    }
}
