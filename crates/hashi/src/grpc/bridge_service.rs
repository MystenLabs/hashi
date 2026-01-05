use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::onchain::types::DepositRequest;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::proto::GetServiceInfoRequest;
use crate::proto::GetServiceInfoResponse;
use crate::proto::SignDepositConfirmationRequest;
use crate::proto::SignDepositConfirmationResponse;
use crate::proto::bridge_service_server::BridgeService;

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
        let deposit_request = request.get_ref().parse_deposit_request();
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

impl SignDepositConfirmationRequest {
    fn parse_deposit_request(&self) -> DepositRequest {
        use sui_sdk_types::Address;

        let id = Address::from_bytes(&self.id).expect("invalid id");
        let txid = Address::from_bytes(&self.txid).expect("invalid txid");
        let derivation_path = self
            .derivation_path
            .as_ref()
            .map(|bytes| Address::from_bytes(bytes).expect("invalid derivation_path"));

        DepositRequest {
            id,
            utxo: Utxo {
                id: UtxoId {
                    txid,
                    vout: self.vout,
                },
                amount: self.amount,
                derivation_path,
            },
            timestamp_ms: self.timestamp_ms,
        }
    }
}
