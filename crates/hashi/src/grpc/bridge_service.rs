use anyhow::Context;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::onchain::types::DepositRequest;
use crate::onchain::types::OutputUtxo;
use crate::onchain::types::Utxo;
use crate::onchain::types::UtxoId;
use crate::withdrawals::WithdrawalApproval;
use hashi_types::proto::GetServiceInfoRequest;
use hashi_types::proto::GetServiceInfoResponse;
use hashi_types::proto::SignDepositConfirmationRequest;
use hashi_types::proto::SignDepositConfirmationResponse;
use hashi_types::proto::SignWithdrawalApprovalRequest;
use hashi_types::proto::SignWithdrawalApprovalResponse;
use hashi_types::proto::SignWithdrawalConfirmationRequest;
use hashi_types::proto::SignWithdrawalConfirmationResponse;
use hashi_types::proto::SignWithdrawalTransactionRequest;
use hashi_types::proto::SignWithdrawalTransactionResponse;
use hashi_types::proto::bridge_service_server::BridgeService;
use sui_sdk_types::Address;

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
        authenticate_caller(&request)?;
        let deposit_request = parse_deposit_request(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let member_signature = self
            .inner
            .validate_and_sign_deposit_confirmation(&deposit_request)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(SignDepositConfirmationResponse {
            member_signature: Some(member_signature),
        }))
    }

    async fn sign_withdrawal_approval(
        &self,
        request: Request<SignWithdrawalApprovalRequest>,
    ) -> Result<Response<SignWithdrawalApprovalResponse>, Status> {
        authenticate_caller(&request)?;
        let approval = parse_withdrawal_approval(request.get_ref())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let member_signature = self
            .inner
            .validate_and_sign_withdrawal_approval(&approval)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(SignWithdrawalApprovalResponse {
            member_signature: Some(member_signature),
        }))
    }

    async fn sign_withdrawal_transaction(
        &self,
        request: Request<SignWithdrawalTransactionRequest>,
    ) -> Result<Response<SignWithdrawalTransactionResponse>, Status> {
        authenticate_caller(&request)?;
        let pending_withdrawal_id = Address::from_bytes(&request.get_ref().pending_withdrawal_id)
            .map_err(|e| {
            Status::invalid_argument(format!("invalid pending_withdrawal_id: {e}"))
        })?;
        let partial_signature = self
            .inner
            .validate_and_sign_withdrawal_tx(&pending_withdrawal_id)
            .await
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(SignWithdrawalTransactionResponse {
            partial_signature: Some(partial_signature.into()),
        }))
    }

    async fn sign_withdrawal_confirmation(
        &self,
        request: Request<SignWithdrawalConfirmationRequest>,
    ) -> Result<Response<SignWithdrawalConfirmationResponse>, Status> {
        authenticate_caller(&request)?;
        let pending_withdrawal_id = Address::from_bytes(&request.get_ref().pending_withdrawal_id)
            .map_err(|e| {
            Status::invalid_argument(format!("invalid pending_withdrawal_id: {e}"))
        })?;
        let member_signature = self
            .inner
            .sign_withdrawal_confirmation(&pending_withdrawal_id)
            .map_err(|e| Status::failed_precondition(e.to_string()))?;
        Ok(Response::new(SignWithdrawalConfirmationResponse {
            member_signature: Some(member_signature),
        }))
    }
}

fn authenticate_caller<T>(request: &Request<T>) -> Result<Address, Status> {
    request
        .extensions()
        .get::<Address>()
        .copied()
        .ok_or_else(|| Status::permission_denied("unknown validator"))
}

fn parse_deposit_request(
    request: &SignDepositConfirmationRequest,
) -> anyhow::Result<DepositRequest> {
    let id = parse_address(&request.id)?;
    let txid = parse_address(&request.txid)?;
    let derivation_path = request
        .derivation_path
        .as_ref()
        .map(|bytes| parse_address(bytes))
        .transpose()?;

    Ok(DepositRequest {
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
    })
}

fn parse_withdrawal_approval(
    request: &SignWithdrawalApprovalRequest,
) -> anyhow::Result<WithdrawalApproval> {
    let request_ids: Vec<Address> = request
        .request_ids
        .iter()
        .map(|bytes| parse_address(bytes))
        .collect::<anyhow::Result<_>>()?;
    let selected_utxos: Vec<UtxoId> = request
        .selected_utxos
        .iter()
        .map(|utxo_id| {
            let txid = utxo_id
                .txid
                .as_ref()
                .map(|bytes| parse_address(bytes))
                .context("missing utxo txid")??;
            let vout = utxo_id.vout.context("missing utxo vout")?;
            Ok(UtxoId { txid, vout })
        })
        .collect::<anyhow::Result<_>>()?;
    let outputs = request
        .outputs
        .iter()
        .map(|output| OutputUtxo {
            amount: output.amount,
            bitcoin_address: output.bitcoin_address.to_vec(),
        })
        .collect();
    let txid = parse_address(&request.txid)?;

    Ok(WithdrawalApproval {
        request_ids,
        selected_utxos,
        outputs,
        txid,
    })
}

fn parse_address(bytes: &[u8]) -> anyhow::Result<sui_sdk_types::Address> {
    sui_sdk_types::Address::from_bytes(bytes).context("invalid address")
}
