use crate::s3_logger::test_s3_connectivity;
use crate::Enclave;
use crate::GuardianError;
use axum::extract::State;
use axum::Json;
use hashi_guardian_shared::*;
use hpke::Serializable;
use nsm_api::api::Request as NsmRequest;
use nsm_api::api::Response as NsmResponse;
use nsm_api::driver;
use serde_bytes::ByteBuf;
use std::sync::Arc;
use tracing::error;
use tracing::info;

/// Health check endpoint that returns server health status (lightweight, unsigned)
pub async fn health_check(State(enclave): State<Arc<Enclave>>) -> Json<HealthCheckResponse> {
    info!("🏥 /health_check - Received request");

    let btc_key_configured = enclave.btc_key().is_ok();

    let s3_configured = {
        match enclave.s3_logger() {
            Ok(logger) => (test_s3_connectivity(logger).await).is_ok(),
            Err(_) => false,
        }
    };

    let shares_received = enclave.decrypted_shares().lock().await.len();

    info!("   S3 configured: {}", s3_configured);
    info!("   BTC key configured: {}", btc_key_configured);
    info!("   Shares received: {}/{}", shares_received, THRESHOLD);

    Json(HealthCheckResponse {
        s3_configured,
        btc_key_configured,
        shares_received,
    })
}

/// Get enclave public information (keys, commitments) - signed for authenticity
pub async fn get_enclave_info(State(enclave): State<Arc<Enclave>>) -> Json<Signed<EnclaveInfoResponse>> {
    info!("🔑 /get_enclave_info - Received request");

    let enc_public_key = enclave.encryption_public_key().to_bytes().to_vec();
    let signing_verification_key = enclave.signing_keypair().verification_key().to_bytes().to_vec();
    let share_commitments = enclave.share_commitments().ok().cloned();

    info!("   Encryption public key: {} bytes", enc_public_key.len());
    info!("   Signing verification key: {} bytes", signing_verification_key.len());
    info!("   Share commitments: {:?}", share_commitments.is_some());

    Json(enclave.sign(EnclaveInfoResponse {
        enc_public_key,
        signing_verification_key,
        share_commitments,
    }))
}

/// Endpoint that returns an attestation committed to the enclave's signing public key
pub async fn get_attestation(
    State(enclave): State<Arc<Enclave>>,
) -> Result<Json<GetAttestationResponse>, GuardianError> {
    info!("📜 /get_attestation - Received request");

    let signing_pk_bytes = enclave.signing_keypair().verification_key().to_bytes();

    info!("Initializing NSM driver...");
    let fd = driver::nsm_init();

    info!("Requesting attestation document from NSM...");
    // Send attestation request to NSM driver with public key set.
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(ByteBuf::from(signing_pk_bytes)),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            info!("Attestation document generated ({} bytes)", document.len());
            info!("Sending attestation to client");
            Ok(Json(GetAttestationResponse {
                attestation: hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            error!("Unexpected response from NSM");
            Err(GuardianError::OpaqueError(
                "unexpected response".to_string(),
            ))
        }
    }
}
