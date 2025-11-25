use crate::Enclave;
use crate::GuardianError;
use axum::extract::State;
use axum::Json;
use fastcrypto::encoding::Encoding;
use fastcrypto::encoding::Hex;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::ToFromBytes;
use hashi_guardian_shared::GetAttestationResponse;
use hpke::Serializable;
use nsm_api::api::Request as NsmRequest;
use nsm_api::api::Response as NsmResponse;
use nsm_api::driver;
use serde_bytes::ByteBuf;
use std::sync::Arc;
use tracing::error;
use tracing::info;

/// Endpoint that returns an attestation committed
/// to the enclave's public key.
pub async fn get_attestation(
    State(enclave): State<Arc<Enclave>>,
) -> Result<Json<GetAttestationResponse>, GuardianError> {
    info!("📥 /get_attestation - Received request");

    let signing_pk_bytes = enclave.signing_keypair().public().as_bytes();
    let enc_pk_bytes = enclave.encryption_public_key().to_bytes();

    info!("🔐 Initializing NSM driver...");
    let fd = driver::nsm_init();

    info!("📜 Requesting attestation document from NSM...");
    // Send attestation request to NSM driver with public key set.
    let request = NsmRequest::Attestation {
        user_data: Some(ByteBuf::from(enc_pk_bytes.to_vec())),
        nonce: None,
        public_key: Some(ByteBuf::from(signing_pk_bytes)),
    };

    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            info!(
                "✅ Attestation document generated ({} bytes)",
                document.len()
            );
            info!("📤 Sending attestation to client");
            Ok(Json(GetAttestationResponse {
                attestation: Hex::encode(document),
            }))
        }
        _ => {
            driver::nsm_exit(fd);
            error!("❌ Unexpected response from NSM");
            Err(GuardianError::GenericError(
                "unexpected response".to_string(),
            ))
        }
    }
}
