use crate::Enclave;
use axum::extract::State;
use axum::Json;
use ed25519_consensus::VerificationKey;
use hashi_guardian_shared::*;
use std::sync::Arc;
use tracing::info;

// Only needed in non-test builds (for NSM hardware interaction)
#[cfg(not(test))]
use {
    crate::GuardianError,
    nsm_api::{
        api::{Request as NsmRequest, Response as NsmResponse},
        driver,
    },
    serde_bytes::ByteBuf,
    tracing::error,
};

/// Endpoint that returns an attestation committed to the enclave's signing public key
pub async fn get_attestation(
    State(enclave): State<Arc<Enclave>>,
) -> GuardianResult<Json<GetAttestationResponse>> {
    info!("/get_attestation - Received request");

    get_attestation_inner(&enclave.signing_pubkey())
        .map(|attestation| Json(GetAttestationResponse { attestation }))
}

#[cfg(not(test))]
pub fn get_attestation_inner(signing_pk: &VerificationKey) -> GuardianResult<Attestation> {
    let signing_pk_bytes = signing_pk.to_bytes();

    info!("Initializing NSM driver.");
    let fd = driver::nsm_init();

    info!("Requesting attestation document from NSM.");
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
            info!("Attestation document generated ({} bytes).", document.len());
            Ok(document)
        }
        _ => {
            driver::nsm_exit(fd);
            error!("Unexpected response from NSM.");
            Err(GuardianError::OpaqueError(
                "unexpected response".to_string(),
            ))
        }
    }
}

#[cfg(test)]
pub fn get_attestation_inner(_: &VerificationKey) -> GuardianResult<Attestation> {
    // Return a mock attestation for testing
    Ok("mock_attestation_document_hex".as_bytes().to_vec())
}
