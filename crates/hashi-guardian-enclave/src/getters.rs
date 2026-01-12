use crate::Enclave;
use ed25519_consensus::VerificationKey;
use hashi_guardian_shared::*;
use std::sync::Arc;
use tracing::info;

// Only needed in non-test builds (for NSM hardware interaction)
#[cfg(not(test))]
use crate::GuardianError;
#[cfg(not(test))]
use nsm_api::api::Request as NsmRequest;
#[cfg(not(test))]
use nsm_api::api::Response as NsmResponse;
#[cfg(not(test))]
use nsm_api::driver;
#[cfg(not(test))]
use serde_bytes::ByteBuf;
#[cfg(not(test))]
use tracing::error;

/// Endpoint that returns an attestation committed to the enclave's signing public key
pub async fn get_guardian_info(enclave: Arc<Enclave>) -> GuardianResult<GetGuardianInfoResponse> {
    info!("/get_guardian_info - Received request");

    let attestation = get_attestation(&enclave.signing_pubkey())?;

    Ok(GetGuardianInfoResponse {
        attestation,
        server_version: "v1".to_string(),
    })
}

#[cfg(not(test))]
pub fn get_attestation(signing_pk: &VerificationKey) -> GuardianResult<Attestation> {
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
            Err(GuardianError::InternalError(
                "unexpected response".to_string(),
            ))
        }
    }
}

#[cfg(test)]
pub fn get_attestation(_: &VerificationKey) -> GuardianResult<Attestation> {
    // Return a mock attestation for testing
    Ok("mock_attestation_document_hex".as_bytes().to_vec())
}
