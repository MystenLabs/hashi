// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

// Only needed in enclave builds (for NSM hardware interaction).
// The `non-enclave-dev` feature and `cfg(test)` both route to the stub below.
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use hashi_types::guardian::GuardianError;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use nsm_api::api::Request as NsmRequest;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use nsm_api::api::Response as NsmResponse;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use nsm_api::driver;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use serde_bytes::ByteBuf;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use tracing::error;

/// Endpoint that returns an attestation committed to the enclave's signing public key
pub async fn get_guardian_info(enclave: Arc<Enclave>) -> GuardianResult<GetGuardianInfoResponse> {
    info!("/get_guardian_info - Received request");

    let signing_pub_key = enclave.signing_pubkey();
    let attestation = get_attestation(&signing_pub_key)?;
    Ok(GetGuardianInfoResponse {
        attestation,
        signing_pub_key,
        signed_info: enclave.sign(enclave.info()),
    })
}

#[cfg(not(any(test, feature = "non-enclave-dev")))]
pub fn get_attestation(signing_pk: &GuardianPubKey) -> GuardianResult<Attestation> {
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

#[cfg(any(test, feature = "non-enclave-dev"))]
pub fn get_attestation(_: &GuardianPubKey) -> GuardianResult<Attestation> {
    Ok(b"mock_attestation_document_hex".to_vec())
}
