// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Enclave attestation. In enclave builds this talks to the AWS Nitro Secure
//! Module hardware; the `non-enclave-dev` feature and `cfg(test)` route to a
//! mock document instead.

use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::NitroAttestation;

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
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use tracing::info;

/// Returns an attestation document committed to the enclave's signing public key.
#[cfg(not(any(test, feature = "non-enclave-dev")))]
pub fn get_attestation(signing_pk: &GuardianPubKey) -> GuardianResult<NitroAttestation> {
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
            Ok(NitroAttestation::new(document))
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
pub fn get_attestation(signing_pk: &GuardianPubKey) -> GuardianResult<NitroAttestation> {
    // No NSM off-enclave to produce a real document, so emit a mock binding the
    // signing key + an all-zero PCR0. A `non-enclave-dev` `verify` checks that
    // binding (`verify_mock_attestation`) in place of the COSE signature.
    Ok(NitroAttestation::mock(signing_pk, &[0u8; 48]))
}
