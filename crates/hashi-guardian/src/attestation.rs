// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Enclave attestation. In enclave builds this talks to the AWS Nitro Secure
//! Module hardware; the `non-enclave-dev` feature and `cfg(test)` route to a
//! mock document instead.

use hashi_types::guardian::AttestationBindings;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::NitroAttestation;

#[cfg(not(any(test, feature = "non-enclave-dev")))]
use hashi_types::guardian::GuardianError;
#[cfg(any(test, not(feature = "non-enclave-dev")))]
use nsm_api::api::Request as NsmRequest;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use nsm_api::api::Response as NsmResponse;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use nsm_api::driver;
#[cfg(any(test, not(feature = "non-enclave-dev")))]
use serde_bytes::ByteBuf;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use tracing::error;
#[cfg(not(any(test, feature = "non-enclave-dev")))]
use tracing::info;

/// Commit to the enclave signing key and, for live queries, the info hash and nonce.
#[cfg(not(any(test, feature = "non-enclave-dev")))]
pub fn get_attestation(
    signing_pk: &GuardianPubKey,
    bindings: Option<&AttestationBindings>,
) -> GuardianResult<NitroAttestation> {
    info!("Initializing NSM driver.");
    let fd = driver::nsm_init();

    info!("Requesting attestation document from NSM.");
    let request = attestation_request(signing_pk, bindings);

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
pub fn get_attestation(
    _: &GuardianPubKey,
    _: Option<&AttestationBindings>,
) -> GuardianResult<NitroAttestation> {
    Ok(NitroAttestation::new(
        b"mock_attestation_document_hex".to_vec(),
    ))
}

#[cfg(any(test, not(feature = "non-enclave-dev")))]
fn attestation_request(
    signing_pk: &GuardianPubKey,
    bindings: Option<&AttestationBindings>,
) -> NsmRequest {
    NsmRequest::Attestation {
        public_key: Some(ByteBuf::from(signing_pk.to_bytes())),
        user_data: bindings.map(|b| ByteBuf::from(b.guardian_info_hash)),
        nonce: bindings.map(|b| ByteBuf::from(b.nonce)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::GuardianInfo;
    use hashi_types::guardian::GuardianSignKeyPair;

    #[test]
    fn live_nsm_request_binds_key_info_and_challenge() {
        let key = GuardianSignKeyPair::from([1; 32]).verification_key();
        let info = GuardianInfo::mock_for_testing();
        let bindings = AttestationBindings::new(&info, [9; 32]);
        let NsmRequest::Attestation {
            public_key,
            user_data,
            nonce,
        } = attestation_request(&key, Some(&bindings))
        else {
            panic!("expected attestation request")
        };
        assert_eq!(public_key.unwrap().as_ref(), key.to_bytes());
        assert_eq!(user_data.unwrap().as_ref(), info.digest());
        assert_eq!(nonce.unwrap().as_ref(), &[9; 32]);
    }

    #[test]
    fn operator_init_pin_has_no_live_query_bindings() {
        let key = GuardianSignKeyPair::from([1; 32]).verification_key();
        let NsmRequest::Attestation {
            public_key,
            user_data,
            nonce,
        } = attestation_request(&key, None)
        else {
            panic!("expected attestation request")
        };
        assert_eq!(public_key.unwrap().as_ref(), key.to_bytes());
        assert!(user_data.is_none());
        assert!(nonce.is_none());
    }
}
