// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared info handler for ordinary and attested queries in both enclave modes.

use crate::attestation::get_attestation;
use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Return signed info, optionally binding it and the caller's nonce into an attestation.
pub async fn get_guardian_info(
    enclave: Arc<Enclave>,
    nonce: Option<AttestationNonce>,
) -> GuardianResult<GetGuardianInfoResponse> {
    info!(
        include_attestation = nonce.is_some(),
        "/get_guardian_info - Received request"
    );

    let signing_pub_key = enclave.signing_pubkey();
    // Attest and sign the same snapshot, including fields updated by withdrawals.
    let info = enclave.info().await;
    let attestation = nonce
        .map(|nonce| {
            get_attestation(
                &signing_pub_key,
                Some(&AttestationBindings::new(&info, nonce)),
            )
        })
        .transpose()?;
    Ok(GetGuardianInfoResponse::new(
        attestation,
        signing_pub_key,
        enclave.sign(info),
    ))
}
