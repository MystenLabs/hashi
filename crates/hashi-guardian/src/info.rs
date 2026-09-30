// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ordinary and attested info handlers, available in both enclave modes.

use crate::attestation::get_attestation;
use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Return signed guardian info without generating an attestation.
pub async fn get_guardian_info(enclave: Arc<Enclave>) -> GuardianResult<GetGuardianInfoResponse> {
    info!("/get_guardian_info - Received request");

    Ok(GetGuardianInfoResponse::new(
        None,
        enclave.signing_pubkey(),
        enclave.sign(enclave.info().await),
    ))
}

/// Bind signed guardian info and the caller's nonce into a fresh attestation.
pub async fn get_attested_guardian_info(
    enclave: Arc<Enclave>,
    nonce: AttestationNonce,
) -> GuardianResult<GetGuardianInfoResponse> {
    info!("/get_attested_guardian_info - Received request");

    let signing_pub_key = enclave.signing_pubkey();
    // Attest and sign the same snapshot, including fields updated by withdrawals.
    let info = enclave.info().await;
    let attestation = get_attestation(
        &signing_pub_key,
        Some(&AttestationBindings::new(&info, nonce)),
    )?;
    Ok(GetGuardianInfoResponse::new(
        Some(attestation),
        signing_pub_key,
        enclave.sign(info),
    ))
}
