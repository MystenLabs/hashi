// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared info handler for ordinary and attested queries in both enclave modes.

use crate::attestation::get_attestation;
use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Return signed guardian info, optionally attesting the enclave's signing public key.
pub async fn get_guardian_info(
    enclave: Arc<Enclave>,
    include_attestation: bool,
) -> GuardianResult<GetGuardianInfoResponse> {
    info!(include_attestation, "/get_guardian_info - Received request");

    let signing_pub_key = enclave.signing_pubkey();
    let attestation = if include_attestation {
        Some(get_attestation(&signing_pub_key)?)
    } else {
        None
    };
    Ok(GetGuardianInfoResponse::new(
        attestation,
        signing_pub_key,
        enclave.sign(enclave.info().await),
    ))
}
