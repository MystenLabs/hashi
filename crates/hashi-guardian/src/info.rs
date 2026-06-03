// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `get_guardian_info` RPC handler. Enabled in both ceremony and withdraw modes.

use crate::attestation::get_attestation;
use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Endpoint that returns an attestation committed to the enclave's signing public key
pub async fn get_guardian_info(enclave: Arc<Enclave>) -> GuardianResult<GetGuardianInfoResponse> {
    info!("/get_guardian_info - Received request");

    let signing_pub_key = enclave.signing_pubkey();
    let attestation = get_attestation(&signing_pub_key)?;
    Ok(GetGuardianInfoResponse {
        attestation,
        signing_pub_key,
        signed_info: enclave.sign(enclave.info().await),
        encrypted_shares: enclave.latest_encrypted_shares(),
    })
}
