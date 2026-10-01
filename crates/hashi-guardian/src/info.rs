// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared info handler for ordinary and attested queries in both enclave modes.

use crate::attestation::get_attestation;
use crate::Enclave;
use hashi_types::guardian::*;
use std::sync::Arc;
use tracing::info;

/// Return self-reported guardian info without signing or attesting it.
pub async fn get_guardian_info(
    enclave: Arc<Enclave>,
    _request: (),
) -> GuardianResult<GuardianResponse<GuardianInfo>> {
    info!("/get_guardian_info - Received request");
    Ok(GuardianResponse::new(
        enclave.info().await,
        now_timestamp_ms(),
    ))
}

/// Return signed guardian info with a fresh attestation of its signing key.
pub async fn get_attested_guardian_info(
    enclave: Arc<Enclave>,
    _request: (),
) -> GuardianResult<AttestedGuardianInfo> {
    info!("/get_attested_guardian_info - Received request");
    let signing_pub_key = enclave.signing_pubkey();
    let attestation = get_attestation(&signing_pub_key)?;
    Ok(AttestedGuardianInfo::new(
        attestation,
        enclave.sign(enclave.info().await),
    ))
}
