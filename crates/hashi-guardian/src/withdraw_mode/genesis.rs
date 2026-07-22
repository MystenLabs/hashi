// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_reader::BuildPolicy;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;

/// Preserve the existing genesis guard: a first-deploy PI may write genesis only
/// while no serving committee exists in `committee-update/` or `genesis/`.
pub(super) async fn ensure_no_serving_committee(enclave: &Enclave) -> GuardianResult<()> {
    let init_config = enclave
        .init_config()
        .ok_or_else(|| InvalidInputs("InitConfig not set".into()))?
        .clone();
    let logger = enclave.config.s3_logger()?.clone();
    let mut reader = GuardianReader::from_s3_client(logger, init_config.pcr_allowlist().clone());

    if reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await
        .map_err(|e| InvalidInputs(format!("read latest committee before genesis write: {e}")))?
        .is_some()
    {
        return Err(InvalidInputs(
            "genesis bootstrap is rejected after a serving committee exists".into(),
        ));
    }

    Ok(())
}
