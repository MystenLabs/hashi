// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_reader::BuildPolicy;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::WriteGenesisUntrustedRequest;
use std::sync::Arc;
use tracing::info;

/// Write the operator-trusted bootstrap committee at `genesis/record.json`.
///
/// This endpoint intentionally trusts the operator to source the committee from
/// onchain state during first deploy. The enclave only enforces the log
/// lifecycle: operator_init must have installed `InitConfig`, and no serving
/// committee source may already exist in S3.
pub async fn write_genesis_untrusted(
    enclave: Arc<Enclave>,
    request: WriteGenesisUntrustedRequest,
) -> GuardianResult<()> {
    let _guard = enclave.control_lock.lock().await;

    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs(
            "write_genesis_untrusted requires operator_init".into(),
        ));
    }

    let logger = enclave.config.s3_logger()?;
    let init_config = enclave
        .init_config()
        .ok_or_else(|| InvalidInputs("write_genesis_untrusted requires InitConfig".into()))?;
    let mut reader =
        GuardianReader::from_s3_client(logger.clone(), init_config.pcr_allowlist().clone());

    if reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await
        .map_err(|e| InvalidInputs(format!("read latest serving committee: {e}")))?
        .is_some()
    {
        return Err(InvalidInputs(
            "write_genesis_untrusted is rejected after a serving committee exists".into(),
        ));
    }

    let committee = request.into_committee();
    let epoch = committee.epoch;
    enclave.log_genesis(GenesisLogMessage { committee }).await?;
    info!(epoch, "genesis committee written");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_logger_with_layout;
    use crate::test_utils::OperatorInitTestArgs;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::HashiCommittee;

    fn mock_committee() -> HashiCommittee {
        HashiCommittee::new(vec![], 0, 3334, 800, 3333, 1)
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let enclave = Enclave::create_with_random_keys();
        let err =
            write_genesis_untrusted(enclave, WriteGenesisUntrustedRequest::new(mock_committee()))
                .await
                .unwrap_err();

        assert!(matches!(err, GuardianError::InvalidInputs(msg) if msg.contains("operator_init")));
    }

    #[tokio::test]
    async fn writes_when_no_genesis_or_committee_update_exists() {
        let logger = mock_logger_with_layout(vec![]);
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;

        write_genesis_untrusted(enclave, WriteGenesisUntrustedRequest::new(mock_committee()))
            .await
            .unwrap();
    }
}
