// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::s3_reader::BuildPolicy;
use crate::s3_reader::GuardianReader;
use crate::Enclave;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::OperatorWriteGenesisRequest;
use hashi_types::guardian::WithdrawStage;
use tracing::info;

/// Write the operator-trusted bootstrap committee at `genesis/record.json`.
///
/// This endpoint intentionally trusts the operator to source the committee from
/// on-chain state during first deploy. The enclave enforces only the log
/// lifecycle: operator_init must have installed S3/config, and no prior serving
/// committee may already exist in `committee-update/` or `genesis/`.
pub async fn operator_write_genesis(
    enclave: Arc<Enclave>,
    request: OperatorWriteGenesisRequest,
) -> GuardianResult<()> {
    let _guard = enclave.control_lock.lock().await;

    enclave.require_lifecycle(WithdrawStage::OperatorInitialized.into())?;

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
            "operator_write_genesis is rejected after a serving committee exists".into(),
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

    fn mock_move_committee() -> hashi_types::move_types::Committee {
        hashi_types::move_types::Committee {
            epoch: 0,
            members: vec![],
            total_weight: 0,
            config: hashi_types::move_types::Config::default(),
        }
    }

    fn mock_request() -> OperatorWriteGenesisRequest {
        OperatorWriteGenesisRequest::from_move_committee(mock_move_committee())
    }

    #[tokio::test]
    async fn rejects_before_operator_init() {
        let enclave = Enclave::create_with_random_keys();
        let err = operator_write_genesis(enclave, mock_request())
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            GuardianError::InvalidInputs(msg)
                if msg.contains("Withdraw(OperatorInitialized)")
                    && msg.contains("Withdraw(Uninitialized)")
        ));
    }

    #[tokio::test]
    async fn writes_when_no_committee_exists() {
        let logger = mock_logger_with_layout(vec![]);
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;

        operator_write_genesis(enclave, mock_request())
            .await
            .unwrap();
    }
}
