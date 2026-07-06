// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_client::GuardianS3Client;
use crate::Enclave;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::WriteGenesisUntrustedRequest;
use hashi_types::guardian::S3_DIR_COMMITTEE_UPDATE;
use hashi_types::move_types::Committee;
use std::sync::Arc;
use tracing::info;

/// Write the operator-trusted bootstrap committee at `genesis/record.json`.
///
/// This endpoint intentionally trusts the operator to source the committee from
/// onchain state during first deploy. The enclave only enforces the log
/// lifecycle: operator_init must have installed S3, no committee-update may
/// exist yet, and the fixed genesis key is idempotent.
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
    reject_after_committee_update(logger).await?;

    let committee = request.into_committee();
    match read_existing_genesis(logger).await? {
        Some(existing) if existing == committee => {
            info!(
                epoch = committee.epoch,
                "genesis committee already written; treating write_genesis_untrusted as idempotent"
            );
            Ok(())
        }
        Some(existing) => Err(InvalidInputs(format!(
            "existing genesis committee epoch {} does not match requested epoch {}",
            existing.epoch, committee.epoch
        ))),
        None => {
            let epoch = committee.epoch;
            enclave.log_genesis(GenesisLogMessage { committee }).await?;
            info!(epoch, "genesis committee written");
            Ok(())
        }
    }
}

async fn reject_after_committee_update(logger: &GuardianS3Client) -> GuardianResult<()> {
    let keys = logger
        .list_all_keys_in_dir(&format!("{}/", S3_DIR_COMMITTEE_UPDATE))
        .await?;
    if keys
        .iter()
        .any(|key| !key.starts_with(&format!("{}/failure-", S3_DIR_COMMITTEE_UPDATE)))
    {
        return Err(InvalidInputs(
            "write_genesis_untrusted is rejected after committee-update exists".into(),
        ));
    }
    Ok(())
}

async fn read_existing_genesis(logger: &GuardianS3Client) -> GuardianResult<Option<Committee>> {
    let key = GenesisLogMessage::object_key();
    let keys = logger.list_all_keys_in_dir(&key).await?;
    if keys.is_empty() {
        return Ok(None);
    }
    if keys != [key.clone()] {
        return Err(InvalidInputs(format!(
            "expected exactly one genesis record at {key}, found {keys:?}"
        )));
    }

    let record = logger.get_log_record(&key).await?;
    match record.message {
        LogMessage::Genesis(msg) => Ok(Some(msg.committee)),
        _ => Err(InvalidInputs(format!("expected a genesis log at {key}"))),
    }
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

    #[tokio::test]
    async fn rejects_after_committee_update_exists() {
        let logger = mock_logger_with_layout(vec![
            "committee-update/00000000000000000001-session.json".to_string(),
        ]);
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;

        let err =
            write_genesis_untrusted(enclave, WriteGenesisUntrustedRequest::new(mock_committee()))
                .await
                .unwrap_err();

        assert!(
            matches!(err, GuardianError::InvalidInputs(msg) if msg.contains("committee-update"))
        );
    }
}
