// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recover the limiter state for standby enclave activation from Guardian S3 withdrawal logs.
//!
//! Each withdrawal log contains the limiter `post_state` after that withdrawal consumes tokens.
//! The withdrawal sequence number always increases, including across rotations.
//! The log with the highest sequence number contains the latest limiter state.
//!
//! The search uses four directory levels: `withdraw/YYYY/MM/DD/HH/`.
//! At each level, it lists `CommonPrefixes` and searches the directories from highest to lowest numeric value.
//! It stops at the first hour directory that contains a withdrawal key.
//! Recovery reads that directory and the directory for the previous hour.
//! This includes logs that a clock difference of less than one hour can place in the previous directory.
//! Recovery selects the withdrawal with the highest sequence number from both directories.
//!
//! Recovery reads the latest directory immediately. It does not wait for `write_completion_time`.
//! The auditor waits for that time because a live session can still write to the directory.
//! Recovery cannot wait, because the latest directory is usually the current hour.
//! For the current hour, that time can be 70 minutes away (`MAX_DIR_COMPLETION_LAG`).
//! Instead, the caller must first verify the heartbeat quiet period for all other sessions.
//! We assume that after the quiet period, no other session can write a withdrawal log.

use super::GuardianReader;
use super::VerifiedLogEntry;
use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::s3::S3NumericDirectory;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::VersionedLogMessage;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use tracing::info;

impl GuardianReader {
    /// Recover the limiter state for activation from withdrawal logs.
    /// Use the `post_state` from the withdrawal with the highest sequence number.
    /// Use the genesis limiter state if no withdrawal log exists.
    /// Limit the available tokens to the configured capacity in case the capacity decreased.
    ///
    /// Before this call, use [`Self::ensure_session_live_and_others_quiet`] to verify that all other sessions completed the required quiet period.
    pub async fn recover_limiter_state(
        &mut self,
        limiter_config: &LimiterConfig,
    ) -> GuardianResult<LimiterState> {
        let Some(mut cursor) = find_latest_withdrawal_bucket(&self.s3).await? else {
            // The search covers the complete S3 withdrawal history, so this
            // branch is reachable only if no withdrawal has ever succeeded.
            info!("no withdrawal logs found; using genesis limiter state");
            return Ok(LimiterState::genesis(limiter_config));
        };

        info!(
            latest_directory = %cursor,
            previous_directory = %cursor.prev_dir(),
            "Reading withdrawal logs for limiter recovery"
        );

        // Read the found bucket + one bucket back, then take max-seq across
        // both. The peek-back defends against sub-hour clock skew that may have
        // placed a higher-seq log in the prior hour bucket.
        let hit = bucket_max_post_state(self.read_logs_in_dir(&cursor).await?)?;
        cursor = cursor.prev_dir();
        let peek = bucket_max_post_state(self.read_logs_in_dir(&cursor).await?)?;
        let recovered_state = [hit, peek]
            .into_iter()
            .flatten()
            .max_by_key(|s| s.next_seq)
            .ok_or_else(|| {
                InvalidS3Log(
                    "latest withdrawal bucket contained no verified withdrawal logs".into(),
                )
            })?;
        let state = recovered_state.capped_to(limiter_config);
        info!(
            next_seq = state.next_seq,
            last_updated_at = state.last_updated_at,
            recovered_num_tokens_available = recovered_state.num_tokens_available,
            capped_num_tokens_available = state.num_tokens_available,
            "recovered limiter state from withdrawal logs"
        );
        Ok(state)
    }
}

/// Find the latest hour directory under `withdraw/` that contains a withdrawal key.
/// Search the YYYY/MM/DD/HH directories from highest to lowest numeric value at each level.
/// Return `None` if no withdrawal log exists.
async fn find_latest_withdrawal_bucket(
    s3_client: &GuardianS3Client,
) -> GuardianResult<Option<S3HourDirectory>> {
    let root = format!("{}/", S3_DIR_WITHDRAW);
    for year in list_subdirs_desc(s3_client, &root).await? {
        for month in list_subdirs_desc(s3_client, &year).await? {
            for day in list_subdirs_desc(s3_client, &month).await? {
                for hour in list_subdirs_desc(s3_client, &day).await? {
                    if !s3_client.list_keys(&hour).await?.is_empty() {
                        let dir = S3HourDirectory::from_path(&hour).map_err(|e| {
                            InvalidS3Log(format!("invalid withdrawal-log directory {hour}: {e}"))
                        })?;
                        return Ok(Some(dir));
                    }
                }
            }
        }
    }
    Ok(None)
}

/// List the immediate numeric subdirectories from highest to lowest value.
/// Return an error if a directory path does not match the required numeric format.
async fn list_subdirs_desc(
    s3_client: &GuardianS3Client,
    prefix: &str,
) -> GuardianResult<Vec<String>> {
    let dirs = s3_client.list_common_prefixes(prefix).await?;
    S3NumericDirectory::sort_desc(dirs)
        .map_err(|e| InvalidS3Log(format!("invalid withdrawal-log directory: {e:#}")))
}

/// Return the limiter state with the highest `next_seq` in the supplied withdrawal logs.
/// Return an error if a log is not a withdrawal log. Return `None` if there are no logs.
fn bucket_max_post_state(logs: Vec<VerifiedLogEntry>) -> GuardianResult<Option<LimiterState>> {
    let mut states = Vec::with_capacity(logs.len());
    for log in logs {
        let withdrawal = log.extract("withdrawal", VersionedLogMessage::into_withdrawal)?;
        states.push(withdrawal.post_state);
    }
    Ok(states.into_iter().max_by_key(|s| s.next_seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Network;
    use bitcoin::Txid;
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::SignedLogEntry;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalResponse;
    use hashi_types::guardian::WithdrawalLogMessage;

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::mock_for_testing("current", 1)
    }

    fn state_with_seq(next_seq: u64) -> LimiterState {
        LimiterState {
            num_tokens_available: 1_000,
            last_updated_at: 100,
            next_seq,
        }
    }

    fn withdrawal_log(next_seq: u64) -> VerifiedLogEntry {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        let msg = WithdrawalLogMessage {
            txid: Txid::from_slice(&[3u8; 32]).expect("valid txid"),
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            response: StandardWithdrawalResponse::mock_for_testing(),
            post_state: state_with_seq(next_seq),
        };
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let entry = SignedLogEntry::new_at_timestamp(
            "test-session".into(),
            LogMessage::Withdrawal(Box::new(msg)),
            &signing_key,
            0,
        )
        .into_entry_unchecked();
        VerifiedLogEntry::new_for_test(entry, build_pcrs())
    }

    #[test]
    fn bucket_max_empty_is_none() {
        assert!(bucket_max_post_state(vec![]).unwrap().is_none());
    }

    #[test]
    fn bucket_max_picks_highest_seq() {
        let logs = vec![withdrawal_log(3), withdrawal_log(7), withdrawal_log(5)];
        let got = bucket_max_post_state(logs)
            .unwrap()
            .expect("non-empty withdrawal set");
        assert_eq!(got.next_seq, 7);
    }

    #[test]
    fn bucket_max_rejects_non_withdrawal_logs() {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let entry = SignedLogEntry::new_at_timestamp(
            "test-session".into(),
            LogMessage::Heartbeat(HeartbeatLogMessage::new(0)),
            &signing_key,
            0,
        )
        .into_entry_unchecked();
        let heartbeat = VerifiedLogEntry::new_for_test(entry, build_pcrs());

        let err = bucket_max_post_state(vec![withdrawal_log(3), heartbeat])
            .expect_err("must reject non-withdrawal logs");
        assert!(err.to_string().contains("expected a withdrawal log"));
    }

    fn withdrawal_key(year: u16, month: u8, day: u8, hour: u8, seq: u64) -> String {
        format!("withdraw/{year:04}/{month:02}/{day:02}/{hour:02}/{seq:020}-widabc.json")
    }

    fn assert_bucket(actual: Option<S3HourDirectory>, expected_path: &str) {
        let got = actual.expect("expected Some bucket");
        assert_eq!(got, S3HourDirectory::from_path(expected_path).unwrap());
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_empty_returns_none() {
        let s3 = crate::test_utils::mock_logger_with_layout(std::iter::empty());
        let got = find_latest_withdrawal_bucket(&s3).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_single_withdrawal_returns_that_bucket() {
        let keys = vec![withdrawal_key(2024, 3, 15, 14, 7)];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_withdrawal_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/14/");
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_rejects_deleted_latest_hour() {
        let s3 = crate::test_utils::mock_logger_with_deleted_layout(
            [withdrawal_key(2024, 3, 15, 13, 5)],
            [withdrawal_key(2024, 3, 15, 14, 7)],
        );
        let err = find_latest_withdrawal_bucket(&s3).await.unwrap_err();
        assert!(matches!(
            err,
            GuardianError::S3Error(message)
                if message == "Delete marker found under prefix withdraw/2024/03/15/14/"
        ));
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_picks_latest_across_years() {
        let keys = vec![
            withdrawal_key(2023, 12, 31, 23, 1),
            withdrawal_key(2024, 1, 1, 0, 2),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_withdrawal_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/01/01/00/");
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_uses_numeric_order_at_each_level() {
        for older_key in [
            "withdraw/999/10/18/18/x",
            "withdraw/2026/9/18/18/x",
            "withdraw/2026/10/9/18/x",
            "withdraw/2026/10/18/9/x",
        ] {
            // Each older path sorts lexicographically above the genuine latest bucket.
            let s3 = crate::test_utils::mock_logger_with_layout([
                withdrawal_key(2026, 10, 18, 18, 7),
                older_key.to_string(),
            ]);
            let got = find_latest_withdrawal_bucket(&s3).await.unwrap();
            assert_bucket(got, "withdraw/2026/10/18/18/");
        }
    }

    #[tokio::test]
    async fn find_latest_withdrawal_bucket_rejects_noncanonical_latest_hour() {
        let s3 = crate::test_utils::mock_logger_with_layout([
            withdrawal_key(2026, 9, 28, 8, 7),
            "withdraw/2026/09/28/9/x".to_string(),
        ]);
        let err = find_latest_withdrawal_bucket(&s3).await.unwrap_err();
        assert!(matches!(
            err,
            InvalidS3Log(message) if message.contains("noncanonical directory path")
        ));
    }
}
