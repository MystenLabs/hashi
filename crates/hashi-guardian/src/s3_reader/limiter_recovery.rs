// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovers a standby enclave's activation limiter state from guardian S3
//! withdrawal logs.
//!
//! Each withdrawal log carries the limiter `post_state` after that
//! consume. The withdrawal seq is strictly monotonic across rotations, so the
//! global max-seq withdrawal log holds the most recent limiter state.
//!
//! Finding that log is a 4-level S3 tree-walk over the hour-partitioned layout
//! (`withdraw/YYYY/MM/DD/HH/`): at each level we list `CommonPrefixes`, pick the
//! lex-greatest, and descend. The first hour bucket containing any withdrawal
//! key is the latest non-empty bucket. We read it and one bucket back
//! (sub-hour clock-skew defense across hour boundaries), then take the max-seq
//! withdrawal across both.
//!
//! We deliberately do not apply the auditor's `write_completion_time`
//! (`DIR_WRITES_COMPLETION_DELAY`) gate when reading the found bucket. That gate
//! exists for polling/auditor reads where the source might still be writing; if
//! used here, an enclave that died late in an hour could have its final-hour
//! bucket treated as not-yet-complete, and recovery would miss the most recent
//! log. Activation instead calls this only after the heartbeat quiet check has
//! confirmed every non-standby session has been silent long enough for S3
//! read-after-write consistency to cover the old session's final writes.

use super::GuardianReader;
use super::VerifiedLogRecord;
use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use tracing::info;

impl GuardianReader {
    /// Derive the activation limiter state from withdrawal logs. Uses the
    /// global max-seq withdrawal post-state when present, otherwise genesis, and
    /// caps tokens to the supplied config in case capacity was lowered.
    ///
    /// Precondition: the caller must have already verified that every
    /// non-standby session is quiet (`ensure_session_live_and_others_quiet`).
    /// This read deliberately skips the `write_completion_time` gate, so it is
    /// only sound once the prior session's final writes are guaranteed visible.
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

        // Read the found bucket + one bucket back, then take max-seq across
        // both. The peek-back defends against sub-hour clock skew that may have
        // placed a higher-seq log in the prior hour bucket.
        let hit = bucket_max_post_state(self.read_logs_in_dir(&cursor).await?);
        cursor = cursor.prev_dir();
        let peek = bucket_max_post_state(self.read_logs_in_dir(&cursor).await?);
        let recovered_state = [hit, peek]
            .into_iter()
            .flatten()
            .max_by_key(|s| s.next_seq)
            .ok_or_else(|| {
                InvalidS3Log(
                    "latest withdrawal bucket contained no verified withdrawal logs".into(),
                )
            })?;
        let state = cap_limiter_state_to_config(recovered_state, limiter_config);
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

/// Finds the latest hour bucket under `withdraw/` containing at least one
/// withdrawal key, by descending the YYYY/MM/DD/HH tree in lex-greatest
/// order at each level. Returns `None` if no withdrawal log exists anywhere.
async fn find_latest_withdrawal_bucket(
    s3_client: &GuardianS3Client,
) -> GuardianResult<Option<S3HourScopedDirectory>> {
    let root = format!("{}/", S3_DIR_WITHDRAW);
    for year in list_subdirs_desc(s3_client, &root).await? {
        for month in list_subdirs_desc(s3_client, &year).await? {
            for day in list_subdirs_desc(s3_client, &month).await? {
                for hour in list_subdirs_desc(s3_client, &day).await? {
                    if !s3_client.list_keys(&hour).await?.is_empty() {
                        let dir = S3HourScopedDirectory::from_path(&hour).map_err(|e| {
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

async fn list_subdirs_desc(
    s3_client: &GuardianS3Client,
    prefix: &str,
) -> GuardianResult<Vec<String>> {
    let mut subs = s3_client.list_common_prefixes(prefix).await?;
    // The S3 client already returns unique prefixes in ascending order.
    subs.reverse();
    Ok(subs)
}

fn bucket_max_post_state(logs: Vec<VerifiedLogRecord>) -> Option<LimiterState> {
    logs.into_iter()
        .filter_map(|log| log.into_entry().into_message().into_withdrawal())
        .map(|withdrawal| withdrawal.post_state)
        .max_by_key(|s| s.next_seq)
}

fn cap_limiter_state_to_config(
    mut state: LimiterState,
    limiter_config: &LimiterConfig,
) -> LimiterState {
    state.num_tokens_available = state
        .num_tokens_available
        .min(limiter_config.max_bucket_capacity);
    state
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
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalResponse;
    use hashi_types::guardian::WithdrawalLogMessage;

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn state_with_seq(next_seq: u64) -> LimiterState {
        LimiterState {
            num_tokens_available: 1_000,
            last_updated_at: 100,
            next_seq,
        }
    }

    fn withdrawal_log(next_seq: u64) -> VerifiedLogRecord {
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
        let entry = LogRecord::new_at_timestamp(
            "test-session".into(),
            LogMessage::Withdrawal(Box::new(msg)),
            &signing_key,
            0,
        )
        .into_entry_unchecked();
        VerifiedLogRecord::new_for_test(entry, build_pcrs())
    }

    #[test]
    fn bucket_max_empty_is_none() {
        assert!(bucket_max_post_state(vec![]).is_none());
    }

    #[test]
    fn bucket_max_picks_highest_seq() {
        let logs = vec![withdrawal_log(3), withdrawal_log(7), withdrawal_log(5)];
        let got = bucket_max_post_state(logs).expect("non-empty withdrawal set");
        assert_eq!(got.next_seq, 7);
    }

    #[test]
    fn cap_limiter_state_to_config_caps_tokens_only() {
        let limiter_config = LimiterConfig {
            refill_rate: 10,
            max_bucket_capacity: 500,
        };
        let got = cap_limiter_state_to_config(state_with_seq(7), &limiter_config);

        assert_eq!(got.num_tokens_available, 500);
        assert_eq!(got.last_updated_at, 100);
        assert_eq!(got.next_seq, 7);
    }

    fn withdrawal_key(year: u16, month: u8, day: u8, hour: u8, seq: u64) -> String {
        format!("withdraw/{year:04}/{month:02}/{day:02}/{hour:02}/{seq:020}-sess-widabc.json")
    }

    fn assert_bucket(actual: Option<S3HourScopedDirectory>, expected_path: &str) {
        let got = actual.expect("expected Some bucket");
        assert_eq!(
            got,
            S3HourScopedDirectory::from_path(expected_path).unwrap()
        );
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
    async fn find_latest_withdrawal_bucket_picks_lex_greatest_across_years() {
        let keys = vec![
            withdrawal_key(2023, 12, 31, 23, 1),
            withdrawal_key(2024, 1, 1, 0, 2),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_withdrawal_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/01/01/00/");
    }
}
