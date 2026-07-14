// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovers a standby enclave's activation limiter state from guardian S3
//! withdrawal logs.
//!
//! Each successful withdrawal log carries the limiter `post_state` after that
//! consume. The withdrawal seq is strictly monotonic across rotations, so the
//! global max-seq Success log holds the most recent limiter state.
//!
//! Finding that log is a 4-level S3 tree-walk over the hour-partitioned layout
//! (`withdraw/YYYY/MM/DD/HH/`): at each level we list `CommonPrefixes`, pick the
//! lex-greatest, and descend. The first hour bucket containing any `success-*`
//! key is the latest non-empty bucket. We read it and one bucket back
//! (sub-hour clock-skew defense across hour boundaries), then take the max-seq
//! Success across both.
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
use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use tracing::info;

impl GuardianReader {
    /// Derive the activation limiter state from withdrawal logs. Uses the
    /// global max-seq Success post-state when present, otherwise genesis, and
    /// caps tokens to the supplied config in case capacity was lowered.
    ///
    /// Precondition: the caller must have already verified that every
    /// non-standby session is quiet (`ensure_session_live_and_others_quiet`).
    /// This read deliberately skips the `write_completion_time` gate, so it is
    /// only sound once the prior session's final writes are guaranteed visible.
    pub async fn recover_limiter_state(
        &mut self,
        limiter_config: &LimiterConfig,
    ) -> anyhow::Result<LimiterState> {
        let Some(mut cursor) = find_latest_success_bucket(self.s3()).await? else {
            info!("no successful withdrawal logs found; using genesis limiter state");
            return Ok(LimiterState::genesis(limiter_config));
        };

        // Read the found bucket + one bucket back, then take max-seq across
        // both. The peek-back defends against sub-hour clock skew that may have
        // placed a higher-seq log in the prior hour bucket.
        let hit = bucket_max_post_state(self.read_dir(&cursor).await?);
        cursor = cursor.prev_dir();
        let peek = bucket_max_post_state(self.read_dir(&cursor).await?);
        let recovered_state = [hit, peek]
            .into_iter()
            .flatten()
            .max_by_key(|s| s.next_seq)
            .ok_or_else(|| {
                anyhow::anyhow!("latest success bucket contained no verified Success logs")
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
/// `success-*` key, by descending the YYYY/MM/DD/HH tree in lex-greatest
/// order at each level. Returns `None` if no Success log exists anywhere.
async fn find_latest_success_bucket(
    s3_client: &GuardianS3Client,
) -> anyhow::Result<Option<S3HourScopedDirectory>> {
    let root = format!("{}/", S3_DIR_WITHDRAW);
    let years = list_subdirs_desc(s3_client, &root).await?;
    for year in years {
        let months = list_subdirs_desc(s3_client, &year).await?;
        for month in months {
            let days = list_subdirs_desc(s3_client, &month).await?;
            for day in days {
                let hours = list_subdirs_desc(s3_client, &day).await?;
                for hour in hours {
                    if hour_bucket_has_success(s3_client, &hour).await? {
                        return Ok(Some(S3HourScopedDirectory::from_path(&hour)?));
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
) -> anyhow::Result<Vec<String>> {
    let mut subs = s3_client
        .list_common_prefixes(prefix)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    subs.sort_by(|a, b| b.cmp(a));
    Ok(subs)
}

async fn hour_bucket_has_success(
    s3_client: &GuardianS3Client,
    bucket: &str,
) -> anyhow::Result<bool> {
    let keys = s3_client
        .validate_prefix_history_and_list_keys(&format!("{bucket}success-"))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(!keys.is_empty())
}

fn bucket_max_post_state(logs: Vec<VerifiedLogRecord>) -> Option<LimiterState> {
    logs.into_iter()
        .filter_map(|log| {
            let LogMessage::V1(LogMessageV1::Withdrawal(boxed)) = log.message else {
                return None;
            };
            match *boxed {
                WithdrawalLogMessage::Success { post_state, .. } => Some(post_state),
                WithdrawalLogMessage::Failure { .. } => None,
            }
        })
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
    use hashi_types::guardian::GuardianSigned;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalResponse;

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

    fn withdrawal_success_log(next_seq: u64) -> VerifiedLogRecord {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        let msg = WithdrawalLogMessage::Success {
            txid: Txid::from_slice(&[3u8; 32]).expect("valid txid"),
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            response: GuardianSigned::<StandardWithdrawalResponse>::mock_for_testing().data,
            post_state: state_with_seq(next_seq),
        };
        VerifiedLogRecord {
            object_key: format!("withdraw/success-{next_seq}.json"),
            session_id: "test-session".into(),
            timestamp_ms: 0,
            message: LogMessageV1::Withdrawal(Box::new(msg)).into(),
            build_pcrs: build_pcrs(),
        }
    }

    fn withdrawal_failure_log() -> VerifiedLogRecord {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        let msg = WithdrawalLogMessage::Failure {
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            error: GuardianError::RateLimitExceeded,
        };
        VerifiedLogRecord {
            object_key: "withdraw/failure.json".to_string(),
            session_id: "test-session".into(),
            timestamp_ms: 0,
            message: LogMessageV1::Withdrawal(Box::new(msg)).into(),
            build_pcrs: build_pcrs(),
        }
    }

    #[test]
    fn bucket_max_empty_is_none() {
        assert!(bucket_max_post_state(vec![]).is_none());
    }

    #[test]
    fn bucket_max_only_failures_is_none() {
        assert!(
            bucket_max_post_state(vec![withdrawal_failure_log(), withdrawal_failure_log()])
                .is_none()
        );
    }

    #[test]
    fn bucket_max_picks_highest_seq_success() {
        let logs = vec![
            withdrawal_success_log(3),
            withdrawal_success_log(7),
            withdrawal_success_log(5),
        ];
        let got = bucket_max_post_state(logs).expect("non-empty success set");
        assert_eq!(got.next_seq, 7);
    }

    #[test]
    fn bucket_max_ignores_failures_when_picking_success() {
        let logs = vec![
            withdrawal_failure_log(),
            withdrawal_success_log(2),
            withdrawal_failure_log(),
            withdrawal_success_log(9),
        ];
        let got = bucket_max_post_state(logs).expect("non-empty success set");
        assert_eq!(got.next_seq, 9);
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

    fn withdraw_success_key(year: u16, month: u8, day: u8, hour: u8, seq: u64) -> String {
        format!(
            "withdraw/{year:04}/{month:02}/{day:02}/{hour:02}/success-{seq:020}-sess-widabc.json"
        )
    }

    fn withdraw_failure_key(year: u16, month: u8, day: u8, hour: u8, n: u32) -> String {
        format!("withdraw/{year:04}/{month:02}/{day:02}/{hour:02}/failure-sess-widabc-{n:08x}.json")
    }

    fn assert_bucket(actual: Option<S3HourScopedDirectory>, expected_path: &str) {
        let got = actual.expect("expected Some bucket");
        assert_eq!(
            got,
            S3HourScopedDirectory::from_path(expected_path).unwrap()
        );
    }

    #[tokio::test]
    async fn find_latest_success_bucket_empty_returns_none() {
        let s3 = crate::test_utils::mock_logger_with_layout(std::iter::empty());
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn find_latest_success_bucket_single_success_returns_that_bucket() {
        let keys = vec![withdraw_success_key(2024, 3, 15, 14, 7)];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/14/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_skips_latest_hour_with_only_failures() {
        let keys = vec![
            withdraw_failure_key(2024, 3, 15, 14, 0xdead_beef),
            withdraw_success_key(2024, 3, 15, 13, 5),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/13/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_picks_lex_greatest_across_years() {
        let keys = vec![
            withdraw_success_key(2023, 12, 31, 23, 1),
            withdraw_success_key(2024, 1, 1, 0, 2),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/01/01/00/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_backtracks_within_day() {
        let keys = vec![
            withdraw_failure_key(2024, 3, 15, 15, 1),
            withdraw_failure_key(2024, 3, 15, 14, 2),
            withdraw_success_key(2024, 3, 15, 12, 9),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/12/");
    }
}
