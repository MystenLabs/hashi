// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovers the next enclave's initial limiter state from the prior enclave's
//! S3 withdrawal logs.
//!
//! Each successful withdrawal log carries the limiter `post_state` after that
//! consume. seq is strictly monotonic across all rotations, so the global
//! max-seq Success log holds the most recent state.
//!
//! Finding that log is a 4-level S3 tree-walk over the hour-partitioned layout
//! (`withdraw/YYYY/MM/DD/HH/`): at each level we list `CommonPrefixes` (~one
//! `list_objects_v2` call), pick the lex-greatest, and descend. The first
//! hour bucket containing any `success-*` key is the latest non-empty bucket
//! — we read it and one bucket back (sub-hour clock-skew defense across hour
//! boundaries) and take the max-seq Success across both.
//!
//! Note we deliberately don't apply the auditor's `write_completion_time`
//! (`DIR_WRITES_COMPLETION_DELAY`) gate when reading the found bucket. That
//! gate exists for the polling/auditor case where the source might still be
//! writing; if we used it here, an enclave that died late in an hour would
//! have its final-hour bucket treated as not-yet-complete, and recovery would
//! miss the most recent log. We instead rely on the caller invoking us only
//! after `heartbeat_audit` has confirmed the prior session has been silent
//! for at least `OTHER_SESSION_QUIET_PERIOD` (10 min), which combined with
//! S3 read-after-write consistency guarantees that all writes of the old session
//! are completed.

use hashi_guardian::s3_client::GuardianS3Client;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use tracing::info;

/// Returns `Some(post_state)` from the global max-seq Success log under
/// `withdraw/` if one exists; returns `None` if no Success log exists
/// anywhere — either a first deployment or a rotation where the prior
/// enclave processed no withdrawals. Caller falls back to genesis on `None`.
pub async fn recover_limiter_state(
    reader: &mut GuardianReader,
) -> anyhow::Result<Option<LimiterState>> {
    let Some(mut cursor) = find_latest_success_bucket(reader.s3()).await? else {
        return Ok(None);
    };

    // Read the found bucket + one bucket back, then take max-seq across both.
    // The peek-back defends against sub-hour clock skew that may have placed
    // a higher-seq log in the prior hour bucket.
    let hit = bucket_max_post_state(reader.read_dir(&cursor).await?);
    cursor = cursor.prev_dir();
    let peek = bucket_max_post_state(reader.read_dir(&cursor).await?);
    let best = [hit, peek].into_iter().flatten().max_by_key(|s| s.next_seq);

    if let Some(ref state) = best {
        info!(
            next_seq = state.next_seq,
            num_tokens_available = state.num_tokens_available,
            last_updated_at = state.last_updated_at,
            "recovered limiter state from prior enclave's withdraw logs"
        );
    }
    Ok(best)
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
        .list_all_keys_in_dir(&format!("{bucket}success-"))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(!keys.is_empty())
}

fn bucket_max_post_state(logs: Vec<VerifiedLogRecord>) -> Option<LimiterState> {
    logs.into_iter()
        .filter_map(|log| {
            let LogMessage::Withdrawal(boxed) = log.message else {
                return None;
            };
            match *boxed {
                WithdrawalLogMessage::Success { post_state, .. } => Some(post_state),
                WithdrawalLogMessage::Failure { .. } => None,
            }
        })
        .max_by_key(|s| s.next_seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::Txid;
    use bitcoin::hashes::Hash;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::GuardianSigned;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalResponse;

    fn state_with_seq(next_seq: u64) -> LimiterState {
        LimiterState {
            num_tokens_available: 1_000,
            last_updated_at: 100,
            next_seq,
        }
    }

    fn success_log(next_seq: u64) -> VerifiedLogRecord {
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
            session_id: "test-session".to_string(),
            timestamp_ms: 0,
            message: LogMessage::Withdrawal(Box::new(msg)),
        }
    }

    fn failure_log() -> VerifiedLogRecord {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        let msg = WithdrawalLogMessage::Failure {
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            error: GuardianError::RateLimitExceeded,
        };
        VerifiedLogRecord {
            session_id: "test-session".to_string(),
            timestamp_ms: 0,
            message: LogMessage::Withdrawal(Box::new(msg)),
        }
    }

    #[test]
    fn bucket_max_empty_is_none() {
        assert!(bucket_max_post_state(vec![]).is_none());
    }

    #[test]
    fn bucket_max_only_failures_is_none() {
        assert!(bucket_max_post_state(vec![failure_log(), failure_log()]).is_none());
    }

    #[test]
    fn bucket_max_picks_highest_seq_success() {
        let logs = vec![success_log(3), success_log(7), success_log(5)];
        let got = bucket_max_post_state(logs).expect("non-empty success set");
        assert_eq!(got.next_seq, 7);
    }

    #[test]
    fn bucket_max_ignores_failures_when_picking_success() {
        let logs = vec![failure_log(), success_log(2), failure_log(), success_log(9)];
        let got = bucket_max_post_state(logs).expect("non-empty success set");
        assert_eq!(got.next_seq, 9);
    }

    // ----- find_latest_success_bucket tests (S3 SDK-level mocking) -----

    fn success_key(year: u16, month: u8, day: u8, hour: u8, seq: u64) -> String {
        format!(
            "withdraw/{year:04}/{month:02}/{day:02}/{hour:02}/success-{seq:020}-sess-widabc.json"
        )
    }

    fn failure_key(year: u16, month: u8, day: u8, hour: u8, n: u32) -> String {
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
        let s3 = hashi_guardian::test_utils::mock_logger_with_layout(std::iter::empty());
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn find_latest_success_bucket_single_success_returns_that_bucket() {
        let keys = vec![success_key(2024, 3, 15, 14, 7)];
        let s3 = hashi_guardian::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/14/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_skips_latest_hour_with_only_failures() {
        let keys = vec![
            failure_key(2024, 3, 15, 14, 0xdead_beef),
            success_key(2024, 3, 15, 13, 5),
        ];
        let s3 = hashi_guardian::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/13/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_picks_lex_greatest_across_years() {
        let keys = vec![
            success_key(2023, 12, 31, 23, 1),
            success_key(2024, 1, 1, 0, 2),
        ];
        let s3 = hashi_guardian::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/01/01/00/");
    }

    #[tokio::test]
    async fn find_latest_success_bucket_backtracks_within_day() {
        // Latest hour (15) has only failures; earlier hour (12) same day has a success.
        let keys = vec![
            failure_key(2024, 3, 15, 15, 1),
            failure_key(2024, 3, 15, 14, 2),
            success_key(2024, 3, 15, 12, 9),
        ];
        let s3 = hashi_guardian::test_utils::mock_logger_with_layout(keys);
        let got = find_latest_success_bucket(&s3).await.unwrap();
        assert_bucket(got, "withdraw/2024/03/15/12/");
    }
}
