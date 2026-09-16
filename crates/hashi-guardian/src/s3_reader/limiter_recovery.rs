// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovers a standby enclave's activation withdrawal state from guardian S3
//! withdrawal logs.
//!
//! Each successful withdrawal log carries the txid it debited and the limiter
//! `post_state` after that consume. Activation reads every one of them, by
//! walking the whole hour-partitioned layout (`withdraw/YYYY/MM/DD/HH/`): the
//! complete txid set is what lets the enclave re-sign any repeat without a
//! second debit, and the max-seq `post_state` is the limiter state to resume
//! from. The walk is O(history) by design, because a set missing one txid would
//! let that transaction be debited twice.
//!
//! We deliberately do not apply the auditor's `write_completion_time`
//! (`DIR_WRITES_COMPLETION_DELAY`) gate. That gate exists for polling/auditor
//! reads where the source might still be writing; if used here, an enclave that
//! died late in an hour could have its final-hour bucket treated as
//! not-yet-complete, and recovery would miss its most recent logs. Activation
//! instead calls this only after the heartbeat quiet check has confirmed every
//! non-standby session has been silent long enough for S3 read-after-write
//! consistency to cover the old session's final writes.

use super::GuardianReader;
use super::VerifiedLogRecord;
use crate::s3_client::GuardianS3Client;
use bitcoin::Txid;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::S3_DIR_WITHDRAW;
use std::collections::HashSet;
use tracing::info;

/// Withdrawal state recovered from the log for activation.
pub struct RecoveredWithdrawals {
    /// Limiter state to resume from.
    pub limiter_state: LimiterState,
    /// Every transaction the log shows as debited in this bucket.
    pub signed_txids: HashSet<Txid>,
}

impl GuardianReader {
    /// Derive the activation withdrawal state from withdrawal logs: every
    /// debited txid, plus the global max-seq Success `post_state` (genesis when
    /// no withdrawal has ever succeeded), with tokens capped to the supplied
    /// config in case capacity was lowered.
    ///
    /// Precondition: the caller must have already verified that every
    /// non-standby session is quiet (`ensure_session_live_and_others_quiet`).
    /// This read deliberately skips the `write_completion_time` gate, so it is
    /// only sound once the prior session's final writes are guaranteed visible.
    pub async fn recover_withdrawal_state(
        &mut self,
        limiter_config: &LimiterConfig,
    ) -> GuardianResult<RecoveredWithdrawals> {
        let dirs = list_success_buckets(&self.s3).await?;
        let mut signed_txids = HashSet::new();
        let mut max_post_state: Option<LimiterState> = None;
        for dir in dirs {
            for (post_state, txid) in
                bucket_successes(self.read_successful_withdrawals_in_dir(&dir).await?)
            {
                signed_txids.insert(txid);
                max_post_state = Some(match max_post_state {
                    Some(max) if max.next_seq >= post_state.next_seq => max,
                    _ => post_state,
                });
            }
        }

        let Some(recovered_state) = max_post_state else {
            info!("no successful withdrawal logs found; using genesis limiter state");
            return Ok(RecoveredWithdrawals {
                limiter_state: LimiterState::genesis(limiter_config),
                signed_txids,
            });
        };
        let limiter_state = cap_limiter_state_to_config(recovered_state, limiter_config);
        info!(
            next_seq = limiter_state.next_seq,
            last_updated_at = limiter_state.last_updated_at,
            recovered_num_tokens_available = recovered_state.num_tokens_available,
            capped_num_tokens_available = limiter_state.num_tokens_available,
            signed_txids = signed_txids.len(),
            "recovered limiter state and signed transactions from withdrawal logs"
        );
        Ok(RecoveredWithdrawals {
            limiter_state,
            signed_txids,
        })
    }
}

/// Every hour bucket under `withdraw/` holding at least one `success-*` key,
/// from a full walk of the YYYY/MM/DD/HH tree.
async fn list_success_buckets(
    s3_client: &GuardianS3Client,
) -> GuardianResult<Vec<S3HourScopedDirectory>> {
    let mut dirs = Vec::new();
    let root = format!("{}/", S3_DIR_WITHDRAW);
    for year in s3_client.list_common_prefixes(&root).await? {
        for month in s3_client.list_common_prefixes(&year).await? {
            for day in s3_client.list_common_prefixes(&month).await? {
                for hour in s3_client.list_common_prefixes(&day).await? {
                    if !hour_bucket_has_success(s3_client, &hour).await? {
                        continue;
                    }
                    dirs.push(S3HourScopedDirectory::from_path(&hour).map_err(|e| {
                        InvalidS3Log(format!("invalid withdrawal-log directory {hour}: {e}"))
                    })?);
                }
            }
        }
    }
    Ok(dirs)
}

async fn hour_bucket_has_success(
    s3_client: &GuardianS3Client,
    bucket: &str,
) -> GuardianResult<bool> {
    let keys = s3_client
        .list_keys(&format!("{bucket}success-"), true)
        .await?;
    Ok(!keys.is_empty())
}

fn bucket_successes(logs: Vec<VerifiedLogRecord>) -> Vec<(LimiterState, Txid)> {
    logs.into_iter()
        .filter_map(|log| {
            let boxed = match log.into_entry().into_message() {
                V1(LogMessageV1::Withdrawal(message)) | V2(LogMessageV2::Withdrawal(message)) => {
                    message
                }
                V1(_) | V2(_) => return None,
            };
            match *boxed {
                WithdrawalLogMessage::Success {
                    txid, post_state, ..
                } => Some((post_state, txid)),
                WithdrawalLogMessage::Failure { .. } => None,
            }
        })
        .collect()
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
    use hashi_types::guardian::WithdrawalID;

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

    /// A Success record whose wid and txid bytes are `next_seq`.
    fn withdrawal_success_log(next_seq: u64) -> VerifiedLogRecord {
        let wid = WithdrawalID::new([next_seq as u8; 32]);
        let signed =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let (request_sign, request_data) = signed.into_parts();
        let mut request_data = StandardWithdrawalRequestWire::from(request_data);
        request_data.seq = next_seq - 1;
        let msg = WithdrawalLogMessage::Success {
            txid: Txid::from_slice(&[next_seq as u8; 32]).expect("valid txid"),
            request_data,
            request_sign,
            response: StandardWithdrawalResponse::mock_for_testing(),
            post_state: state_with_seq(next_seq),
        };
        verified_withdrawal_log(msg)
    }

    fn withdrawal_failure_log() -> VerifiedLogRecord {
        let signed = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let (request_sign, request_data) = signed.into_parts();
        let msg = WithdrawalLogMessage::Failure {
            request_data: StandardWithdrawalRequestWire::from(request_data),
            request_sign,
            error: GuardianError::RateLimitExceeded.to_string(),
        };
        verified_withdrawal_log(msg)
    }

    fn verified_withdrawal_log(message: WithdrawalLogMessage) -> VerifiedLogRecord {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let entry = LogRecord::new_at_timestamp(
            "test-session".into(),
            LogMessage::Withdrawal(Box::new(message)),
            &signing_key,
            0,
        )
        .into_entry_unchecked();
        VerifiedLogRecord::new_for_test(entry, build_pcrs())
    }

    #[test]
    fn bucket_successes_empty_is_empty() {
        assert!(bucket_successes(vec![]).is_empty());
    }

    #[test]
    fn bucket_successes_skips_failures() {
        assert!(
            bucket_successes(vec![withdrawal_failure_log(), withdrawal_failure_log()]).is_empty()
        );
    }

    #[test]
    fn bucket_successes_returns_every_success_with_its_post_state() {
        let logs = vec![
            withdrawal_success_log(3),
            withdrawal_failure_log(),
            withdrawal_success_log(7),
            withdrawal_success_log(5),
        ];
        let got = bucket_successes(logs);
        // Every debited transaction is returned, each paired with the limiter
        // state from its own record.
        assert_eq!(
            got,
            vec![
                (state_with_seq(3), Txid::from_slice(&[3; 32]).unwrap()),
                (state_with_seq(7), Txid::from_slice(&[7; 32]).unwrap()),
                (state_with_seq(5), Txid::from_slice(&[5; 32]).unwrap()),
            ]
        );
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

    fn bucket_paths(dirs: Vec<S3HourScopedDirectory>) -> Vec<String> {
        dirs.iter().map(|dir| dir.to_string()).collect()
    }

    #[tokio::test]
    async fn list_success_buckets_empty_returns_nothing() {
        let s3 = crate::test_utils::mock_logger_with_layout(std::iter::empty());
        assert!(list_success_buckets(&s3).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_success_buckets_returns_every_success_hour() {
        // Recovery needs all of them, not just the newest: one missing txid
        // would let that transaction be debited a second time.
        let keys = vec![
            withdraw_success_key(2023, 12, 31, 23, 1),
            withdraw_success_key(2024, 1, 1, 0, 2),
            withdraw_success_key(2024, 3, 15, 12, 9),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = bucket_paths(list_success_buckets(&s3).await.unwrap());
        assert_eq!(
            got,
            vec![
                "withdraw/2023/12/31/23/",
                "withdraw/2024/01/01/00/",
                "withdraw/2024/03/15/12/",
            ]
        );
    }

    #[tokio::test]
    async fn list_success_buckets_skips_hours_with_only_failures() {
        let keys = vec![
            withdraw_failure_key(2024, 3, 15, 14, 0xdead_beef),
            withdraw_success_key(2024, 3, 15, 13, 5),
        ];
        let s3 = crate::test_utils::mock_logger_with_layout(keys);
        let got = bucket_paths(list_success_buckets(&s3).await.unwrap());
        assert_eq!(got, vec!["withdraw/2024/03/15/13/"]);
    }

    #[tokio::test]
    async fn list_success_buckets_rejects_a_deleted_record() {
        let s3 = crate::test_utils::mock_logger_with_deleted_layout(
            [withdraw_success_key(2024, 3, 15, 13, 5)],
            [withdraw_success_key(2024, 3, 15, 14, 7)],
        );
        let err = list_success_buckets(&s3).await.unwrap_err();
        assert!(matches!(
            err,
            GuardianError::S3Error(message)
                if message == "Delete marker found under prefix withdraw/2024/03/15/14/success-"
        ));
    }
}
