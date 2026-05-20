// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Recovers the next enclave's initial limiter state from the prior enclave's
//! S3 withdrawal logs.
//!
//! Each successful withdrawal log carries the limiter `post_state` after that
//! consume. seq is strictly monotonic across all rotations, so the global
//! max-seq Success log holds the most recent state. To find it we walk back
//! hour by hour from `now`, returning the post_state from the first non-empty
//! bucket's max-seq log. We also peek one bucket further back to defend
//! against sub-hour clock skew across hour boundaries.
//!
//! Note we deliberately don't apply `GuardianPollerCore::is_readable`'s
//! `DIR_WRITES_COMPLETION_DELAY` gate here. That gate exists for the
//! polling/auditor case where the source might still be writing; if we used it
//! here, an enclave that died late in an hour would have its final-hour bucket
//! treated as not-yet-readable, and the recovery would skip past the most
//! recent log. We instead rely on the caller invoking us only after
//! `heartbeat_audit` has confirmed the prior session has been silent for at
//! least `OTHER_SESSION_QUIET_PERIOD` (10 min), which combined with S3
//! read-after-write consistency guarantees all of its writes are visible.

use crate::domain::now_unix_seconds;
use crate::rpc::guardian::GuardianLogDir;
use crate::rpc::guardian::GuardianPollerCore;
use hashi_guardian::s3_logger::S3Logger;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::WithdrawalLogMessage;
use tracing::info;

/// Max hour buckets to walk back when searching for the most recent Success log.
/// One week covers any realistic idleness; if no Success is found within this
/// window the prior enclave is treated as having consumed nothing, and the
/// caller falls back to a genesis limiter state.
const MAX_WALK_BACK_HOURS: u64 = 7 * 24;

/// Returns `Some(post_state)` from the global max-seq Success log if one is
/// found within `MAX_WALK_BACK_HOURS`. Returns `None` if no Success log exists
/// in that window — caller decides what to do (typically: fall back to
/// genesis, since combined with the rotation-mode check this unambiguously
/// means the prior enclave processed no withdrawals).
pub async fn recover_limiter_state(s3_client: S3Logger) -> anyhow::Result<Option<LimiterState>> {
    let now = now_unix_seconds();
    let mut poller = GuardianPollerCore::from_s3_client(s3_client, now, GuardianLogDir::Withdraw);

    let mut best: Option<LimiterState> = None;
    for _ in 0..MAX_WALK_BACK_HOURS {
        // NOTE (future optimization): read_cur_dir fetches and verifies every
        // log body in the bucket, but we only need the max-seq Success body.
        // The seq-prefixed key format (`success-{seq:020}-...`) lets us list
        // keys, pick the lex-last `success-*` entry, and fetch only that
        // single object — turning O(n) object reads per bucket into O(1).
        if let Some(hit) = bucket_max_post_state(poller.read_cur_dir().await?) {
            // First non-empty bucket. Peek one bucket back for clock-skew safety,
            // then take the max across both.
            poller.retreat_cursor();
            let peek = bucket_max_post_state(poller.read_cur_dir().await?);
            best = [Some(hit), peek]
                .into_iter()
                .flatten()
                .max_by_key(|s| s.next_seq);
            break;
        }
        poller.retreat_cursor();
    }

    if let Some(state) = best {
        info!(
            next_seq = state.next_seq,
            num_tokens_available = state.num_tokens_available,
            last_updated_at = state.last_updated_at,
            "recovered limiter state from prior enclave's withdraw logs"
        );
    }
    Ok(best)
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
}
