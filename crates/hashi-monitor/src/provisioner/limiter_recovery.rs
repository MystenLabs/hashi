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
/// One week covers any realistic idleness; beyond this we bail rather than
/// silently treat a missing-log situation as genesis.
const MAX_WALK_BACK_HOURS: u64 = 7 * 24;

pub async fn recover_limiter_state(s3_client: S3Logger) -> anyhow::Result<LimiterState> {
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

    let state = best.ok_or_else(|| {
        anyhow::anyhow!(
            "no successful withdrawal logs found within last {} hours; \
             cannot recover limiter state",
            MAX_WALK_BACK_HOURS
        )
    })?;
    info!(
        next_seq = state.next_seq,
        num_tokens_available = state.num_tokens_available,
        last_updated_at = state.last_updated_at,
        "recovered limiter state from prior enclave's withdraw logs"
    );
    Ok(state)
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
