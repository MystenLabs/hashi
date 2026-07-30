// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::ObjectKeyPattern;
use crate::committee::CommitteeSignature;
use crate::guardian::LimiterState;
use crate::guardian::StandardWithdrawalRequestWire;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
use crate::guardian::WithdrawalID;
use crate::guardian::s3_utils::S3HourScopedDirectory;
use crate::guardian::unix_millis_to_seconds;
use bitcoin::Txid;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
pub enum WithdrawalLogMessage {
    Success {
        txid: Txid,
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        response: StandardWithdrawalResponse,
        /// Limiter state after this withdrawal was consumed. The KP rotating in
        /// the next enclave reads the max-seq Success log and uses its
        /// `post_state` as the new enclave's initial limiter state.
        post_state: LimiterState,
    },
    Failure {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        error: String,
    },
}

impl WithdrawalLogMessage {
    /// Success keys lead with `success-{seq:020}` so that lexicographic listing
    /// within an hour bucket is also seq-sorted — the last key is the max-seq
    /// log, which the KP reads to recover limiter state. Failures don't have a
    /// meaningful seq (the request's seq may be stale), so they use a random
    /// suffix for dedup.
    pub fn object_key_pattern(
        &self,
        session_id: &str,
        timestamp_ms: UnixMillis,
    ) -> ObjectKeyPattern {
        let directory = S3HourScopedDirectory::withdraw(unix_millis_to_seconds(timestamp_ms));
        match self {
            Self::Success { request_data, .. } => ObjectKeyPattern::Fixed(format!(
                "{directory}success-{:020}-{session_id}-wid{}.json",
                request_data.seq, request_data.wid,
            )),
            Self::Failure { request_data, .. } => ObjectKeyPattern::RandomSuffix(format!(
                "{directory}failure-{session_id}-wid{}-",
                request_data.wid,
            )),
        }
    }

    pub fn wid(&self) -> WithdrawalID {
        match self {
            WithdrawalLogMessage::Success { request_data, .. } => request_data.wid,
            WithdrawalLogMessage::Failure { request_data, .. } => request_data.wid,
        }
    }
}
