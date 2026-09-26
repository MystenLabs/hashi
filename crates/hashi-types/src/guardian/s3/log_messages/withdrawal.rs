// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3HourScopedDirectory;
use crate::committee::CommitteeSignature;
use crate::guardian::LimiterState;
use crate::guardian::StandardWithdrawalRequestWire;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
use crate::guardian::WithdrawalID;
use crate::guardian::unix_millis_to_seconds;
use bitcoin::Txid;
use serde::Deserialize;
use serde::Serialize;

/// A successfully processed withdrawal and its durable limiter state.
#[derive(Debug, Serialize, Deserialize)]
pub struct WithdrawalLogMessage {
    pub txid: Txid,
    pub request_data: StandardWithdrawalRequestWire,
    pub request_sign: CommitteeSignature,
    pub response: StandardWithdrawalResponse,
    /// Limiter state after this withdrawal was consumed. The KP rotating in
    /// the next enclave reads the max-seq log and uses its `post_state` as
    /// the new enclave's initial limiter state.
    pub post_state: LimiterState,
}

impl WithdrawalLogMessage {
    /// Keys lead with `{seq:020}` so that lexicographic listing within
    /// an hour bucket is also seq-sorted. The KP reads the max-seq log to
    /// recover limiter state.
    pub fn object_key(&self, session_id: &str, timestamp_ms: UnixMillis) -> String {
        let directory = S3HourScopedDirectory::withdraw(unix_millis_to_seconds(timestamp_ms));
        format!(
            "{directory}{:020}-{session_id}-wid{}.json",
            self.request_data.seq, self.request_data.wid,
        )
    }

    pub fn wid(&self) -> WithdrawalID {
        self.request_data.wid
    }
}
