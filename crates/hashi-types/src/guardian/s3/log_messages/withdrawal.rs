// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3HourDirectory;
use crate::committee::CommitteeSignature;
use crate::guardian::LimiterState;
use crate::guardian::StandardWithdrawalRequestWire;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
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
    pub fn object_key(&self, timestamp_ms: UnixMillis) -> anyhow::Result<String> {
        let directory = S3HourDirectory::withdraw(unix_millis_to_seconds(timestamp_ms))?;
        Ok(format!(
            "{directory}{:020}-wid{}.json",
            self.request_data.seq, self.request_data.wid,
        ))
    }

    /// Return the sequence number in a key from [`Self::object_key`].
    /// Return `None` if the file name does not start with 20 decimal digits.
    pub fn seq_from_object_key(key: &str) -> Option<u64> {
        let name = key.rsplit('/').next()?;
        name.get(..20)?.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_from_object_key_reads_the_zero_padded_prefix() {
        let key = "withdraw/2026/10/06/12/00000000000000000042-wid0xaa.json";
        assert_eq!(WithdrawalLogMessage::seq_from_object_key(key), Some(42));
        let max = format!("withdraw/2026/10/06/12/{:020}-wid0xaa.json", u64::MAX);
        assert_eq!(
            WithdrawalLogMessage::seq_from_object_key(&max),
            Some(u64::MAX)
        );
    }

    #[test]
    fn seq_from_object_key_rejects_other_file_names() {
        for key in [
            "withdraw/2026/10/06/12/unknown-s-wid0xaa.json",
            "withdraw/2026/10/06/12/0042-wid0xaa.json",
            "withdraw/2026/10/06/12/99999999999999999999-wid0xaa.json",
            "withdraw/2026/10/06/12/",
        ] {
            assert_eq!(
                WithdrawalLogMessage::seq_from_object_key(key),
                None,
                "{key}"
            );
        }
    }
}
