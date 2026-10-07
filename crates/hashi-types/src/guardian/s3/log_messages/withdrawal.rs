// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3HourDirectory;
use crate::committee::CommitteeSignature;
use crate::guardian::GuardianError::InvalidS3Log;
use crate::guardian::GuardianResult;
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
    pub fn object_key(&self, timestamp_ms: UnixMillis) -> anyhow::Result<String> {
        let directory = S3HourDirectory::withdraw(unix_millis_to_seconds(timestamp_ms))?;
        Ok(Self::format_object_key(
            &directory.to_string(),
            self.request_data.seq,
            &self.request_data.wid,
        ))
    }

    fn format_object_key(prefix: &str, seq: u64, wid: &WithdrawalID) -> String {
        format!("{prefix}{seq:020}-wid{wid}.json")
    }

    /// Return the seq and the wid from a key that [`Self::object_key`] made under `prefix`.
    /// The caller supplies the complete directory prefix, including the final `/`.
    /// Return an error if the key is not the exact canonical form.
    pub fn parse_object_key(prefix: &str, key: &str) -> GuardianResult<(u64, WithdrawalID)> {
        let parsed = key
            .strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(".json"))
            .and_then(|name| name.split_once("-wid"))
            .and_then(|(seq, wid)| {
                Some((seq.parse::<u64>().ok()?, WithdrawalID::from_hex(wid).ok()?))
            });
        let Some((seq, wid)) = parsed else {
            return Err(InvalidS3Log(format!(
                "noncanonical withdrawal log key {key} for prefix {prefix}"
            )));
        };
        let expected_key = Self::format_object_key(prefix, seq, &wid);
        if key != expected_key {
            return Err(InvalidS3Log(format!(
                "noncanonical withdrawal log key: got {key}, expected {expected_key}"
            )));
        }
        Ok((seq, wid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WID: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";
    const PREFIX: &str = "withdraw/2026/10/06/12/";

    #[test]
    fn parse_object_key_reads_the_seq_and_wid() {
        let key = format!("{PREFIX}00000000000000000042-wid{WID}.json");
        let (seq, wid) = WithdrawalLogMessage::parse_object_key(PREFIX, &key).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(wid.to_string(), WID);
        let max = format!("{PREFIX}{:020}-wid{WID}.json", u64::MAX);
        let (seq, _) = WithdrawalLogMessage::parse_object_key(PREFIX, &max).unwrap();
        assert_eq!(seq, u64::MAX);
    }

    #[test]
    fn parse_object_key_rejects_noncanonical_keys() {
        for key in [
            format!("{PREFIX}unknown-s-wid{WID}.json"),
            format!("{PREFIX}0042-wid{WID}.json"),
            format!("{PREFIX}99999999999999999999-wid{WID}.json"),
            format!("{PREFIX}00000000000000000042-wid{WID}"),
            format!("{PREFIX}00000000000000000042-wid0xaa.json"),
            format!("{PREFIX}00000000000000000042-widxyz.json"),
            format!("withdraw/2026/10/06/13/00000000000000000042-wid{WID}.json"),
            format!("00000000000000000042-wid{WID}.json"),
            PREFIX.to_string(),
        ] {
            let error = WithdrawalLogMessage::parse_object_key(PREFIX, &key).unwrap_err();
            assert!(error.to_string().contains("noncanonical"), "{key}: {error}");
        }
    }
}
