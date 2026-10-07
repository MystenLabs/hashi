// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3HourDirectory;
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
    pub fn object_key(&self, timestamp_ms: UnixMillis) -> anyhow::Result<String> {
        let directory = S3HourDirectory::withdraw(unix_millis_to_seconds(timestamp_ms))?;
        Ok(format!(
            "{directory}{:020}-wid{}.json",
            self.request_data.seq, self.request_data.wid,
        ))
    }

    /// Return the seq and the wid from a key that [`Self::object_key`] made.
    /// Return `None` if the file name is not canonical.
    pub fn parse_object_key(key: &str) -> Option<(u64, WithdrawalID)> {
        let name = key.rsplit('/').next()?;
        let (seq, wid) = name.strip_suffix(".json")?.split_once("-wid")?;
        let seq = seq.parse().ok()?;
        let wid = WithdrawalID::from_hex(wid).ok()?;
        (name == format!("{seq:020}-wid{wid}.json")).then_some((seq, wid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WID: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";

    #[test]
    fn parse_object_key_reads_the_seq_and_wid() {
        let key = format!("withdraw/2026/10/06/12/00000000000000000042-wid{WID}.json");
        let (seq, wid) = WithdrawalLogMessage::parse_object_key(&key).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(wid.to_string(), WID);
        let max = format!("withdraw/2026/10/06/12/{:020}-wid{WID}.json", u64::MAX);
        assert_eq!(
            WithdrawalLogMessage::parse_object_key(&max).map(|(seq, _)| seq),
            Some(u64::MAX)
        );
    }

    #[test]
    fn parse_object_key_rejects_noncanonical_names() {
        for key in [
            format!("withdraw/2026/10/06/12/unknown-s-wid{WID}.json"),
            format!("withdraw/2026/10/06/12/0042-wid{WID}.json"),
            format!("withdraw/2026/10/06/12/99999999999999999999-wid{WID}.json"),
            format!("withdraw/2026/10/06/12/00000000000000000042-wid{WID}"),
            "withdraw/2026/10/06/12/00000000000000000042-wid0xaa.json".to_string(),
            "withdraw/2026/10/06/12/00000000000000000042-widxyz.json".to_string(),
            "withdraw/2026/10/06/12/".to_string(),
        ] {
            assert_eq!(WithdrawalLogMessage::parse_object_key(&key), None, "{key}");
        }
    }
}
