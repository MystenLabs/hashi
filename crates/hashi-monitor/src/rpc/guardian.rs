// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian poller: the withdrawal E2 events read from the guardian's
//! S3 logs, one hourly directory at a time, while the directory fills.
//!
//! Why it exists: the guardian's signature on a withdrawal is only recorded
//! in its log. The poller reads the log through `GuardianReader`, which
//! verifies each session's attestation against the allowlist and each
//! record's signature.
//!
//! How it works:
//! 1. The `GuardianCursor` names an hourly directory. Each poll lists it and
//!    reads only the keys it has not read yet, so an E2 arrives within a poll.
//! 2. Every verified withdrawal log becomes an E2 event. A log whose signed
//!    time differs from its S3 `LastModified` time by more than
//!    `MAX_EXPECTED_LOG_CLOCK_SKEW` is also a finding.
//! 3. The guardian's limiter takes each `seq` once, in order, so the logs
//!    have the seqs 0, 1, 2, ... A second log for a seq is a
//!    `GuardianInconsistency::SeqDuplicate` finding.
//! 4. A seq that a higher seq skips is a gap. It may still appear in the
//!    next directory. A skip of more than `MAX_SEQ_SKIP` seqs is a `SeqJump`
//!    finding at once. A gap still open at the end of that directory is a
//!    `GuardianInconsistency::SeqGap` finding.
//! 5. Once the directory's write completion time has passed, a last poll
//!    reads it, and the cursor moves to the next directory.
//!
//! Assumptions:
//! - The bridge keys are read once, before polling, from the genesis and
//!   ceremony records. They never change.
//! - The guardian's clock does not step back by more than one directory
//!   between two logs. A later seq is then never two directories early.
//! - A first run starts at the bridge's genesis, before the first
//!   withdrawal log. Its seq is 0.

use crate::config::Config;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::findings::GuardianInconsistency;
use crate::findings::MonitorFinding;
use crate::keys::HashiBTCKeys;
use crate::rpc::PollCursor;
use crate::time::utc_timestamp;
use anyhow::Context;
use bitcoin::Network;
use hashi_guardian::MAX_EXPECTED_LOG_CLOCK_SKEW;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::s3::S3HourDirectory;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;
use serde::Deserialize;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use sui_sdk_types::Address;
use tracing::debug;

/// The most seqs one log may skip before a `SeqJump` finding. A skip is
/// rare, so a larger one is a finding, and the skipped seqs are not tracked.
const MAX_SEQ_SKIP: u64 = 10;

/// How far the guardian log is read, and the seqs it has.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GuardianCursor {
    /// The directory read now. Every earlier directory is read in full.
    dir: S3HourDirectory,
    /// The keys read in `dir`.
    dir_keys: BTreeSet<String>,
    /// The seq after the highest seq read. The first log in a bucket has
    /// seq 0, because the guardian's limiter starts there.
    next_seq: u64,
    /// The seqs skipped in `dir`. Their logs may come until the end of the
    /// next directory.
    gaps: BTreeSet<u64>,
    /// The seqs skipped in the directory before `dir`. Their logs must come
    /// by the end of `dir`.
    due_gaps: BTreeSet<u64>,
}

impl GuardianCursor {
    pub fn new(dir: S3HourDirectory) -> Self {
        Self {
            dir,
            dir_keys: BTreeSet::new(),
            next_seq: 0,
            gaps: BTreeSet::new(),
            due_gaps: BTreeSet::new(),
        }
    }

    /// The start of `dir`. Every log before it is read.
    pub fn read_until(&self) -> UnixSeconds {
        self.dir.to_unix_seconds()
    }

    fn is_new(&self, key: &str) -> bool {
        !self.dir_keys.contains(key)
    }

    /// Record the read log `key` with `seq`. Return the inconsistency it
    /// shows, if any.
    fn record(&mut self, key: String, seq: u64) -> Option<GuardianInconsistency> {
        // `poll` reads only new keys, and a list has each key once.
        let new = self.dir_keys.insert(key.clone());
        assert!(new, "the guardian log {key} was read twice");
        match seq.cmp(&self.next_seq) {
            // A seq below `next_seq` is a late log for a gap, or a duplicate.
            Ordering::Less => {
                if !self.gaps.remove(&seq) && !self.due_gaps.remove(&seq) {
                    return Some(GuardianInconsistency::SeqDuplicate {
                        seq,
                        object_key: key,
                    });
                }
                tracing::info!(seq, key, "a late guardian log filled a seq gap");
                None
            }
            Ordering::Equal => {
                self.next_seq = seq.saturating_add(1);
                None
            }
            // A seq above `next_seq` skips the seqs between them.
            Ordering::Greater => {
                let next_seq = self.next_seq;
                self.next_seq = seq.saturating_add(1);
                if seq - next_seq > MAX_SEQ_SKIP {
                    return Some(GuardianInconsistency::SeqJump {
                        next_seq,
                        seq,
                        object_key: key,
                    });
                }
                tracing::info!(
                    first_missing = next_seq,
                    last_missing = seq - 1,
                    key,
                    "a guardian log skipped seqs; they are gaps"
                );
                self.gaps.extend(next_seq..seq);
                None
            }
        }
    }

    /// Move to the next directory. Return a gap for each due seq that no
    /// log filled.
    fn finish_dir(&mut self) -> anyhow::Result<Vec<GuardianInconsistency>> {
        self.dir = self.dir.next_dir()?;
        self.dir_keys.clear();
        let expect_by = self.dir.to_unix_seconds();
        let due = std::mem::take(&mut self.due_gaps);
        self.due_gaps = std::mem::take(&mut self.gaps);
        Ok(due
            .into_iter()
            .map(|seq| GuardianInconsistency::SeqGap { seq, expect_by })
            .collect())
    }
}

/// What one guardian poll read.
pub struct GuardianPoll {
    pub events: Vec<MonitorEvent>,
    pub findings: Vec<MonitorFinding>,
    /// Whether the poll finished the directory and moved the cursor.
    pub dir_done: bool,
}

pub struct GuardianWithdrawalsPoller {
    /// Owns the S3 client + the trusted-key cache, so a session's attestation is
    /// verified once for the poller's lifetime.
    reader: GuardianReader,
    cursor: GuardianCursor,
    /// Set by `read_hashi_btc_keys`. The guardian's internal outputs state a
    /// derivation path, and the keys turn it into the address they pay.
    hashi_btc_keys: Option<HashiBTCKeys>,
}

impl PollCursor for GuardianWithdrawalsPoller {
    type Position = GuardianCursor;

    fn read_until(&self) -> UnixSeconds {
        self.cursor.read_until()
    }

    fn next_item_to_poll(&self) -> Self::Position {
        self.cursor.clone()
    }
}

impl GuardianWithdrawalsPoller {
    /// Fails if S3 cannot be reached.
    pub async fn new(config: &Config, start: GuardianCursor) -> anyhow::Result<Self> {
        let s3_credentials =
            hashi_guardian::resolve_s3_credentials(config.s3_credentials.as_ref()).await?;
        Ok(Self {
            reader: GuardianReader::new(config.deployment.clone(), s3_credentials).await?,
            cursor: start,
            hashi_btc_keys: None,
        })
    }

    /// The two keys every bridge address derives from, and the Hashi object
    /// id. They never change. The MPC master key and the object id come from
    /// the KP-authorized genesis record and the guardian's Bitcoin key from
    /// the latest ceremony record, both verified against the allowlist.
    pub async fn read_hashi_identity(
        &mut self,
        network: Network,
    ) -> anyhow::Result<(HashiBTCKeys, Address)> {
        let genesis = self
            .reader
            .read_genesis()
            .await
            .context("failed to read the guardian genesis record")?
            .context("the guardian genesis record does not exist")?;
        let ceremony = self
            .reader
            .read_latest_ceremony_state()
            .await
            .context("failed to read the guardian ceremony record")?;
        let keys = HashiBTCKeys::new(ceremony.btc_master_pubkey, genesis.mpc_master_g, network);
        tracing::info!(
            change_script = %keys.script_pubkey(None),
            hashi_object_id = %genesis.hashi_object_id,
            "read the Hashi identity from the guardian records"
        );
        self.hashi_btc_keys = Some(keys.clone());
        Ok((keys, genesis.hashi_object_id))
    }

    /// Read the logs of the current directory that are not read yet. Once
    /// the directory's write completion time has passed, finish it.
    pub async fn poll(&mut self) -> anyhow::Result<GuardianPoll> {
        // Decide before the list, so the last list sees every write.
        let dir_done = now_timestamp_secs() >= self.cursor.dir.write_completion_time();
        let dir = self.cursor.dir.clone();
        let cursor = &self.cursor;
        let mut verified_logs = self
            .reader
            .read_logs_in_dir_where(&dir, |key| cursor.is_new(key))
            .await?;
        // The seq rules need seq order. Sort by the signed seq, so the order
        // does not depend on the key format.
        verified_logs.sort_by_key(|log| {
            let message = log.entry().message().as_withdrawal();
            message.map(|withdrawal| withdrawal.request_data.seq)
        });
        // A failed poll leaves the cursor as it was, so the retry reads the
        // same logs again.
        let mut next = self.cursor.clone();
        // Withdrawal polling may replay historical buckets during an upgrade, so
        // this caller accepts any record whose session build verifies against the
        // configured allowlist. Add a cursor/cutoff policy here if tailing must
        // require the current build after the upgrade window.
        let keys = self
            .hashi_btc_keys
            .as_ref()
            .context("the bridge keys must be read before polling guardian logs")?;
        let mut findings = Vec::new();
        let mut withdrawal_events = Vec::with_capacity(verified_logs.len());
        for log in verified_logs {
            // Each record is one sample of the guardian's clock against AWS
            // time, plus the write latency.
            if log.exceeds_clock_skew(MAX_EXPECTED_LOG_CLOCK_SKEW) {
                findings.push(MonitorFinding::GuardianClockSkew {
                    session_id: log.session_id().clone(),
                    object_key: log.entry().object_key().to_owned(),
                    logged_at_ms: log.entry().timestamp_ms(),
                    stored_at_ms: log.stored_at_ms(),
                });
            }
            let entry = log.into_entry();
            let object_key = entry.object_key().to_owned();
            let timestamp_ms = entry.timestamp_ms();
            let withdrawal = entry
                .into_message()
                .into_withdrawal()
                .context("non-withdrawal log in the guardian's withdrawal logs")?;
            let inconsistency = next.record(object_key, withdrawal.request_data.seq);
            findings.extend(inconsistency.map(MonitorFinding::GuardianInconsistency));
            match MonitorWithdrawalEvent::from_guardian(&withdrawal, timestamp_ms, keys) {
                Ok(event) => {
                    debug!(wid = %event.wid, txid = %event.btc_txid, "guardian withdrawal log");
                    withdrawal_events.push(MonitorEvent::Withdrawal(event));
                }
                Err(found) => findings.extend(found),
            }
        }
        if dir_done {
            let gaps = next.finish_dir()?;
            findings.extend(gaps.into_iter().map(MonitorFinding::GuardianInconsistency));
        }
        self.cursor = next;
        tracing::info!(
            dir = %utc_timestamp(dir.to_unix_seconds()),
            events = withdrawal_events.len(),
            dir_done,
            "read guardian logs"
        );
        Ok(GuardianPoll {
            events: withdrawal_events,
            findings,
            dir_done,
        })
    }
}

#[cfg(test)]
impl GuardianWithdrawalsPoller {
    /// A poller over a mock S3 client, for tests that never poll it.
    pub(crate) fn for_tests(config: &Config, start: UnixSeconds) -> Self {
        Self {
            reader: hashi_guardian::test_utils::mock_reader(config.deployment.clone()),
            cursor: GuardianCursor::new(
                S3HourDirectory::withdraw(start).expect("valid test timestamp"),
            ),
            hashi_btc_keys: Some(crate::test_utils::test_hashi_btc_keys()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: UnixSeconds = 1_700_000_000 / 3_600 * 3_600;

    fn cursor() -> GuardianCursor {
        GuardianCursor::new(S3HourDirectory::withdraw(HOUR).unwrap())
    }

    fn record(cursor: &mut GuardianCursor, seq: u64) -> Option<GuardianInconsistency> {
        cursor.record(format!("key-{seq}"), seq)
    }

    #[test]
    fn seqs_in_order_give_no_finding() {
        let mut cursor = cursor();
        for seq in 0..4 {
            assert_eq!(record(&mut cursor, seq), None);
        }
        assert!(!cursor.is_new("key-2"));
        assert_eq!(cursor.finish_dir().unwrap(), vec![]);
        assert!(cursor.is_new("key-2"));
        assert_eq!(cursor.read_until(), HOUR + 3_600);
    }

    #[test]
    fn a_second_log_for_a_seq_is_a_duplicate() {
        let mut cursor = cursor();
        assert_eq!(record(&mut cursor, 0), None);
        assert_eq!(
            cursor.record("other-0".to_string(), 0),
            Some(GuardianInconsistency::SeqDuplicate {
                seq: 0,
                object_key: "other-0".to_string(),
            })
        );
    }

    #[test]
    fn a_gap_may_close_in_the_next_directory() {
        let mut cursor = cursor();
        assert_eq!(record(&mut cursor, 0), None);
        assert_eq!(record(&mut cursor, 2), None);
        assert_eq!(cursor.finish_dir().unwrap(), vec![]);

        assert_eq!(record(&mut cursor, 1), None);
        assert_eq!(cursor.finish_dir().unwrap(), vec![]);
        // A seq whose gap closed is a duplicate after that.
        assert!(matches!(
            cursor.record("again-1".to_string(), 1),
            Some(GuardianInconsistency::SeqDuplicate { seq: 1, .. })
        ));
    }

    #[test]
    fn a_gap_open_at_the_end_of_the_next_directory_is_a_finding() {
        let mut cursor = cursor();
        // The first log in a bucket has seq 0, so seq 0 is a gap too.
        assert_eq!(record(&mut cursor, 2), None);
        assert_eq!(cursor.finish_dir().unwrap(), vec![]);

        assert_eq!(record(&mut cursor, 1), None);
        assert_eq!(
            cursor.finish_dir().unwrap(),
            vec![GuardianInconsistency::SeqGap {
                seq: 0,
                expect_by: HOUR + 2 * 3_600,
            }]
        );
    }

    #[test]
    fn a_skip_of_more_than_the_limit_is_a_jump() {
        let mut cursor = cursor();
        assert_eq!(record(&mut cursor, 0), None);
        assert_eq!(record(&mut cursor, 1 + MAX_SEQ_SKIP), None);
        assert_eq!(
            record(&mut cursor, 3 + 2 * MAX_SEQ_SKIP),
            Some(GuardianInconsistency::SeqJump {
                next_seq: 2 + MAX_SEQ_SKIP,
                seq: 3 + 2 * MAX_SEQ_SKIP,
                object_key: format!("key-{}", 3 + 2 * MAX_SEQ_SKIP),
            })
        );
        // A jump adds no gaps; the next seq continues after it.
        assert_eq!(record(&mut cursor, 4 + 2 * MAX_SEQ_SKIP), None);
    }

    #[test]
    fn a_cursor_with_gaps_round_trips_through_json() {
        let mut cursor = cursor();
        assert_eq!(record(&mut cursor, 1), None);
        cursor.finish_dir().unwrap();
        assert_eq!(record(&mut cursor, 3), None);

        let json = serde_json::to_string(&cursor).unwrap();
        assert_eq!(
            serde_json::from_str::<GuardianCursor>(&json).unwrap(),
            cursor
        );
    }
}
