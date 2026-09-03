// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianReader;
use super::VerifiedLogRecord;
use crate::HEARTBEAT_INTERVAL;
use crate::LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE;
use crate::OTHER_SESSION_QUIET_PERIOD;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::time::now_timestamp_ms;
use hashi_types::guardian::time::unix_millis_to_seconds;
use hashi_types::guardian::time::UnixMillis;
use hashi_types::guardian::GuardianError::CurrentSessionHeartbeatNotLive;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianError::PriorSessionHeartbeatStillRecent;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::info;

#[derive(Debug)]
struct HeartbeatScan {
    sessions: Vec<GuardianSessionInfo>,
    started_at: UnixMillis,
    completed_at: UnixMillis,
}

#[derive(Debug, Clone)]
struct GuardianSessionInfo {
    session_id: SessionID,
    first_heartbeat: UnixMillis,
    last_heartbeat: UnixMillis,
}

impl GuardianReader {
    /// Enforces that `live_session` has heartbeated recently.
    pub async fn ensure_session_live(&mut self, live_session: &str) -> GuardianResult<()> {
        let scan = self.read_recent_heartbeat_summary().await?;
        let live_session_info =
            validate_session_live(&scan.sessions, scan.completed_at, live_session)?;

        info!(
            session_id = %live_session,
            first_heartbeat_ms = live_session_info.first_heartbeat,
            last_heartbeat_ms = live_session_info.last_heartbeat,
            age_secs = unix_millis_to_seconds(
                scan.completed_at.saturating_sub(live_session_info.last_heartbeat)
            ),
            "session heartbeat check passed"
        );
        Ok(())
    }

    /// Enforces that `live_session` has heartbeated recently, while every other
    /// guardian session has been quiet long enough to no longer be considered
    /// active.
    pub async fn ensure_session_live_and_others_quiet(
        &mut self,
        live_session: &str,
    ) -> GuardianResult<()> {
        let scan = self.read_recent_heartbeat_summary().await?;

        let live_session_info =
            validate_session_live(&scan.sessions, scan.completed_at, live_session)?;
        // The quiet boundary must already have passed when the final scan
        // begins; crossing it while reading S3 is not sufficient.
        validate_other_sessions_quiet(
            &scan.sessions,
            scan.started_at,
            live_session,
            OTHER_SESSION_QUIET_PERIOD,
        )?;

        info!(
            session_id = %live_session,
            first_heartbeat_ms = live_session_info.first_heartbeat,
            last_heartbeat_ms = live_session_info.last_heartbeat,
            age_secs = unix_millis_to_seconds(
                scan.completed_at.saturating_sub(live_session_info.last_heartbeat)
            ),
            "activation heartbeat check passed"
        );
        Ok(())
    }

    async fn read_recent_heartbeat_summary(&mut self) -> GuardianResult<HeartbeatScan> {
        let started_at = now_timestamp_ms();
        let recent_heartbeats = self.read_recent_heartbeat_logs(started_at).await?;
        let sessions = summarize_heartbeats_by_session(recent_heartbeats)?;
        Ok(HeartbeatScan {
            sessions,
            started_at,
            completed_at: now_timestamp_ms(),
        })
    }

    async fn read_recent_heartbeat_logs(
        &mut self,
        reference_time: UnixMillis,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        // Read from the previous, current, and next hour-scoped prefixes to
        // cover clock-boundary cases and moderate clock skew.
        let one_hour_ago = unix_millis_to_seconds(reference_time).saturating_sub(60 * 60);
        let mut cursor = S3HourScopedDirectory::heartbeat(one_hour_ago);
        let mut logs = Vec::new();
        for _ in 0..3 {
            logs.extend(self.read_logs_in_dir(&cursor).await?);
            cursor = cursor.next_dir();
        }
        Ok(logs)
    }
}

fn summarize_heartbeats_by_session(
    logs: Vec<VerifiedLogRecord>,
) -> GuardianResult<Vec<GuardianSessionInfo>> {
    let mut map: BTreeMap<SessionID, (UnixMillis, UnixMillis)> = BTreeMap::new();

    for log in logs {
        let entry = log.into_entry();
        let session_id = entry.session_id().clone();
        let ts = entry.timestamp_ms();
        match entry.into_message() {
            V1(LogMessageV1::Heartbeat(..)) | V2(LogMessageV2::Heartbeat(..)) => {}
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(
                    "non-heartbeat log found under the heartbeat prefix".into(),
                ));
            }
        }

        map.entry(session_id)
            .and_modify(|(first, last)| {
                *first = (*first).min(ts);
                *last = (*last).max(ts);
            })
            .or_insert((ts, ts));
    }

    Ok(map
        .into_iter()
        .map(
            |(session_id, (first_heartbeat, last_heartbeat))| GuardianSessionInfo {
                session_id,
                first_heartbeat,
                last_heartbeat,
            },
        )
        .collect())
}

fn validate_other_sessions_quiet(
    summary: &[GuardianSessionInfo],
    scan_started_at: UnixMillis,
    live_session: &str,
    other_session_quiet_period: Duration,
) -> GuardianResult<()> {
    if let Some(most_recent_other_session) = summary
        .iter()
        .filter(|s| s.session_id.as_str() != live_session)
        .max_by_key(|s| s.last_heartbeat)
    {
        let heartbeat_age_ms =
            scan_started_at.saturating_sub(most_recent_other_session.last_heartbeat);
        if u128::from(heartbeat_age_ms) < other_session_quiet_period.as_millis() {
            return Err(PriorSessionHeartbeatStillRecent {
                session_id: most_recent_other_session.session_id.clone(),
                heartbeat_age_secs: unix_millis_to_seconds(heartbeat_age_ms),
                required_quiet_secs: other_session_quiet_period.as_secs(),
            });
        }
    }
    Ok(())
}

fn validate_session_live<'a>(
    summary: &'a [GuardianSessionInfo],
    now: UnixMillis,
    live_session: &str,
) -> GuardianResult<&'a GuardianSessionInfo> {
    let live_session_info = summary
        .iter()
        .find(|s| s.session_id.as_str() == live_session)
        .ok_or_else(|| CurrentSessionHeartbeatNotLive {
            session_id: live_session.into(),
            heartbeat_age_secs: None,
            retry_after_secs: HEARTBEAT_INTERVAL.as_secs(),
        })?;
    let live_session_age_ms = now.saturating_sub(live_session_info.last_heartbeat);
    if u128::from(live_session_age_ms) > LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE.as_millis() {
        return Err(CurrentSessionHeartbeatNotLive {
            session_id: live_session.into(),
            heartbeat_age_secs: Some(unix_millis_to_seconds(live_session_age_ms)),
            retry_after_secs: HEARTBEAT_INTERVAL.as_secs(),
        });
    }
    Ok(live_session_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::InitLogMessage;
    use hashi_types::guardian::LogMessage;

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn heartbeat_log(session_id: &str, timestamp_ms: UnixMillis) -> VerifiedLogRecord {
        verified_log(
            session_id,
            timestamp_ms,
            LogMessage::Heartbeat(HeartbeatLogMessage::new(0)),
        )
    }

    fn non_heartbeat_log() -> VerifiedLogRecord {
        verified_log(
            "test-session",
            0,
            LogMessage::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 0,
                share_ids: vec![],
                enclave_btc_pubkey: hashi_types::bitcoin::create_btc_keypair_for_test(&[1; 32])
                    .x_only_public_key()
                    .0,
            })),
        )
    }

    fn verified_log(session_id: &str, timestamp_ms: u64, message: LogMessage) -> VerifiedLogRecord {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let entry = hashi_types::guardian::LogRecord::new_at_timestamp(
            session_id.into(),
            message,
            &signing_key,
            timestamp_ms,
        )
        .into_entry_unchecked();
        VerifiedLogRecord::new_for_test(entry, build_pcrs())
    }

    #[test]
    fn summarize_heartbeats_tracks_latest_per_session() {
        let summary = summarize_heartbeats_by_session(vec![
            heartbeat_log("b", 20_000),
            heartbeat_log("a", 10_000),
            heartbeat_log("a", 30_000),
        ])
        .unwrap();

        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].session_id.as_str(), "a");
        assert_eq!(summary[0].first_heartbeat, 10_000);
        assert_eq!(summary[0].last_heartbeat, 30_000);
        assert_eq!(summary[1].session_id.as_str(), "b");
        assert_eq!(summary[1].first_heartbeat, 20_000);
        assert_eq!(summary[1].last_heartbeat, 20_000);
    }

    #[test]
    fn summarize_heartbeats_rejects_non_heartbeat_logs() {
        let err = summarize_heartbeats_by_session(vec![non_heartbeat_log()])
            .expect_err("must reject non-heartbeat logs");
        assert!(err.to_string().contains("non-heartbeat log"));
    }

    #[test]
    fn validate_other_sessions_quiet_accepts_quiet_session() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 990_000,
                last_heartbeat: 990_000,
            },
            GuardianSessionInfo {
                session_id: "old".into(),
                first_heartbeat: 400_000,
                last_heartbeat: 400_000,
            },
        ];

        validate_other_sessions_quiet(&summary, 1_000_000, "live", Duration::from_secs(600))
            .expect("other session is quiet at the exact millisecond boundary");
    }

    #[test]
    fn validate_other_sessions_quiet_rejects_one_millisecond_short() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 990_000,
                last_heartbeat: 990_000,
            },
            GuardianSessionInfo {
                session_id: "old".into(),
                first_heartbeat: 400_001,
                last_heartbeat: 400_001,
            },
        ];

        validate_other_sessions_quiet(&summary, 1_000_000, "live", Duration::from_secs(600))
            .expect_err("the complete quiet period must pass before the scan starts");
    }

    #[test]
    fn validate_session_live_allows_another_live_session() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "target".into(),
                first_heartbeat: 990_000,
                last_heartbeat: 990_000,
            },
            GuardianSessionInfo {
                session_id: "active".into(),
                first_heartbeat: 995_000,
                last_heartbeat: 995_000,
            },
        ];

        validate_session_live(&summary, 1_000_000, "target")
            .expect("target session is live even while the active session also heartbeats");
    }

    #[test]
    fn heartbeat_validators_accept_boundary_ages() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 820_000,
                last_heartbeat: 820_000,
            },
            GuardianSessionInfo {
                session_id: "old".into(),
                first_heartbeat: 400_000,
                last_heartbeat: 400_000,
            },
        ];

        validate_session_live(&summary, 1_000_000, "live")
            .expect("live session heartbeat is at the age boundary");
        validate_other_sessions_quiet(&summary, 1_000_000, "live", Duration::from_secs(600))
            .expect("other session heartbeat is at the quiet boundary");
    }

    #[test]
    fn validate_session_live_fails_when_session_missing() {
        let summary = vec![GuardianSessionInfo {
            session_id: "old".into(),
            first_heartbeat: 200_000,
            last_heartbeat: 200_000,
        }];

        let err = validate_session_live(&summary, 1_000_000, "live")
            .expect_err("must require heartbeat for live session");
        assert_eq!(
            err,
            CurrentSessionHeartbeatNotLive {
                session_id: "live".into(),
                heartbeat_age_secs: None,
                retry_after_secs: HEARTBEAT_INTERVAL.as_secs(),
            }
        );
    }

    #[test]
    fn validate_session_live_fails_when_session_stale() {
        let summary = vec![GuardianSessionInfo {
            session_id: "live".into(),
            first_heartbeat: 800_000,
            last_heartbeat: 800_000,
        }];

        let err = validate_session_live(&summary, 1_000_001, "live")
            .expect_err("must reject stale live session");
        assert_eq!(
            err,
            CurrentSessionHeartbeatNotLive {
                session_id: "live".into(),
                heartbeat_age_secs: Some(200),
                retry_after_secs: HEARTBEAT_INTERVAL.as_secs(),
            }
        );
    }

    #[test]
    fn validate_other_sessions_quiet_reports_most_recent_heartbeat() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 990_000,
                last_heartbeat: 990_000,
            },
            GuardianSessionInfo {
                session_id: "other-older".into(),
                first_heartbeat: 920_000,
                last_heartbeat: 920_000,
            },
            GuardianSessionInfo {
                session_id: "other-newer".into(),
                first_heartbeat: 950_000,
                last_heartbeat: 950_000,
            },
        ];

        let err =
            validate_other_sessions_quiet(&summary, 1_000_000, "live", Duration::from_secs(100))
                .expect_err("must reject a recent heartbeat from another session");
        assert_eq!(
            err,
            PriorSessionHeartbeatStillRecent {
                session_id: "other-newer".into(),
                heartbeat_age_secs: 50,
                required_quiet_secs: 100,
            }
        );
    }
}
