// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianReader;
use super::VerifiedLogRecord;
use crate::HEARTBEAT_INTERVAL;
use crate::LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE;
use crate::OTHER_SESSION_QUIET_PERIOD;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::time::unix_millis_to_seconds;
use hashi_types::guardian::time::UnixSeconds;
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
use tracing::info;

impl GuardianReader {
    /// Enforces that `live_session` has heartbeated recently.
    pub async fn ensure_session_live(&mut self, live_session: &str) -> GuardianResult<()> {
        let (summary, now) = self.read_recent_heartbeat_summary().await?;
        let live_session_info = validate_session_live(&summary, now, live_session)?;

        info!(
            session_id = %live_session,
            first_heartbeat = live_session_info.first_heartbeat,
            last_heartbeat = live_session_info.last_heartbeat,
            age_secs = now.saturating_sub(live_session_info.last_heartbeat),
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
        let (summary, now) = self.read_recent_heartbeat_summary().await?;

        let live_session_info = validate_session_live(&summary, now, live_session)?;
        validate_other_sessions_quiet(
            &summary,
            now,
            live_session,
            OTHER_SESSION_QUIET_PERIOD.as_secs(),
        )?;

        info!(
            session_id = %live_session,
            first_heartbeat = live_session_info.first_heartbeat,
            last_heartbeat = live_session_info.last_heartbeat,
            age_secs = now.saturating_sub(live_session_info.last_heartbeat),
            "activation heartbeat check passed"
        );
        Ok(())
    }

    async fn read_recent_heartbeat_summary(
        &mut self,
    ) -> GuardianResult<(Vec<GuardianSessionInfo>, UnixSeconds)> {
        let recent_heartbeats = self.read_recent_heartbeat_logs().await?;
        let summary = summarize_heartbeats_by_session(recent_heartbeats)?;
        Ok((summary, now_timestamp_secs()))
    }

    async fn read_recent_heartbeat_logs(&mut self) -> GuardianResult<Vec<VerifiedLogRecord>> {
        // Read from the previous, current, and next hour-scoped prefixes to
        // cover clock-boundary cases and moderate clock skew.
        let one_hour_ago = now_timestamp_secs().saturating_sub(60 * 60);
        let mut cursor = S3HourScopedDirectory::heartbeat(one_hour_ago);
        let mut logs = Vec::new();
        for _ in 0..3 {
            logs.extend(self.read_logs_in_dir(&cursor).await?);
            cursor = cursor.next_dir();
        }
        Ok(logs)
    }
}

#[derive(Debug, Clone)]
struct GuardianSessionInfo {
    session_id: SessionID,
    first_heartbeat: UnixSeconds,
    last_heartbeat: UnixSeconds,
}

fn summarize_heartbeats_by_session(
    logs: Vec<VerifiedLogRecord>,
) -> GuardianResult<Vec<GuardianSessionInfo>> {
    let mut map: BTreeMap<SessionID, (UnixSeconds, UnixSeconds)> = BTreeMap::new();

    for log in logs {
        let entry = log.into_entry();
        let session_id = entry.session_id().clone();
        let ts = unix_millis_to_seconds(entry.timestamp_ms());
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
    now: UnixSeconds,
    live_session: &str,
    other_session_quiet_secs: UnixSeconds,
) -> GuardianResult<()> {
    if let Some(most_recent_other_session) = summary
        .iter()
        .filter(|s| s.session_id.as_str() != live_session)
        .max_by_key(|s| s.last_heartbeat)
    {
        let heartbeat_age_secs = now.saturating_sub(most_recent_other_session.last_heartbeat);
        if heartbeat_age_secs < other_session_quiet_secs {
            return Err(PriorSessionHeartbeatStillRecent {
                session_id: most_recent_other_session.session_id.clone(),
                heartbeat_age_secs,
                required_quiet_secs: other_session_quiet_secs,
            });
        }
    }
    Ok(())
}

fn validate_session_live<'a>(
    summary: &'a [GuardianSessionInfo],
    now: UnixSeconds,
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
    let live_session_age_secs = now.saturating_sub(live_session_info.last_heartbeat);
    if live_session_age_secs > LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE.as_secs() {
        return Err(CurrentSessionHeartbeatNotLive {
            session_id: live_session.into(),
            heartbeat_age_secs: Some(live_session_age_secs),
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

    fn heartbeat_log(session_id: &str, timestamp_secs: UnixSeconds) -> VerifiedLogRecord {
        verified_log(
            session_id,
            timestamp_secs * 1_000,
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
            heartbeat_log("b", 20),
            heartbeat_log("a", 10),
            heartbeat_log("a", 30),
        ])
        .unwrap();

        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].session_id.as_str(), "a");
        assert_eq!(summary[0].first_heartbeat, 10);
        assert_eq!(summary[0].last_heartbeat, 30);
        assert_eq!(summary[1].session_id.as_str(), "b");
        assert_eq!(summary[1].first_heartbeat, 20);
        assert_eq!(summary[1].last_heartbeat, 20);
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
                first_heartbeat: 990,
                last_heartbeat: 990,
            },
            GuardianSessionInfo {
                session_id: "old".into(),
                first_heartbeat: 200,
                last_heartbeat: 200,
            },
        ];

        validate_other_sessions_quiet(&summary, 1_000, "live", 600)
            .expect("other session is quiet");
    }

    #[test]
    fn validate_session_live_allows_another_live_session() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "target".into(),
                first_heartbeat: 990,
                last_heartbeat: 990,
            },
            GuardianSessionInfo {
                session_id: "active".into(),
                first_heartbeat: 995,
                last_heartbeat: 995,
            },
        ];

        validate_session_live(&summary, 1_000, "target")
            .expect("target session is live even while the active session also heartbeats");
    }

    #[test]
    fn heartbeat_validators_accept_boundary_ages() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 820,
                last_heartbeat: 820,
            },
            GuardianSessionInfo {
                session_id: "old".into(),
                first_heartbeat: 400,
                last_heartbeat: 400,
            },
        ];

        validate_session_live(&summary, 1_000, "live")
            .expect("live session heartbeat is at the age boundary");
        validate_other_sessions_quiet(&summary, 1_000, "live", 600)
            .expect("other session heartbeat is at the quiet boundary");
    }

    #[test]
    fn validate_session_live_fails_when_session_missing() {
        let summary = vec![GuardianSessionInfo {
            session_id: "old".into(),
            first_heartbeat: 200,
            last_heartbeat: 200,
        }];

        let err = validate_session_live(&summary, 1_000, "live")
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
            first_heartbeat: 800,
            last_heartbeat: 800,
        }];

        let err = validate_session_live(&summary, 1_000, "live")
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
                first_heartbeat: 990,
                last_heartbeat: 990,
            },
            GuardianSessionInfo {
                session_id: "other-older".into(),
                first_heartbeat: 920,
                last_heartbeat: 920,
            },
            GuardianSessionInfo {
                session_id: "other-newer".into(),
                first_heartbeat: 950,
                last_heartbeat: 950,
            },
        ];

        let err = validate_other_sessions_quiet(&summary, 1_000, "live", 100)
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
