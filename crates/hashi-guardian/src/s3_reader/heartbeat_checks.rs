// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::heartbeat_cursor;
use super::GuardianReader;
use crate::LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE;
use crate::OTHER_SESSION_QUIET_PERIOD;
use hashi_types::guardian::time_utils::now_timestamp_secs;
use hashi_types::guardian::time_utils::unix_millis_to_seconds;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VerifiedLogRecord;
use std::collections::BTreeMap;
use tracing::info;

impl GuardianReader {
    /// Enforces that `live_session` has heartbeated recently, while every other
    /// guardian session has been quiet long enough to no longer be considered
    /// active.
    pub async fn ensure_session_live_and_others_quiet(
        &mut self,
        live_session: &str,
    ) -> anyhow::Result<()> {
        let recent_heartbeats = self.read_recent_heartbeats().await?;
        let summary = summarize_heartbeats_by_session(recent_heartbeats)?;
        let now = now_timestamp_secs();

        validate_session_live_and_others_quiet(
            &summary,
            now,
            live_session,
            LIVE_SESSION_LATEST_HEARTBEAT_MAX_AGE.as_secs(),
            OTHER_SESSION_QUIET_PERIOD.as_secs(),
        )?;

        let live_session_info = summary
            .iter()
            .find(|s| s.session_id.as_str() == live_session)
            .expect("validated live session must be present");
        info!(
            session_id = %live_session,
            first_heartbeat = live_session_info.first_heartbeat,
            last_heartbeat = live_session_info.last_heartbeat,
            age_secs = now.saturating_sub(live_session_info.last_heartbeat),
            "activation heartbeat check passed"
        );
        Ok(())
    }

    async fn read_recent_heartbeats(&mut self) -> anyhow::Result<Vec<VerifiedLogRecord>> {
        // Read from the previous, current, and next hour-scoped prefixes to
        // cover clock-boundary cases and moderate clock skew.
        let one_hour_ago = now_timestamp_secs().saturating_sub(60 * 60);
        let mut cursor = heartbeat_cursor(one_hour_ago);
        let mut logs = Vec::new();
        for _ in 0..3 {
            logs.extend(self.read_dir(&cursor).await?);
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
) -> anyhow::Result<Vec<GuardianSessionInfo>> {
    let mut map: BTreeMap<SessionID, (UnixSeconds, UnixSeconds)> = BTreeMap::new();

    for log in logs {
        if !matches!(log.message, LogMessage::V1(LogMessageV1::Heartbeat(..))) {
            anyhow::bail!("non-heartbeat logs found");
        }

        let ts = unix_millis_to_seconds(log.timestamp_ms);
        map.entry(log.session_id)
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

fn validate_session_live_and_others_quiet(
    summary: &[GuardianSessionInfo],
    now: UnixSeconds,
    live_session: &str,
    live_session_max_age_secs: UnixSeconds,
    other_session_quiet_secs: UnixSeconds,
) -> anyhow::Result<()> {
    let live_session_info = summary
        .iter()
        .find(|s| s.session_id.as_str() == live_session)
        .ok_or_else(|| anyhow::anyhow!("no heartbeat logs found for session {live_session}"))?;
    let live_session_age_secs = now.saturating_sub(live_session_info.last_heartbeat);
    if live_session_age_secs > live_session_max_age_secs {
        anyhow::bail!(
            "session {} is stale: last heartbeat {}s ago (expected <= {}s)",
            live_session,
            live_session_age_secs,
            live_session_max_age_secs
        );
    }

    let active_sessions = summary
        .iter()
        .filter(|s| s.session_id.as_str() != live_session)
        .filter_map(|s| {
            let age_secs = now.saturating_sub(s.last_heartbeat);
            (age_secs < other_session_quiet_secs)
                .then(|| format!("{} ({}s ago)", s.session_id, age_secs))
        })
        .collect::<Vec<_>>();
    if !active_sessions.is_empty() {
        anyhow::bail!(
            "sessions are still active within {}s: {}",
            other_session_quiet_secs,
            active_sessions.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::BuildPcrs;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::InitLogMessage;

    fn build_pcrs() -> BuildPcrs {
        BuildPcrs::new("current", vec![0])
    }

    fn heartbeat_log(session_id: &str, timestamp_secs: UnixSeconds) -> VerifiedLogRecord {
        VerifiedLogRecord {
            object_key: format!("heartbeat/{session_id}.json"),
            session_id: session_id.into(),
            timestamp_ms: timestamp_secs * 1_000,
            message: LogMessageV1::Heartbeat(HeartbeatLogMessage::new(0)).into(),
            build_pcrs: build_pcrs(),
        }
    }

    fn non_heartbeat_log() -> VerifiedLogRecord {
        VerifiedLogRecord {
            object_key: "init/test-session/03-pi-enclave-fully-initialized.json".to_string(),
            session_id: "test-session".into(),
            timestamp_ms: 0,
            message: LogMessageV1::Init(Box::new(InitLogMessage::PIEnclaveFullyInitialized {
                sharing_seq: 0,
                share_ids: vec![],
                enclave_btc_pubkey: hashi_types::bitcoin::create_btc_keypair_for_test(&[1; 32])
                    .x_only_public_key()
                    .0,
            }))
            .into(),
            build_pcrs: build_pcrs(),
        }
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
        assert_eq!(summary[0].last_heartbeat, 30);
        assert_eq!(summary[1].session_id.as_str(), "b");
        assert_eq!(summary[1].last_heartbeat, 20);
    }

    #[test]
    fn summarize_heartbeats_rejects_non_heartbeat_logs() {
        let err = summarize_heartbeats_by_session(vec![non_heartbeat_log()])
            .expect_err("must reject non-heartbeat logs");
        assert!(err.to_string().contains("non-heartbeat logs"));
    }

    #[test]
    fn validate_session_live_and_others_quiet_accepts_live_session() {
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

        validate_session_live_and_others_quiet(&summary, 1_000, "live", 100, 600)
            .expect("live session is recent and other session is quiet");
    }

    #[test]
    fn validate_session_live_and_others_quiet_fails_when_live_session_missing() {
        let summary = vec![GuardianSessionInfo {
            session_id: "old".into(),
            first_heartbeat: 200,
            last_heartbeat: 200,
        }];

        let err = validate_session_live_and_others_quiet(&summary, 1_000, "live", 100, 600)
            .expect_err("must require heartbeat for live session");
        assert!(err.to_string().contains("no heartbeat logs found"));
    }

    #[test]
    fn validate_session_live_and_others_quiet_fails_when_live_session_stale() {
        let summary = vec![GuardianSessionInfo {
            session_id: "live".into(),
            first_heartbeat: 800,
            last_heartbeat: 800,
        }];

        let err = validate_session_live_and_others_quiet(&summary, 1_000, "live", 100, 600)
            .expect_err("must reject stale live session");
        assert!(err.to_string().contains("stale"));
    }

    #[test]
    fn validate_session_live_and_others_quiet_fails_when_other_session_active() {
        let summary = vec![
            GuardianSessionInfo {
                session_id: "live".into(),
                first_heartbeat: 990,
                last_heartbeat: 990,
            },
            GuardianSessionInfo {
                session_id: "other".into(),
                first_heartbeat: 950,
                last_heartbeat: 950,
            },
        ];

        let err = validate_session_live_and_others_quiet(&summary, 1_000, "live", 100, 100)
            .expect_err("must reject active other session");
        assert!(err.to_string().contains("sessions are still active"));
    }
}
