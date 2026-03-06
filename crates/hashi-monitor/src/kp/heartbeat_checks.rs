use crate::domain::now_unix_seconds;
use crate::rpc::guardian::GuardianLogDir;
use crate::rpc::guardian::GuardianPollerCore;
use hashi_guardian_enclave::s3_logger::S3Logger;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::VerifiedLogRecord;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::time_utils::unix_millis_to_seconds;
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::info;

/// Heartbeat-audit logic used by the KP flow.
///
/// The audit enforces a single-live-session invariant before a KP submits `ProvisionerInit`:
/// - exactly one session is considered live (latest heartbeat is recent), and
/// - all other sessions have been quiet long enough.
///
/// Maximum acceptable heartbeat age for the selected "live" session.
/// Set to HEARTBEAT_INTERVAL + grace period to account for clock skew and retries.
const LIVE_SESSION_MAX_AGE: Duration = Duration::from_mins(3);

/// If another session has a heartbeat in the last X secs (X is given below), it is considered still active.
/// MAX_HEARTBEAT_FAILURES * HEARTBEAT_INTERVAL + grace period to account for retries and clock skew.
const OTHER_SESSION_QUIET_PERIOD: Duration = Duration::from_mins(10);

#[derive(Debug, Clone)]
pub struct GuardianSessionInfo {
    /// Session identifier derived from the guardian signing key.
    pub session_id: String,
    /// Earliest heartbeat timestamp observed for this session.
    pub first_heartbeat: UnixSeconds,
    /// Latest heartbeat timestamp observed for this session.
    pub last_heartbeat: UnixSeconds,
}

/// Implements check A of IOP-225.
///
/// Returns the selected live session id if all invariants pass.
pub async fn kp_heartbeat_audit(s3_client: &S3Logger) -> anyhow::Result<String> {
    let recent_heartbeats = read_recent_heartbeats(s3_client).await?;
    let summary = summarize_heartbeats_by_session(recent_heartbeats)?;
    let now = now_unix_seconds();
    select_live_session(
        &summary,
        now,
        LIVE_SESSION_MAX_AGE.as_secs(),
        OTHER_SESSION_QUIET_PERIOD.as_secs(),
    )
}

async fn read_recent_heartbeats(s3_client: &S3Logger) -> anyhow::Result<Vec<VerifiedLogRecord>> {
    // Read from the current and next hour-scoped prefixes to cover clock-boundary cases.
    let one_hour_ago = now_unix_seconds().saturating_sub(60 * 60);
    let mut poller = GuardianPollerCore::from_s3_client(
        s3_client.clone(),
        one_hour_ago,
        GuardianLogDir::Heartbeat,
    );
    let mut logs = Vec::new();
    logs.extend(poller.read_cur_dir().await?);
    poller.advance_cursor();
    logs.extend(poller.read_cur_dir().await?);
    Ok(logs)
}

/// Aggregates verified heartbeat logs into [first, last] bounds per session.
fn summarize_heartbeats_by_session(
    logs: Vec<VerifiedLogRecord>,
) -> anyhow::Result<Vec<GuardianSessionInfo>> {
    let mut map: BTreeMap<String, (UnixSeconds, UnixSeconds)> = BTreeMap::new();

    for log in logs {
        if !matches!(log.message, LogMessage::Heartbeat { .. }) {
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

/// Checks that exactly one session is live and returns its ID.
///
/// A session is considered live when its latest heartbeat is not older than
/// `live_session_max_age_secs`. Any other session with a heartbeat newer than
/// `other_session_quiet_secs` is treated as still active and causes a failure.
fn select_live_session(
    summary: &[GuardianSessionInfo],
    now: UnixSeconds,
    live_session_max_age_secs: UnixSeconds,
    other_session_quiet_secs: UnixSeconds,
) -> anyhow::Result<String> {
    let mut summary = summary.to_vec();

    summary.sort_by_key(|s| s.last_heartbeat);
    let live_session_info = summary
        .last()
        .ok_or_else(|| anyhow::anyhow!("no heartbeat logs found in the most recent 2 hours"))?;
    let live_session_id = &live_session_info.session_id;

    let live_session_age_secs = now.saturating_sub(live_session_info.last_heartbeat);
    if live_session_age_secs > live_session_max_age_secs {
        anyhow::bail!(
            "latest session {} is stale: last heartbeat {}s ago (expected <= {}s)",
            live_session_id,
            live_session_age_secs,
            live_session_max_age_secs
        );
    }

    let active_other_sessions = summary
        .iter()
        .filter(|s| s.session_id != *live_session_id)
        .filter_map(|s| {
            let age_secs = now.saturating_sub(s.last_heartbeat);
            (age_secs < other_session_quiet_secs)
                .then(|| format!("{} ({}s ago)", s.session_id, age_secs))
        })
        .collect::<Vec<_>>();
    if !active_other_sessions.is_empty() {
        anyhow::bail!(
            "other sessions are still active within {}s: {}",
            other_session_quiet_secs,
            active_other_sessions.join(", ")
        );
    }

    info!(
        "Selected session {} (first={}s, last={}s, age={}s)",
        live_session_id,
        live_session_info.first_heartbeat,
        live_session_info.last_heartbeat,
        now.saturating_sub(live_session_info.last_heartbeat)
    );

    Ok(live_session_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_live_session_picks_latest_session() {
        let now = 1_000;
        let summary = vec![
            GuardianSessionInfo {
                session_id: "old".to_string(),
                first_heartbeat: 100,
                last_heartbeat: 300,
            },
            GuardianSessionInfo {
                session_id: "new".to_string(),
                first_heartbeat: 600,
                last_heartbeat: 990,
            },
        ];

        let target =
            select_live_session(&summary, now, 100, 600).expect("must select newest session");
        assert_eq!(target, "new");
    }

    #[test]
    fn select_live_session_fails_when_empty() {
        let err = select_live_session(&[], 1_000, 100, 600).expect_err("must fail");
        assert!(err.to_string().contains("no heartbeat logs found"));
    }

    #[test]
    fn select_live_session_fails_when_latest_stale() {
        let summary = vec![GuardianSessionInfo {
            session_id: "only".to_string(),
            first_heartbeat: 100,
            last_heartbeat: 200,
        }];

        let err = select_live_session(&summary, 1_000, 100, 600).expect_err("must fail");
        assert!(err.to_string().contains("stale"));
    }

    #[test]
    fn select_live_session_fails_when_other_session_is_active() {
        let now = 1_000;
        let summary = vec![
            GuardianSessionInfo {
                session_id: "old".to_string(),
                first_heartbeat: 100,
                last_heartbeat: 950,
            },
            GuardianSessionInfo {
                session_id: "new".to_string(),
                first_heartbeat: 900,
                last_heartbeat: 990,
            },
        ];

        let err = select_live_session(&summary, now, 100, 100).expect_err("must fail");
        assert!(err.to_string().contains("other sessions are still active"));
    }
}
