use crate::domain::now_unix_seconds;
use crate::rpc::guardian::GuardianLogDir;
use crate::rpc::guardian::GuardianPollerCore;
use crate::rpc::guardian::VerifiedLogRecord;
use hashi_guardian_enclave::NO_HEARTBEAT_PERIOD;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::s3_utils::SECONDS_PER_HOUR;
use hashi_types::guardian::time_utils::UnixSeconds;
use hashi_types::guardian::time_utils::unix_millis_to_seconds;
use std::collections::BTreeMap;
use tracing::info;

#[derive(Debug, Clone)]
pub struct GuardianSessionInfo {
    pub session_id: String,
    pub first_heartbeat: UnixSeconds,
    pub last_heartbeat: UnixSeconds,
}

/// Implements check A of IOP-225
pub async fn kp_heartbeat_audits(cfg: &S3Config) -> anyhow::Result<String> {
    let one_hour_ago = now_unix_seconds().saturating_sub(SECONDS_PER_HOUR);
    let mut poller = GuardianPollerCore::new(cfg, one_hour_ago, GuardianLogDir::Heartbeat).await?;
    let mut logs = Vec::new();
    logs.extend(poller.read_cur_dir().await?);
    poller.advance_cursor();
    logs.extend(poller.read_cur_dir().await?);

    let mut summary = summarize_logs_by_session(logs)?;
    summary.sort_by_key(|s| s.last_heartbeat);
    let target_session_info = summary
        .last()
        .ok_or_else(|| anyhow::anyhow!("no heartbeat logs found in the most recent 2 hours"))?;
    let target_session_id = &target_session_info.session_id;

    let now = now_unix_seconds();
    // currently set to 10 mins
    let threshold_secs = NO_HEARTBEAT_PERIOD.as_secs();
    let target_age_secs = now.saturating_sub(target_session_info.last_heartbeat);
    // TODO: Should we use a tighter bound for the new enclave's timestamp?
    if target_age_secs > threshold_secs {
        anyhow::bail!(
            "latest session {} is stale: last heartbeat {}s ago (threshold {}s)",
            target_session_id,
            target_age_secs,
            threshold_secs
        );
    }

    let active_other_sessions = summary
        .iter()
        .filter(|s| s.session_id != *target_session_id)
        .filter_map(|s| {
            let age_secs = now.saturating_sub(s.last_heartbeat);
            (age_secs < threshold_secs).then(|| format!("{} ({}s ago)", s.session_id, age_secs))
        })
        .collect::<Vec<_>>();
    if !active_other_sessions.is_empty() {
        anyhow::bail!(
            "other sessions are still active within {}s: {}",
            threshold_secs,
            active_other_sessions.join(", ")
        );
    }

    info!(
        "Selected session {} with a heartbeat {}s ago",
        target_session_id,
        now.saturating_sub(target_session_info.last_heartbeat)
    );

    Ok(target_session_id.clone())
}

/// Aggregates verified heartbeat logs into [first, last] bounds per session.
fn summarize_logs_by_session(
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
