use std::collections::HashMap;

use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::E1SuiInit;
use crate::domain::E2GuardianApproved;
use crate::domain::E3SuiApproved;
use crate::domain::Finding;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::timeline::Timeline;

/// Parameters for audit window and liveness horizons.
/// Horizon stands for the timestamp until which we have logs from that data source.
#[derive(Clone, Copy, Debug)]
pub struct AuditWindow {
    /// Start of the audit window (events with timestamp >= t1 trigger checks).
    pub t1: UnixSeconds,
    /// End of the audit window (events with timestamp <= t2 trigger checks).
    pub t2: UnixSeconds,
    /// Horizon for Guardian logs (E2). Liveness for E1->E2 is decidable up to this point.
    pub guardian_horizon: UnixSeconds,
    /// Horizon for Sui logs (E3). Liveness for E2->E3 is decidable up to this point.
    pub sui_horizon: UnixSeconds,
    /// Horizon for BTC RPC. Liveness for E3->BTC is decidable up to this point.
    pub btc_horizon: UnixSeconds,
}

impl AuditWindow {
    pub fn contains(&self, ts: UnixSeconds) -> bool {
        self.t1 <= ts && ts <= self.t2
    }
}

pub fn run_audit(cfg: &Config, t1: UnixSeconds, t2: UnixSeconds) -> anyhow::Result<()> {
    anyhow::ensure!(t1 <= t2, "invalid time range: t1={t1} > t2={t2}");

    // Step 1: download Guardian logs (E2).
    // - Look back by (e2_e3_delay + slack) so E2 predecessors of E3 near t1 are included.
    // - Look ahead by (e1_e2_delay + slack) so E2 successors of E1 near t2 are included (liveness).
    let guardian_lookback = cfg.e2_e3_delay_secs.saturating_add(cfg.slack_secs);
    let guardian_lookahead = cfg.e1_e2_delay_secs.saturating_add(cfg.slack_secs);
    let guardian_start = t1.saturating_sub(guardian_lookback);
    let guardian_requested_end = t2.saturating_add(guardian_lookahead);

    // Step 2: compute Sui download window (E1/E3).
    // - Look back by (e1_e2_delay + slack) so E1 predecessors of E2 near t1 are included.
    // - Look ahead by (e2_e3_delay + slack) so E3 successors of E2 near t2 are included (liveness).
    let sui_lookback = cfg.e1_e2_delay_secs.saturating_add(cfg.slack_secs);
    let sui_lookahead = cfg.e2_e3_delay_secs.saturating_add(cfg.slack_secs);
    let sui_start = t1.saturating_sub(sui_lookback);
    let sui_requested_end = t2.saturating_add(sui_lookahead);

    // Step 3: download events. Downloaders return actual horizon (maybe < requested_end).
    let (e2_all, guardian_horizon) =
        download_e2_guardian(cfg, guardian_start, guardian_requested_end)?;
    let (e1_all, e3_all, sui_horizon) = download_e1_e3_sui(cfg, sui_start, sui_requested_end)?;

    // BTC horizon is just `now` since we query the RPC in real-time.
    let btc_horizon = now_unix_seconds();

    // Liveness is decidable for E1 timestamps up to `guardian_horizon - e1_e2_delay`, for E2
    // timestamps up to `sui_horizon - e2_e3_delay`, and for E3 up to `btc_horizon - e3_e4_delay`.
    let verified_up_to_e1_e2 = guardian_horizon.saturating_sub(cfg.e1_e2_delay_secs);
    let verified_up_to_e2_e3 = sui_horizon.saturating_sub(cfg.e2_e3_delay_secs);
    let verified_up_to_e3_e4 = btc_horizon.saturating_sub(cfg.e3_e4_delay_secs);
    let verified_up_to = t2.min(
        verified_up_to_e1_e2
            .min(verified_up_to_e2_e3)
            .min(verified_up_to_e3_e4),
    );

    tracing::info!(
        t1,
        t2,
        verified_up_to,
        guardian_start,
        guardian_requested_end,
        guardian_horizon,
        sui_start,
        sui_requested_end,
        sui_horizon,
        btc_horizon,
        s3_bucket = %cfg.guardian.s3_bucket,
        rpc_url = %cfg.sui.rpc_url,
        btc_url = %cfg.btc.rpc_url,
        "starting audit"
    );

    // Step 4: evaluate checks.
    // Mental model: events in [t1, t2] start obligations.
    // - Safety (predecessor/link) checks are immediate.
    // - Liveness checks are only evaluated when the corresponding successor horizon includes the deadline.
    tracing::info!(
        e1_total = e1_all.len(),
        e2_total = e2_all.len(),
        e3_total = e3_all.len(),
        "downloaded events"
    );

    let mut events_by_wid: HashMap<WithdrawalID, Vec<WithdrawalEvent>> = HashMap::new();

    for e1 in e1_all {
        events_by_wid
            .entry(e1.wid)
            .or_default()
            .push(WithdrawalEvent::SuiInit(e1));
    }

    for e2 in e2_all {
        events_by_wid
            .entry(e2.wid)
            .or_default()
            .push(WithdrawalEvent::GuardianApproved(e2));
    }

    for e3 in e3_all {
        events_by_wid
            .entry(e3.wid)
            .or_default()
            .push(WithdrawalEvent::SuiApproved(e3));
    }

    let window = AuditWindow {
        t1,
        t2,
        guardian_horizon,
        sui_horizon,
        btc_horizon,
    };

    let mut findings = Vec::<Finding>::new();

    for (_wid, events) in events_by_wid {
        findings.extend(Timeline::new_audit(events, &window, cfg));
    }

    if findings.is_empty() {
        tracing::info!(verified_up_to, "audit passed");
        return Ok(());
    }

    // For CLI usage, fail fast but keep the error readable.
    let msg = findings
        .into_iter()
        .take(50)
        .map(|f| format!("{f}"))
        .collect::<Vec<_>>()
        .join("\n");

    Err(anyhow::anyhow!("findings:\n{msg}"))
}

fn now_unix_seconds() -> UnixSeconds {
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    dur.as_secs()
}

/// Returns (events, horizon) where horizon is the latest timestamp with complete data.
fn download_e2_guardian(
    _cfg: &Config,
    _start: UnixSeconds,
    end: UnixSeconds,
) -> anyhow::Result<(Vec<E2GuardianApproved>, UnixSeconds)> {
    // TODO:
    // - List S3 objects by time-bucket prefix (planned key scheme: YYYY/MM/DD/HH/...)
    // - Download and deserialize Guardian log envelopes into E2GuardianApproved.
    // - Return actual horizon based on latest complete bucket.
    let horizon = end; // Stub: assume we got everything requested
    Ok((vec![], horizon))
}

/// Returns (e1_events, e3_events, horizon) where horizon is the latest timestamp with complete data.
fn download_e1_e3_sui(
    _cfg: &Config,
    _start: UnixSeconds,
    end: UnixSeconds,
) -> anyhow::Result<(Vec<E1SuiInit>, Vec<E3SuiApproved>, UnixSeconds)> {
    // TODO:
    // - Query Sui events across checkpoints that intersect [start, end]
    // - Convert to E1SuiInit / E3SuiApproved with checkpoint timestamps.
    // - Return actual horizon based on latest checkpoint timestamp.
    let horizon = end; // Stub: assume we got everything requested
    Ok((vec![], vec![], horizon))
}
