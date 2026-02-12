use std::collections::HashMap;

use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorError;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::now_unix_seconds;
use crate::rpc::download_guardian;
use crate::rpc::download_sui;
use crate::state_machine::WithdrawalStateMachine;

/// A batch auditor that is expected to be called sporadically.
/// It checks validity of all Sui & Guardian logs emitted in the range [t1, t2].
/// Note: The auditor looks back and beyond the input range a little bit, e.g., to find a predecessor for an event that happens around t1.
pub struct BatchAuditor {
    cfg: Config,
    t1: UnixSeconds,
    t2: UnixSeconds,
}

impl BatchAuditor {
    pub fn new(cfg: Config, t1: UnixSeconds, t2: UnixSeconds) -> anyhow::Result<Self> {
        anyhow::ensure!(t1 <= t2, "invalid time range: t1={t1} > t2={t2}");
        Ok(Self { cfg, t1, t2 })
    }

    pub fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp() >= self.t1 && e.timestamp() <= self.t2
    }

    pub fn run(&self) -> anyhow::Result<()> {
        let cfg = &self.cfg;
        let t1 = self.t1;
        let t2 = self.t2;

        // Step 1: compute Guardian download window (E2).
        // E2 is successor of E1. Due to clock skew, E2 can be recorded up to clock_skew before E1.
        // E2 should occur within e1_e2_delay after E1.
        // - Lookback: E2 can be clock_skew before E1@t1
        // - Lookahead: E2 can be e1_e2_delay after E1@t2
        let guardian_lookback = cfg.clock_skew;
        let guardian_lookahead = cfg.e1_e2_delay_secs;
        let guardian_start = t1.saturating_sub(guardian_lookback);
        let guardian_requested_end = t2.saturating_add(guardian_lookahead);

        // Step 2: compute Sui download window (E1).
        // E1 is predecessor of E2. E1 can be up to e1_e2_delay before E2.
        // Due to clock skew, E1 can be recorded up to clock_skew after E2.
        // - Lookback: E1 can be e1_e2_delay before E2@t1
        // - Lookahead: E1 can be clock_skew after E2@t2
        let sui_lookback = cfg.e1_e2_delay_secs;
        let sui_lookahead = cfg.clock_skew;
        let sui_start = t1.saturating_sub(sui_lookback);
        let sui_requested_end = t2.saturating_add(sui_lookahead);

        // Step 3: download events. Downloaders return actual cursor (may be < requested_end).
        let (guardian_events, guardian_cursor) =
            download_guardian(cfg, guardian_start, guardian_requested_end)?;
        let (sui_events, sui_cursor) = download_sui(cfg, sui_start, sui_requested_end)?;

        // BTC cursor is `now` since we query the RPC in real-time.
        let btc_cursor = now_unix_seconds();

        let cursors = Cursors {
            sui: sui_cursor,
            guardian: guardian_cursor,
            btc: btc_cursor,
        };

        // Liveness is decidable for E1 up to `guardian_cursor - e1_e2_delay`,
        // for E2 up to `btc_cursor - e2_e3_delay`.
        let verified_up_to_e1 = guardian_cursor.saturating_sub(cfg.e1_e2_delay_secs);
        let verified_up_to_e2 = btc_cursor.saturating_sub(cfg.e2_e3_delay_secs);
        let verified_up_to = t2.min(verified_up_to_e1.min(verified_up_to_e2));

        tracing::info!(
            t1,
            t2,
            verified_up_to,
            guardian_start,
            guardian_requested_end,
            guardian_cursor,
            sui_start,
            sui_requested_end,
            sui_cursor,
            btc_cursor,
            s3_bucket = %cfg.guardian.s3_bucket,
            sui_rpc = %cfg.sui.rpc_url,
            btc_rpc = %cfg.btc.rpc_url,
            "starting batch audit"
        );

        // Step 4: group events by wid.
        let mut events_by_wid: HashMap<WithdrawalID, Vec<WithdrawalEvent>> = HashMap::new();

        for ev in guardian_events {
            events_by_wid.entry(ev.wid()).or_default().push(ev);
        }
        for ev in sui_events {
            events_by_wid.entry(ev.wid()).or_default().push(ev);
        }

        tracing::info!(withdrawal_count = events_by_wid.len(), "grouped events");

        // Step 5: run state machine for each withdrawal that has at least one event in [t1, t2].
        // Events outside [t1, t2] are only used to check predecessors/successors.
        let mut findings = Vec::<MonitorError>::new();
        let mut state_machines: Vec<WithdrawalStateMachine> = Vec::new();

        for (_wid, events) in events_by_wid {
            // Only audit if at least one event falls within [t1, t2].
            let dominated = events.iter().any(|e| self.in_window(e));
            if !dominated {
                continue;
            }

            match WithdrawalStateMachine::new_with_events(events, cfg) {
                Ok(sm) => state_machines.push(sm),
                Err(e) => findings.push(e),
            }
        }

        // Step 6: for withdrawals expecting BTC confirmation, query BTC RPC.
        for sm in &mut state_machines {
            if let Some(Err(e)) = sm.try_fetch_btc_tx(cfg) {
                findings.push(e);
            }
        }

        // Step 7: collect violations from all state machines.
        for sm in &state_machines {
            findings.extend(sm.violations(&cursors));
        }

        if findings.is_empty() {
            tracing::info!(verified_up_to, "audit passed");
            return Ok(());
        }

        let msg = findings
            .into_iter()
            .map(|f| format!("{f}"))
            .collect::<Vec<_>>()
            .join("\n");

        Err(anyhow::anyhow!("findings:\n{msg}"))
    }
}
