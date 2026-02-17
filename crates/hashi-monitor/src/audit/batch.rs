use crate::audit::AuditWindow;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use crate::errors::MonitorError;
use crate::rpc::poll_guardian;
use crate::rpc::poll_sui;
use crate::state_machine::BtcFetchOutcome;
use crate::state_machine::WithdrawalStateMachine;
use hashi_guardian_shared::WithdrawalID;
use std::collections::HashMap;
use std::collections::hash_map::Entry;

const NUM_ITERATIONS_BEFORE_FAIL: u8 = 5;

/// the exact amount of time to look back or ahead to identify all the potentially interesting events
#[derive(Clone, Copy, Debug)]
pub struct BatchAuditWindow {
    /// time range input by user
    user_start: UnixSeconds,
    user_end: UnixSeconds,
    /// relaxed time ranges used to pull logs from sui & guardian
    sui_start: UnixSeconds,
    sui_end: UnixSeconds,
    guardian_start: UnixSeconds,
    guardian_end: UnixSeconds,
}

impl BatchAuditWindow {
    pub fn new(cfg: &Config, start: UnixSeconds, end: UnixSeconds, cur_time: UnixSeconds) -> Self {
        let e1_e2_delay_secs = cfg
            .next_event_delay(WithdrawalEventType::E1HashiApproved)
            .expect("should be Some");
        let sui_start = start.saturating_sub(e1_e2_delay_secs); // guardian_e2@{start} might match sui_e1@{start-e1_e2_delay_secs}
        let sui_end = end.saturating_add(cfg.clock_skew).min(cur_time); // guardian_e2@{end} might match sui_e1@{end+skew}

        let guardian_start = start.saturating_sub(cfg.clock_skew); // sui_e1@{start} might match guardian_e2@{start-skew}
        let guardian_end = end.saturating_add(e1_e2_delay_secs).min(cur_time); // sui_e1@{end} might match guardian_e2@{end+e1_e2_delay_secs}

        Self {
            user_start: start,
            user_end: end,
            sui_start,
            sui_end,
            guardian_start,
            guardian_end,
        }
    }
}

impl AuditWindow for BatchAuditWindow {
    fn in_window(&self, e: &WithdrawalEvent) -> bool {
        e.timestamp >= self.user_start && e.timestamp <= self.user_end
    }
}

/// A batch auditor that tries to validate all events emitted during a given time period `[t1, t2]`.
///
/// It functions as follows:
///     - fetch all sui events from `[t1 - e1_e2_delay_secs, t2 + clock_skew]`
///     - fetch all guardian events from `[t1 - clock_skew, t2 + e1_e2_delay_secs]`
///     - fetch btx tx & perform checks for all withdrawals with at least one event in the range `[t1, t2]`
/// Finally, it outputs a timestamp `verified_up_to` to be used as `t1` in the next audit.
///
/// Notes:
/// 1) A successful batch audit guarantees that any sui or guardian event emitted in the range `[t1, verified_up_to)`
///    as measured by the emitter's clock is cross-verified. In other words, for all e_sui with sui timestamp in the verified range
///    and for all e_guardian with guardian timestamp in the verified range, all the checks succeed.
/// 2) Note that events emitted towards the end of the time range may not be fully verified, e.g., if t2 is current or if there is
///    some issue with RPC. This info is captured by the `verified_up_to` timestamp.
/// 3) The current approach is fetch-then-check. An alternate streaming auditor can be implemented in the future if needed.
pub struct BatchAuditor {
    // immutable
    pub cfg: Config,
    pub audit_window: BatchAuditWindow,
    // mutable
    pub cursors: Cursors,
    pub pending: HashMap<WithdrawalID, WithdrawalStateMachine>,
    pub findings: Vec<MonitorError>,
}

impl BatchAuditor {
    pub fn new(cfg: Config, start: UnixSeconds, end: UnixSeconds) -> anyhow::Result<Self> {
        anyhow::ensure!(
            start <= end,
            "invalid time range: start={start} > end={end}"
        );
        let cur_time = now_unix_seconds();
        anyhow::ensure!(
            end <= cur_time,
            "end is in the future: end={end} > cur_time={cur_time}"
        );

        let audit_window = BatchAuditWindow::new(&cfg, start, end, cur_time);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };
        Ok(Self {
            cfg,
            audit_window,
            cursors,
            pending: HashMap::new(),
            findings: Vec::new(),
        })
    }

    pub fn ingest(&mut self, event: WithdrawalEvent) {
        let wid = event.wid;
        match self.pending.entry(wid) {
            Entry::Occupied(mut entry) => {
                if let Err(e) = entry.get_mut().add_event(event, &self.cfg) {
                    self.findings.push(e);
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(WithdrawalStateMachine::new(event, &self.cfg));
            }
        }
    }

    pub fn ingest_batch(&mut self, events: Vec<WithdrawalEvent>) {
        for event in events {
            self.ingest(event)
        }
    }

    async fn fetch_all_sui_guardian_events(&mut self) -> anyhow::Result<()> {
        let mut stalled_iterations = 0_u8;

        while self.cursors.sui < self.audit_window.sui_end
            || self.cursors.guardian < self.audit_window.guardian_end
        {
            let prev_sui = self.cursors.sui;
            let prev_guardian = self.cursors.guardian;

            let should_poll_sui = self.cursors.sui < self.audit_window.sui_end;
            let should_poll_guardian = self.cursors.guardian < self.audit_window.guardian_end;

            let (sui_result, guardian_result) = tokio::join!(
                async {
                    if should_poll_sui {
                        Some(poll_sui(&self.cfg, self.cursors.sui).await)
                    } else {
                        None
                    }
                },
                async {
                    if should_poll_guardian {
                        Some(poll_guardian(&self.cfg, self.cursors.guardian).await)
                    } else {
                        None
                    }
                }
            );

            if let Some(result) = sui_result {
                let (events, new_cursor) = result?;
                self.cursors.sui = new_cursor;
                self.ingest_batch(events);
            }

            if let Some(result) = guardian_result {
                let (events, new_cursor) = result?;
                self.cursors.guardian = new_cursor;
                self.ingest_batch(events);
            }

            if prev_sui == self.cursors.sui && prev_guardian == self.cursors.guardian {
                stalled_iterations = stalled_iterations.saturating_add(1);
                if stalled_iterations >= NUM_ITERATIONS_BEFORE_FAIL {
                    tracing::warn!(
                        "batch polling cursors did not advance fully (sui={}, guardian={})",
                        self.cursors.sui,
                        self.cursors.guardian
                    );
                    return Ok(());
                }
            } else {
                stalled_iterations = 0;
            }
        }
        tracing::info!("all desired cursor endpoints reached");
        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.findings.clear();
        self.fetch_all_sui_guardian_events().await?;

        tracing::info!(
            start = self.audit_window.user_start,
            end = self.audit_window.user_end,
            sui_start = self.audit_window.sui_start,
            sui_target_end = self.audit_window.sui_end,
            sui_cursor = self.cursors.sui,
            guardian_start = self.audit_window.guardian_start,
            guardian_target_end = self.audit_window.guardian_end,
            guardian_cursor = self.cursors.guardian,
            "finished batch polling"
        );

        // Fetch all BTC info
        for sm in self.pending.values_mut() {
            if let BtcFetchOutcome::Confirmed(Some(e)) = sm.try_fetch_btc_tx(&self.cfg)? {
                self.findings.push(e);
            }
        }

        // Gather all violations & also identify the earliest incomplete state machine (to signal when to start next)
        let mut verified_up_to = self.cursors.min();
        for sm in self.pending.values() {
            if !sm.is_in_audit_window(&self.audit_window) {
                continue;
            }
            self.findings.extend(sm.violations(&self.cursors));
            if !sm.is_valid() {
                // we are being a little conservative here; e.g., if e_hashi, e_guardian exist and e_btc doesn't, then
                // earliest event time might correspond to e_hashi. but even using e_guardian suffices.
                verified_up_to = verified_up_to.min(
                    sm.earliest_event_time()
                        .expect("incomplete state machines must have one timestamp"),
                )
            }
        }

        if self.findings.is_empty() {
            tracing::info!("audit passed. run next audit at {verified_up_to}");
        } else {
            tracing::warn!(count = self.findings.len(), "audit produced findings");
        }

        Ok(())
    }
}
