use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use crate::errors::MonitorError;
use crate::rpc::poll_guardian;
use crate::rpc::poll_sui;

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
    pub inner: AuditorCore,
    pub audit_window: BatchAuditWindow,
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
            inner: AuditorCore::new(cfg, cursors),
            audit_window,
            findings: Vec::new(),
        })
    }

    pub fn ingest_batch(&mut self, events: Vec<WithdrawalEvent>) {
        let errors = self.inner.ingest_batch(events);
        log_findings("batch", "ingest", &errors);
        self.findings.extend(errors);
    }

    async fn fetch_all_sui_guardian_events(&mut self) -> anyhow::Result<()> {
        let mut stalled_iterations = 0_u8;

        while self.inner.get_sui_cursor() < self.audit_window.sui_end
            || self.inner.get_guardian_cursor() < self.audit_window.guardian_end
        {
            let prev_sui = self.inner.get_sui_cursor();
            let prev_guardian = self.inner.get_guardian_cursor();

            let should_poll_sui = prev_sui < self.audit_window.sui_end;
            let should_poll_guardian = prev_guardian < self.audit_window.guardian_end;

            let (sui_result, guardian_result) = tokio::join!(
                async {
                    if should_poll_sui {
                        Some(poll_sui(&self.inner.cfg, prev_sui).await)
                    } else {
                        None
                    }
                },
                async {
                    if should_poll_guardian {
                        Some(poll_guardian(&self.inner.cfg, prev_guardian).await)
                    } else {
                        None
                    }
                }
            );

            if let Some(result) = sui_result {
                let (events, new_cursor) = result?;
                self.inner.set_sui_cursor(new_cursor);
                self.ingest_batch(events);
            }

            if let Some(result) = guardian_result {
                let (events, new_cursor) = result?;
                self.inner.set_guardian_cursor(new_cursor);
                self.ingest_batch(events);
            }

            if prev_sui == self.inner.get_sui_cursor()
                && prev_guardian == self.inner.get_guardian_cursor()
            {
                stalled_iterations = stalled_iterations.saturating_add(1);
                if stalled_iterations >= NUM_ITERATIONS_BEFORE_FAIL {
                    tracing::warn!(
                        "batch polling cursors did not advance fully (sui={}, guardian={})",
                        self.inner.get_sui_cursor(),
                        self.inner.get_guardian_cursor()
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
            sui_cursor = self.inner.get_sui_cursor(),
            guardian_start = self.audit_window.guardian_start,
            guardian_target_end = self.audit_window.guardian_end,
            guardian_cursor = self.inner.get_guardian_cursor(),
            "finished batch polling"
        );

        // Fetch all BTC info
        let btc_findings = self.inner.fetch_btc_info(&self.audit_window)?;
        log_findings("batch", "btc", &btc_findings);
        self.findings.extend(btc_findings);

        // Gather all violations
        let violations = self.inner.detect_violations(&self.audit_window);
        log_findings("batch", "violations", &violations);
        self.findings.extend(violations);

        // Identify the earliest incomplete state machine (to signal when to start next)
        let mut verified_up_to = self.inner.cursors.min();
        for sm in self.inner.pending.values() {
            if !sm.is_in_audit_window(&self.audit_window) || sm.is_valid() {
                continue;
            }
            // we are being a little conservative here; e.g., if e_hashi, e_guardian exist and e_btc doesn't, then
            // earliest event time might correspond to e_hashi. but even using e_guardian suffices.
            verified_up_to = verified_up_to.min(
                sm.earliest_event_time()
                    .expect("incomplete state machines must have one timestamp"),
            )
        }

        if self.findings.is_empty() {
            tracing::info!("audit passed. run next audit at {verified_up_to}");
        } else {
            tracing::warn!(count = self.findings.len(), "audit produced findings");
        }

        Ok(())
    }
}
