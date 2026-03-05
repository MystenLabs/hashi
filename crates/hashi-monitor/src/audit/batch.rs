use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::PollOutcome;
use crate::domain::WithdrawalEventType;
use crate::domain::now_unix_seconds;
use hashi_types::guardian::time_utils::UnixSeconds;

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
        // Guardian timeline is authoritative. We still fetch Sui in a relaxed range to validate E2 -> E1.
        let sui_start = start.saturating_sub(e1_e2_delay_secs); // guardian_e2@{start} might match sui_e1@{start-e1_e2_delay_secs}
        let sui_end = end.saturating_add(cfg.clock_skew).min(cur_time); // guardian_e2@{end} might match sui_e1@{end+clock_skew}

        // User [start, end] is interpreted as guardian timestamps.
        let guardian_start = start;
        let guardian_end = end;

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
    fn in_window(&self, e: &MonitorWithdrawalEvent) -> bool {
        e.timestamp_secs >= self.user_start && e.timestamp_secs <= self.user_end
    }
}

/// A batch auditor that tries to validate all events emitted during a given time period `[t1, t2]`.
///
/// It functions as follows:
///     - fetch guardian events from `[t1, t2]` (authoritative timeline)
///     - fetch sui events from `[t1 - e1_e2_delay_secs, t2 + clock_skew]` (for E2 predecessor checks)
///     - fetch btc tx & perform checks for withdrawals anchored by guardian events in `[t1, t2]`
/// Finally, it outputs a timestamp `verified_up_to` to be used as `t1` in the next audit.
///
/// Notes:
/// 1) A successful batch audit guarantees that guardian events emitted in `[t1, verified_up_to)` are cross-verified.
/// 2) We currently also report orphan E1 findings if they fall in the user window.
///    TODO: If desired, this can be relaxed later to strict guardian-anchored scope.
/// 3) Events emitted towards the end of the time range may not be fully verified, e.g., if t2 is current or if there is
///    some issue with RPC. This info is captured by the `verified_up_to` timestamp.
/// 4) The current approach is fetch-then-check. An alternate streaming auditor can be implemented in the future if needed.
pub struct BatchAuditor {
    pub inner: AuditorCore,
    pub audit_window: BatchAuditWindow,
    pub violation_found: bool,
}

impl BatchAuditor {
    pub async fn new(cfg: &Config, start: UnixSeconds, end: UnixSeconds) -> anyhow::Result<Self> {
        anyhow::ensure!(
            start <= end,
            "invalid time range: start={start} > end={end}"
        );
        let cur_time = now_unix_seconds();
        anyhow::ensure!(
            end <= cur_time,
            "end is in the future: end={end} > cur_time={cur_time}"
        );

        let audit_window = BatchAuditWindow::new(cfg, start, end, cur_time);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };
        Ok(Self {
            inner: AuditorCore::new(cfg, cursors).await?,
            audit_window,
            violation_found: false,
        })
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorWithdrawalEvent>) {
        let errors = self.inner.ingest_batch(events);
        log_findings("batch", "ingest", &errors);
        if !errors.is_empty() {
            self.violation_found = true;
        }
    }

    async fn fetch_all_sui_guardian_events(&mut self) -> anyhow::Result<()> {
        let mut stalled_iterations = 0_u8;

        loop {
            let sui_cursor = self.inner.get_sui_cursor();
            let guardian_cursor = self.inner.get_guardian_cursor();

            let should_poll_sui = sui_cursor < self.audit_window.sui_end;
            let should_poll_guardian = guardian_cursor < self.audit_window.guardian_end;

            if !should_poll_sui && !should_poll_guardian {
                break;
            }

            let mut sui_cursor_moved = false;
            if should_poll_sui
                && let PollOutcome::CursorAdvanced(events) = self.inner.poll_sui().await?
            {
                self.ingest_batch(events);
                sui_cursor_moved = true;
            }

            let mut guardian_cursor_moved = false;
            if should_poll_guardian
                && let PollOutcome::CursorAdvanced(events) = self.inner.poll_guardian().await?
            {
                self.ingest_batch(events);
                guardian_cursor_moved = true;
            }

            if !sui_cursor_moved && !guardian_cursor_moved {
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
        self.violation_found = false;
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
        if !btc_findings.is_empty() {
            self.violation_found = true;
        }

        // Gather all violations
        let violations = self.inner.detect_violations(&self.audit_window);
        log_findings("batch", "violations", &violations);
        if !violations.is_empty() {
            self.violation_found = true;
        }

        // Identify the earliest incomplete guardian-anchored state machine (to signal when to start next)
        let mut verified_up_to = self.inner.get_guardian_cursor();
        for sm in self.inner.pending.values() {
            if !sm.is_in_audit_window(&self.audit_window) || sm.is_valid() {
                continue;
            }

            // Guardian timeline is authoritative for deciding next batch boundary.
            if let Some(e2) = sm.get(WithdrawalEventType::E2GuardianApproved) {
                verified_up_to = verified_up_to.min(e2.timestamp_secs);
            } else {
                tracing::warn!(
                    wid = sm.wid(),
                    "in-window withdrawal missing guardian anchor; skipping in verified_up_to computation"
                );
            }
        }

        if !self.violation_found {
            tracing::info!("audit passed. run next audit at {verified_up_to}");
        } else {
            tracing::warn!("audit produced findings: see logs");
        }

        Ok(())
    }
}
