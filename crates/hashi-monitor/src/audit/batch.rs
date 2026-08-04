// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::domain::now_unix_seconds;
use crate::domain::utc_timestamp;
use hashi_types::guardian::time_utils::UnixSeconds;

const NUM_ITERATIONS_BEFORE_FAIL: u8 = 5;

/// User and derived source ranges for one batch audit.
#[derive(Clone, Copy, Debug)]
pub struct BatchAuditWindow {
    /// Guardian time range supplied by the user.
    user_start: UnixSeconds,
    user_end: UnixSeconds,
    /// Derived source ranges used to poll Sui and Guardian.
    sui_start: UnixSeconds,
    sui_end: UnixSeconds,
    guardian_start: UnixSeconds,
    guardian_end: UnixSeconds,
}

impl BatchAuditWindow {
    pub fn new(cfg: &Config, start: UnixSeconds, end: UnixSeconds, cur_time: UnixSeconds) -> Self {
        // Guardian timeline is authoritative. We still fetch Sui in a relaxed range to validate E2 -> E1.
        let sui_start = start.saturating_sub(cfg.withdrawal_predecessor_lookback);
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
    fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
        timestamp_secs >= self.user_start && timestamp_secs <= self.user_end
    }
}

/// A batch auditor that tries to validate all events emitted during a given time period `[t1, t2]`.
///
/// It functions as follows:
///     - fetch guardian events from `[t1, t2]` (authoritative timeline)
///     - fetch withdrawal and deposit events from
///       `[t1 - withdrawal_predecessor_lookback, t2 + clock_skew]`
///     - fetch BTC data for in-scope withdrawals and deposits found in the Sui range
/// Finally, it logs progress watermarks that identify a safe start for the next audit.
///
/// Notes:
/// 1) If no findings are emitted, Guardian events in the verified withdrawal
///    range were cross-checked against their Sui and Bitcoin neighbors.
/// 2) We currently also report orphan E1 findings if they fall in the user window.
///    TODO: If desired, this can be relaxed later to strict guardian-anchored scope.
/// 3) Events near the end may remain unresolved because their successors are
///    not yet due or observed. The progress watermarks capture a safe restart;
///    infrastructure failures return an error instead of a partial audit.
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
            "invalid time range: start={} > end={}",
            utc_timestamp(start),
            utc_timestamp(end),
        );
        let cur_time = now_unix_seconds();
        anyhow::ensure!(
            end <= cur_time,
            "end is in the future: end={} > current_time={}",
            utc_timestamp(end),
            utc_timestamp(cur_time),
        );

        let audit_window = BatchAuditWindow::new(cfg, start, end, cur_time);
        let cursors = Cursors {
            sui: audit_window.sui_start,
            guardian: audit_window.guardian_start,
        };
        tracing::info!(
            "starting batch audit:\n  requested_start={}\n  requested_end={}\n  sui_start={}\n  sui_target_end={}\n  guardian_start={}\n  guardian_target_end={}",
            utc_timestamp(audit_window.user_start),
            utc_timestamp(audit_window.user_end),
            utc_timestamp(audit_window.sui_start),
            utc_timestamp(audit_window.sui_end),
            utc_timestamp(audit_window.guardian_start),
            utc_timestamp(audit_window.guardian_end),
        );
        Ok(Self {
            inner: AuditorCore::new(cfg, cursors).await?,
            audit_window,
            violation_found: false,
        })
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorEvent>) {
        let findings = self.inner.ingest_batch(events);
        log_findings("batch", "ingest", &findings);
        if !findings.is_empty() {
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
                && let PollOutcome::CursorAdvanced(events) =
                    self.inner.poll_sui(self.audit_window.sui_end).await?
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

            if should_poll_guardian && !guardian_cursor_moved {
                let ready_at = self.inner.get_guardian_next_partition_ready_at();
                if now_unix_seconds() < ready_at {
                    anyhow::bail!(
                        "Guardian data is not finalized for the requested batch range:\n  \
                         guardian_complete_through={}\n  requested_end={}\n  \
                         next_partition_ready_at={}\nRerun at or after {}, or choose an end \
                         time at or before {}.",
                        utc_timestamp(self.inner.get_guardian_cursor()),
                        utc_timestamp(self.audit_window.guardian_end),
                        utc_timestamp(ready_at),
                        utc_timestamp(ready_at),
                        utc_timestamp(self.inner.get_guardian_cursor()),
                    );
                }
            }

            if !sui_cursor_moved && !guardian_cursor_moved {
                stalled_iterations = stalled_iterations.saturating_add(1);
                if stalled_iterations >= NUM_ITERATIONS_BEFORE_FAIL {
                    anyhow::bail!(
                        "batch polling stalled:\n  sui_cursor={}\n  sui_target={}\n  \
                         guardian_cursor={}\n  guardian_target={}",
                        utc_timestamp(self.inner.get_sui_cursor()),
                        utc_timestamp(self.audit_window.sui_end),
                        utc_timestamp(self.inner.get_guardian_cursor()),
                        utc_timestamp(self.audit_window.guardian_end),
                    );
                }
            } else {
                stalled_iterations = 0;
            }
        }
        tracing::info!("all Sui and Guardian cursor endpoints reached");
        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.violation_found = false;
        self.fetch_all_sui_guardian_events().await?;

        tracing::info!(
            "finished batch polling:\n  start={}\n  end={}\n  sui_start={}\n  sui_target_end={}\n  sui_cursor={}\n  guardian_start={}\n  guardian_target_end={}\n  guardian_cursor={}",
            utc_timestamp(self.audit_window.user_start),
            utc_timestamp(self.audit_window.user_end),
            utc_timestamp(self.audit_window.sui_start),
            utc_timestamp(self.audit_window.sui_end),
            utc_timestamp(self.inner.get_sui_cursor()),
            utc_timestamp(self.audit_window.guardian_start),
            utc_timestamp(self.audit_window.guardian_end),
            utc_timestamp(self.inner.get_guardian_cursor()),
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

        let progress = self.inner.progress_watermarks(&self.audit_window);

        tracing::info!(
            "batch progress watermarks:\n  verified_up_to_withdrawals={}\n  verified_up_to_deposits={}\n  next_start={}",
            utc_timestamp(progress.verified_up_to_withdrawals),
            utc_timestamp(progress.verified_up_to_deposits),
            utc_timestamp(progress.restart_start),
        );

        if !self.violation_found {
            tracing::info!(
                "audit passed. run next audit at {}",
                utc_timestamp(progress.restart_start)
            );
        } else {
            tracing::warn!("audit produced findings: see logs");
        }

        Ok(())
    }
}
