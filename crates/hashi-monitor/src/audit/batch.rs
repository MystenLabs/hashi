// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The batch auditor: one audit of a closed guardian time range.
//!
//! Why it exists: an operator audits a past range once, for example after an
//! incident or before a build is retired, and wants a pass or fail answer.
//!
//! How it works:
//! 1. The user's `[start, end]` is on the guardian timeline. The Sui range
//!    is widened by `Timing::sui_lookback` before it and
//!    `Timing::sui_lookahead` after it, so every E1 that can match an E2 in
//!    the range is read.
//! 2. Both pollers run until they reach the end of their range. The audit
//!    fails if the guardian's last hour is not complete yet, or if the Sui
//!    node has pruned the start of the Sui range.
//! 3. The core then looks up Bitcoin, fetches the missing Sui approvals,
//!    and reports the violations.
//! 4. The progress watermarks say where the next audit can start.
//!
//! Assumptions:
//! - Events near the end may stay unresolved, because their successors are
//!   not due yet. They are not failures.
//! - An infrastructure failure is an error, not a partial audit.

use crate::audit::AuditWindow;
use crate::audit::AuditorCore;
use crate::audit::log_findings;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorEvent;
use crate::domain::PollOutcome;
use crate::findings::MonitorFinding;
use crate::time::utc_timestamp;
use crate::timing::Timing;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::time::now_timestamp_secs;

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
    pub fn new(
        timing: &Timing,
        start: UnixSeconds,
        end: UnixSeconds,
        cur_time: UnixSeconds,
    ) -> Self {
        // The guardian timeline is authoritative. Sui is read in a wider
        // range, so every E1 that can match an E2 in the range is found.
        let sui_start = start.saturating_sub(timing.sui_lookback());
        let sui_end = end.saturating_add(timing.sui_lookahead()).min(cur_time);

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

    /// A batch audit claims its whole Sui range, so it fails if the Sui node pruned the
    /// start and the scan had to begin later.
    fn ensure_sui_history(&self, sui_scan_start: UnixSeconds) -> anyhow::Result<()> {
        anyhow::ensure!(
            sui_scan_start <= self.sui_start,
            "the Sui node no longer serves history before {}, but this audit needs it from {}; \
             use a Sui RPC that keeps it, or a later start",
            utc_timestamp(sui_scan_start),
            utc_timestamp(self.sui_start),
        );
        Ok(())
    }
}

impl AuditWindow for BatchAuditWindow {
    fn in_window(&self, timestamp_secs: UnixSeconds) -> bool {
        timestamp_secs >= self.user_start && timestamp_secs <= self.user_end
    }
}

/// One audit of the events in a guardian time range. See the module doc for
/// the steps. `violation_found` is set once any finding is reported.
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
        let cur_time = now_timestamp_secs();
        anyhow::ensure!(
            end <= cur_time,
            "end is in the future: end={} > current_time={}",
            utc_timestamp(end),
            utc_timestamp(cur_time),
        );

        let audit_window = BatchAuditWindow::new(&cfg.timing, start, end, cur_time);
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

    fn report_findings(&mut self, phase: &'static str, findings: &[MonitorFinding]) {
        log_findings("batch", phase, findings);
        if !findings.is_empty() {
            self.violation_found = true;
        }
    }

    pub fn ingest_batch(&mut self, events: Vec<MonitorEvent>) {
        let findings = self.inner.ingest_batch(events);
        self.report_findings("ingest", &findings);
    }

    async fn fetch_all_sui_guardian_events(&mut self) -> anyhow::Result<()> {
        let mut stalled_iterations = 0_u8;

        loop {
            let sui_cursor = self.inner.sui_cursor();
            let guardian_cursor = self.inner.guardian_cursor();

            let should_poll_sui = sui_cursor < self.audit_window.sui_end;
            let should_poll_guardian = guardian_cursor < self.audit_window.guardian_end;

            if !should_poll_sui && !should_poll_guardian {
                break;
            }

            let mut sui_cursor_moved = false;
            if should_poll_sui
                && let PollOutcome::CursorAdvanced { events, findings } =
                    self.inner.poll_sui(self.audit_window.sui_end).await?
            {
                self.report_findings("sui", &findings);
                self.ingest_batch(events);
                sui_cursor_moved = true;
            }

            let mut guardian_cursor_moved = false;
            if should_poll_guardian
                && let PollOutcome::CursorAdvanced { events, findings } =
                    self.inner.poll_guardian().await?
            {
                self.report_findings("guardian", &findings);
                self.ingest_batch(events);
                guardian_cursor_moved = true;
            }

            if should_poll_guardian && !guardian_cursor_moved {
                let ready_at = self.inner.guardian_next_partition_ready_at();
                if now_timestamp_secs() < ready_at {
                    anyhow::bail!(
                        "Guardian data is not finalized for the requested batch range:\n  \
                         guardian_complete_through={}\n  requested_end={}\n  \
                         next_partition_ready_at={}\nRerun at or after {}, or choose an end \
                         time at or before {}.",
                        utc_timestamp(self.inner.guardian_cursor()),
                        utc_timestamp(self.audit_window.guardian_end),
                        utc_timestamp(ready_at),
                        utc_timestamp(ready_at),
                        utc_timestamp(self.inner.guardian_cursor()),
                    );
                }
            }

            if !sui_cursor_moved && !guardian_cursor_moved {
                stalled_iterations = stalled_iterations.saturating_add(1);
                if stalled_iterations >= NUM_ITERATIONS_BEFORE_FAIL {
                    anyhow::bail!(
                        "batch polling stalled:\n  sui_cursor={}\n  sui_target={}\n  \
                         guardian_cursor={}\n  guardian_target={}",
                        utc_timestamp(self.inner.sui_cursor()),
                        utc_timestamp(self.audit_window.sui_end),
                        utc_timestamp(self.inner.guardian_cursor()),
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
        self.audit_window
            .ensure_sui_history(self.inner.sui_scan_start())?;

        tracing::info!(
            "finished batch polling:\n  start={}\n  end={}\n  sui_start={}\n  sui_target_end={}\n  sui_cursor={}\n  guardian_start={}\n  guardian_target_end={}\n  guardian_cursor={}",
            utc_timestamp(self.audit_window.user_start),
            utc_timestamp(self.audit_window.user_end),
            utc_timestamp(self.audit_window.sui_start),
            utc_timestamp(self.audit_window.sui_end),
            utc_timestamp(self.inner.sui_cursor()),
            utc_timestamp(self.audit_window.guardian_start),
            utc_timestamp(self.audit_window.guardian_end),
            utc_timestamp(self.inner.guardian_cursor()),
        );

        let btc_findings = self.inner.fetch_btc_info(&self.audit_window)?;
        self.report_findings("btc", &btc_findings);

        let lookup_findings = self
            .inner
            .fetch_missing_hashi_approvals(&self.audit_window)
            .await;
        self.report_findings("lookup", &lookup_findings);

        let violations = self.inner.detect_violations(&self.audit_window);
        self.report_findings("violations", &violations);

        let progress = self.inner.progress_watermarks(&self.audit_window);

        tracing::info!(
            "batch progress watermarks:\n  verified_up_to_withdrawals={}\n  withdrawal_blockers={}\n  verified_up_to_deposits={}\n  next_start={}",
            utc_timestamp(progress.verified_up_to_withdrawals),
            progress.withdrawal_blockers(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_fails_once_the_sui_node_has_pruned_the_start_of_its_range() {
        let window = BatchAuditWindow {
            user_start: 200,
            user_end: 300,
            sui_start: 100,
            sui_end: 310,
            guardian_start: 200,
            guardian_end: 300,
        };

        assert!(window.ensure_sui_history(100).is_ok());
        assert!(window.ensure_sui_history(101).is_err());
    }
}
