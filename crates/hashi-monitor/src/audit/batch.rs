use crate::audit::BatchAuditWindow;
use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorError;
use crate::domain::UnixSeconds;
use crate::domain::WithdrawalEvent;
use crate::domain::now_unix_seconds;
use crate::rpc::poll_guardian;
use crate::rpc::poll_sui;
use crate::state_machine::BtcFetchOutcome;
use crate::state_machine::WithdrawalStateMachine;
use hashi_guardian_shared::WithdrawalID;
use std::collections::HashMap;

const NUM_ITERATIONS_BEFORE_FAIL: u8 = 5;

/// A batch auditor that validates all events emitted during a given time period.
///
/// It currently functions as follows:
///     - first fetch all the necessary sui, guardian events
///     - then perform all the checks
/// An alternate streaming auditor can be implemented in the future if needed.
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
        let wid = event.wid();
        let sm = self.pending.entry(wid).or_default();
        if let Err(e) = sm.add_event(event, &self.cfg) {
            self.findings.push(e);
        }
    }

    pub fn ingest_batch(&mut self, events: Vec<WithdrawalEvent>) {
        for event in events {
            self.ingest(event)
        }
    }

    async fn fetch_all_sui_guardian_events(&mut self) -> anyhow::Result<()> {
        let mut stalled_iterations = 0_u8;

        while self.cursors.sui < self.audit_window.sui_end()
            || self.cursors.guardian < self.audit_window.guardian_end()
        {
            let prev_sui = self.cursors.sui;
            let prev_guardian = self.cursors.guardian;

            let should_poll_sui = self.cursors.sui < self.audit_window.sui_end();
            let should_poll_guardian = self.cursors.guardian < self.audit_window.guardian_end();

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
            sui_start = self.audit_window.sui_start(),
            sui_target_end = self.audit_window.sui_end(),
            sui_cursor = self.cursors.sui,
            guardian_start = self.audit_window.guardian_start(),
            guardian_target_end = self.audit_window.guardian_end(),
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
        // note that we only need to find earliest_incomplete_e2_timestamp for correctness; so we are being conservative.
        let mut verified_up_to = self.cursors.min();
        for sm in self.pending.values() {
            if !sm.is_in_audit_window(&self.audit_window) {
                continue;
            }
            self.findings.extend(sm.violations(&self.cursors));
            if !sm.is_valid() {
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
