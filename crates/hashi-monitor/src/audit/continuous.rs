use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use hashi_guardian_shared::WithdrawalID;

use crate::config::Config;
use crate::domain::Cursors;
use crate::domain::MonitorError;
use crate::domain::now_unix_seconds;
use crate::domain::WithdrawalEvent;
use crate::rpc::poll_guardian;
use crate::rpc::poll_sui;
use crate::state_machine::WithdrawalStateMachine;

/// A continuous auditor that runs indefinitely, processing events as they arrive.
// TODO: Accept a start time `t1` as input. Before entering the poll loop:
// 1. Compute lookback windows (like BatchAuditor) to find predecessor events for events at t1.
// 2. Backfill events from [t1 - lookback, t1] and ingest them.
// 3. Set initial cursors to t1.
// 4. Then start polling for new events from t1 onward.
pub struct ContinuousAuditor {
    cfg: Config,
    cursors: Cursors,

    /// Withdrawals with incomplete state (still have pending expectations).
    pending: HashMap<WithdrawalID, WithdrawalStateMachine>,
}

impl ContinuousAuditor {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            cursors: Cursors {
                sui: 0,
                guardian: 0,
                btc: 0,
            },
            pending: HashMap::new(),
        }
    }

    /// Ingest a new event from Sui or Guardian pollers.
    pub fn ingest(&mut self, event: WithdrawalEvent) -> Result<(), MonitorError> {
        let wid = event.wid();
        let sm = self.pending.entry(wid).or_default();
        sm.add_event(event, &self.cfg)
    }

    /// Run the auditor loop indefinitely.
    pub fn run(&mut self) -> ! {
        loop {
            // Poll Sui for new events.
            match poll_sui(&self.cfg, self.cursors.sui) {
                Ok((events, new_cursor)) => {
                    for ev in events {
                        if let Err(e) = self.ingest(ev) {
                            tracing::warn!(?e, "sui ingest error");
                        }
                    }
                    self.cursors.sui = new_cursor;
                }
                Err(e) => {
                    tracing::warn!(err = %e, "sui poll failed");
                }
            }

            // Poll Guardian for new events.
            match poll_guardian(&self.cfg, self.cursors.guardian) {
                Ok((events, new_cursor)) => {
                    for ev in events {
                        if let Err(e) = self.ingest(ev) {
                            tracing::warn!(?e, "guardian ingest error");
                        }
                    }
                    self.cursors.guardian = new_cursor;
                }
                Err(e) => {
                    tracing::warn!(err = %e, "guardian poll failed");
                }
            }

            // Tick: update btc cursor, fetch confirmations, check violations.
            self.cursors.btc = now_unix_seconds();
            let findings = self.tick_inner();

            for f in &findings {
                tracing::error!(?f, "violation detected");
            }

            tracing::info!(
                pending_count = self.pending.len(),
                violation_count = findings.len(),
                sui_cursor = self.cursors.sui,
                guardian_cursor = self.cursors.guardian,
                "tick complete"
            );

            thread::sleep(Duration::from_secs(self.cfg.poll_interval_secs));
        }
    }

    /// Internal tick: fetch BTC confirmations and check violations.
    fn tick_inner(&mut self) -> Vec<MonitorError> {
        let mut findings = Vec::new();
        let mut completed = Vec::new();

        for (wid, sm) in &mut self.pending {
            // Query BTC for any expecting confirmation.
            if let Some(Err(e)) = sm.try_fetch_btc_tx(&self.cfg) {
                findings.push(e);
            }

            // Check violations.
            findings.extend(sm.violations(&self.cursors));

            // If no more expectations, withdrawal is complete.
            if sm.is_complete() {
                completed.push(*wid);
            }
        }

        // Prune completed withdrawals.
        for wid in completed {
            self.pending.remove(&wid);
        }

        findings
    }
}
