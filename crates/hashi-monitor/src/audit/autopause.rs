// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pause Hashi on a live finding that autopauses, at most once per configured
//! generation. The fired generation is saved before pausing, so a restart
//! cannot fire again. Findings replayed by the catch-up never fire, but a
//! fresh-approval finding is live even during the catch-up.

use super::Auditor;
use crate::findings::MonitorFinding;
use crate::metrics::AUTOPAUSE_FAILED;
use crate::metrics::AUTOPAUSE_SUCCEEDED;
use crate::pause::initiate_pause;
use hashi_types::guardian::time::now_timestamp_secs;

impl Auditor {
    fn autopause_generation(&self) -> Option<u64> {
        self.cfg.pause.as_ref()?.autopause_generation
    }

    /// Whether the configured generation is higher than the fired one.
    pub fn autopause_armed(&self) -> bool {
        self.autopause_generation().is_some_and(|generation| {
            self.autopause_fired_generation
                .is_none_or(|fired| generation > fired)
        })
    }

    /// Export whether autopause is armed, if it is enabled.
    pub(super) fn export_autopause_armed(&self) {
        if self.autopause_generation().is_some() {
            self.metrics.set_autopause_armed(self.autopause_armed());
        }
    }

    /// Fire on the first finding that autopauses, once caught up.
    pub(super) fn note_autopause(&mut self, findings: &[MonitorFinding]) {
        if self.caught_up {
            self.fire_autopause(findings);
        }
    }

    /// Fire on the first finding that autopauses, even during the catch-up.
    pub(super) fn fire_autopause(&mut self, findings: &[MonitorFinding]) {
        if !self.autopause_armed() {
            return;
        }
        let Some(finding) = findings.iter().find(|finding| finding.autopauses()) else {
            return;
        };
        tracing::error!(%finding, "autopause fired; pausing Hashi");
        self.autopause_fired_generation = self.autopause_generation();
        self.autopause_due = true;
        self.export_autopause_armed();
    }

    /// Save the latch, then pause on a separate task.
    pub(super) async fn run_due_autopause(&mut self) {
        if !std::mem::take(&mut self.autopause_due) {
            return;
        }
        // Pause even if the save fails: the violation is live.
        self.save_snapshot().await;
        let cfg = self.cfg.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let result = match initiate_pause(&cfg).await {
                Ok(()) => {
                    tracing::warn!("autopause paused Hashi");
                    AUTOPAUSE_SUCCEEDED
                }
                Err(error) => {
                    tracing::error!(?error, "autopause failed to pause Hashi");
                    AUTOPAUSE_FAILED
                }
            };
            metrics.record_autopause(result, now_timestamp_secs());
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::tests::auditor_with;
    use crate::config::Config;
    use crate::config::PauseConfig;
    use crate::metrics::MonitorMetrics;
    use crate::test_utils::approval_of;
    use crate::test_utils::deposit_request;
    use std::sync::Arc;
    use std::time::Duration;

    /// An auditor whose autopause has `generation`, or is disabled, and its metrics.
    fn autopause_auditor(generation: Option<u64>) -> (Auditor, Arc<MonitorMetrics>) {
        let mut cfg = Config::for_tests();
        cfg.pause = Some(PauseConfig {
            // Nothing listens here, so a pause fails.
            transaction_rpc_url: "http://127.0.0.1:1".to_owned(),
            object_id: None,
            operator_key_paths: Vec::new(),
            autopause_generation: generation,
        });
        let metrics = Arc::new(MonitorMetrics::new());
        let auditor = auditor_with(&cfg, metrics.clone());
        auditor.export_autopause_armed();
        (auditor, metrics)
    }

    fn unbacked() -> MonitorFinding {
        MonitorFinding::DepositUnbacked {
            sui: approval_of(&deposit_request(), 200),
        }
    }

    #[tokio::test]
    async fn autopause_fires_once_per_generation_across_restarts() {
        let (mut auditor, metrics) = autopause_auditor(Some(1));
        assert!(metrics.render().contains("hashi_monitor_autopause_armed 1"));
        auditor.report_findings("test", &[unbacked()]);
        assert!(auditor.autopause_due);
        assert!(metrics.render().contains("hashi_monitor_autopause_armed 0"));

        // Neither a repeat nor a restart from the snapshot fires again.
        auditor.autopause_due = false;
        auditor.report_findings("test", &[unbacked()]);
        assert!(!auditor.autopause_due);
        let (mut restarted, _) = autopause_auditor(Some(1));
        restarted.restore(auditor.state());
        restarted.report_findings("test", &[unbacked()]);
        assert!(!restarted.autopause_due);

        // A higher generation re-arms it.
        let (mut rearmed, _) = autopause_auditor(Some(2));
        rearmed.restore(auditor.state());
        rearmed.report_findings("test", &[unbacked()]);
        assert!(rearmed.autopause_due);
    }

    #[tokio::test]
    async fn only_a_fresh_approval_fires_during_catch_up() {
        let (mut catching_up, _) = autopause_auditor(Some(1));
        catching_up.caught_up = false;
        catching_up.report_findings("test", &[unbacked()]);
        assert!(!catching_up.autopause_due);
        catching_up.fire_autopause(&[unbacked()]);
        assert!(catching_up.autopause_due);
    }

    #[tokio::test]
    async fn no_fire_when_disabled() {
        let (mut disabled, metrics) = autopause_auditor(None);
        disabled.report_findings("test", &[unbacked()]);
        assert!(!disabled.autopause_due);
        assert!(!metrics.render().contains("hashi_monitor_autopause_armed"));
    }

    #[tokio::test]
    async fn a_failed_pause_keeps_the_saved_latch() {
        let (mut auditor, metrics) = autopause_auditor(Some(1));
        auditor.report_findings("test", &[unbacked()]);
        auditor.run_due_autopause().await;
        while !metrics.render().contains(r#"result="failed""#) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let saved = auditor.store.load().await.unwrap().unwrap();
        assert_eq!(saved.state.autopause_fired_generation, Some(1));
    }
}
