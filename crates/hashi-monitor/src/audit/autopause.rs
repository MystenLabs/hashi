// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pause Hashi on a live finding that autopauses, at most once per configured
//! generation. The fired generation is saved before pausing, so a restart
//! cannot fire again. Findings replayed by the catch-up never fire.

use super::Auditor;
use crate::findings::MonitorFinding;
use crate::pause::initiate_pause;

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

    /// Fire on the first finding that autopauses.
    pub(super) fn note_autopause(&mut self, findings: &[MonitorFinding]) {
        if !self.caught_up || !self.autopause_armed() {
            return;
        }
        let Some(finding) = findings.iter().find(|finding| finding.autopauses()) else {
            return;
        };
        tracing::error!(%finding, "autopause fired; pausing Hashi");
        self.autopause_fired_generation = self.autopause_generation();
        self.autopause_due = true;
    }

    /// Save the latch, then pause on a separate task.
    pub(super) async fn run_due_autopause(&mut self) {
        if !std::mem::take(&mut self.autopause_due) {
            return;
        }
        // Pause even if the save fails: the violation is live.
        self.save_snapshot().await;
        let cfg = self.cfg.clone();
        tokio::spawn(async move {
            match initiate_pause(&cfg).await {
                Ok(()) => tracing::warn!("autopause paused Hashi"),
                Err(error) => tracing::error!(?error, "autopause failed to pause Hashi"),
            }
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

    fn config_with_generation(generation: u64) -> Config {
        let mut cfg = Config::for_tests();
        cfg.pause = Some(PauseConfig {
            transaction_rpc_url: String::new(),
            object_id: None,
            operator_key_paths: Vec::new(),
            autopause_generation: Some(generation),
        });
        cfg
    }

    #[tokio::test]
    async fn autopause_fires_once_per_generation_across_restarts() {
        let unbacked = MonitorFinding::DepositUnbacked {
            sui: approval_of(&deposit_request(), 200),
        };
        let mut auditor = auditor_with(&config_with_generation(1), Arc::new(MonitorMetrics::new()));
        auditor.report_findings("test", std::slice::from_ref(&unbacked));
        assert!(auditor.autopause_due);
        assert!(!auditor.autopause_armed());

        // Neither a repeat nor a restart from the snapshot fires again.
        auditor.autopause_due = false;
        auditor.report_findings("test", std::slice::from_ref(&unbacked));
        assert!(!auditor.autopause_due);
        let mut restarted =
            auditor_with(&config_with_generation(1), Arc::new(MonitorMetrics::new()));
        restarted.restore(auditor.state());
        restarted.report_findings("test", std::slice::from_ref(&unbacked));
        assert!(!restarted.autopause_due);

        // A higher generation re-arms it.
        let mut rearmed = auditor_with(&config_with_generation(2), Arc::new(MonitorMetrics::new()));
        rearmed.restore(auditor.state());
        assert!(rearmed.autopause_armed());
        rearmed.report_findings("test", std::slice::from_ref(&unbacked));
        assert!(rearmed.autopause_due);
    }
}
