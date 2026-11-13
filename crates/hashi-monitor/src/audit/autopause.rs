// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pause Hashi when a reported finding autopauses. The pause starts at once,
//! on a separate task, and only one runs at a time. A pause of an already
//! paused Hashi does nothing.

use super::Auditor;
use crate::findings::MonitorFinding;
use crate::metrics::AUTOPAUSE_FAILED;
use crate::metrics::AUTOPAUSE_SUCCEEDED;
use crate::pause::initiate_pause;
use hashi_types::guardian::time::now_timestamp_secs;

impl Auditor {
    /// Pause Hashi on the first finding that autopauses, if autopause is
    /// enabled and no pause is running.
    pub(super) fn autopause(&mut self, findings: &[MonitorFinding]) {
        if !self.cfg.pause.as_ref().is_some_and(|pause| pause.autopause) {
            return;
        }
        if self
            .pause_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return;
        }
        let Some(finding) = findings.iter().find(|finding| finding.autopauses()) else {
            return;
        };
        let cfg = self.cfg.clone();
        let metrics = self.metrics.clone();
        let finding = finding.to_string();
        self.pause_task = Some(tokio::spawn(async move {
            let result = match initiate_pause(&cfg).await {
                Ok(false) => return,
                Ok(true) => {
                    tracing::error!(finding, "autopause paused Hashi");
                    AUTOPAUSE_SUCCEEDED
                }
                Err(error) => {
                    tracing::error!(finding, ?error, "autopause failed to pause Hashi");
                    AUTOPAUSE_FAILED
                }
            };
            metrics.record_autopause(result, now_timestamp_secs());
        }));
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

    fn autopause_auditor(autopause: bool) -> (Auditor, Arc<MonitorMetrics>) {
        let mut cfg = Config::for_tests();
        cfg.pause = Some(PauseConfig {
            // Nothing listens here, so a pause fails.
            transaction_rpc_url: "http://127.0.0.1:1".to_owned(),
            object_id: None,
            operators: Vec::new(),
            bitcoin_api_url: String::new(),
            autopause,
        });
        let metrics = Arc::new(MonitorMetrics::new());
        (auditor_with(&cfg, metrics.clone()), metrics)
    }

    fn unbacked() -> MonitorFinding {
        MonitorFinding::DepositUnbacked {
            sui: approval_of(&deposit_request(), 200),
            reason: crate::findings::DepositUnbackedReason::Unverified,
        }
    }

    #[tokio::test]
    async fn a_finding_starts_one_pause_at_a_time() {
        let (mut auditor, metrics) = autopause_auditor(true);
        auditor.report_findings("test", &[unbacked()]);
        let first = auditor.pause_task.as_ref().unwrap().id();
        auditor.report_findings("test", &[unbacked()]);
        assert_eq!(auditor.pause_task.as_ref().unwrap().id(), first);

        auditor.pause_task.take().unwrap().await.unwrap();
        assert!(metrics.render().contains(r#"result="failed""#));
    }

    #[tokio::test]
    async fn no_pause_when_disabled() {
        let (mut auditor, _) = autopause_auditor(false);
        auditor.report_findings("test", &[unbacked()]);
        assert!(auditor.pause_task.is_none());
    }
}
