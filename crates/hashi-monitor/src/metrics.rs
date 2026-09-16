// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for continuous audits, served at `/metrics`.

use std::sync::Arc;

use hashi_types::guardian::time::UnixSeconds;
use prometheus::Encoder;
use prometheus::IntGaugeVec;
use prometheus::Opts;
use prometheus::Registry;
use prometheus::TextEncoder;
use tracing::info;

use crate::findings::FindingCategory;
use crate::findings::MonitorFinding;

pub const SOURCE_SUI: &str = "sui";
pub const SOURCE_GUARDIAN: &str = "guardian";
pub const SOURCE_BTC: &str = "btc";

pub struct MonitorMetrics {
    registry: Registry,
    /// Unix time of the latest finding per category; 0 until one is reported.
    last_finding_timestamp_seconds: IntGaugeVec,
    /// Unix time each source has been checked through: the Sui and guardian
    /// cursors, and the start of the last successful Bitcoin lookup cycle.
    /// 0 until the auditor starts, so a monitor that never starts reads stale.
    checked_through_timestamp_seconds: IntGaugeVec,
}

impl MonitorMetrics {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let registry = Registry::new();
        let last_finding_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "hashi_monitor_last_finding_timestamp_seconds",
                "Unix time of the latest monitor finding by category",
            ),
            &["category"],
        )
        .expect("valid metric");
        let checked_through_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "hashi_monitor_checked_through_timestamp_seconds",
                "Unix time through which each source has been checked",
            ),
            &["source"],
        )
        .expect("valid metric");

        registry
            .register(Box::new(last_finding_timestamp_seconds.clone()))
            .expect("register");
        registry
            .register(Box::new(checked_through_timestamp_seconds.clone()))
            .expect("register");

        for category in [FindingCategory::Safety, FindingCategory::Liveness] {
            last_finding_timestamp_seconds
                .with_label_values(&[category.to_string().as_str()])
                .set(0);
        }
        for source in [SOURCE_SUI, SOURCE_GUARDIAN, SOURCE_BTC] {
            checked_through_timestamp_seconds
                .with_label_values(&[source])
                .set(0);
        }

        Self {
            registry,
            last_finding_timestamp_seconds,
            checked_through_timestamp_seconds,
        }
    }

    pub fn record_findings(&self, findings: &[MonitorFinding], now: UnixSeconds) {
        for finding in findings {
            self.last_finding_timestamp_seconds
                .with_label_values(&[finding.category().to_string().as_str()])
                .set(gauge_value(now));
        }
    }

    pub fn set_checked_through(&self, source: &str, timestamp: UnixSeconds) {
        self.checked_through_timestamp_seconds
            .with_label_values(&[source])
            .set(gauge_value(timestamp));
    }

    fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("encode metrics");
        String::from_utf8(buf).expect("metrics are utf-8")
    }

    /// Serve `GET /metrics` on an already bound listener, forever.
    pub async fn serve(self: Arc<Self>, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let metrics = self.clone();
                async move { metrics.render() }
            }),
        );
        info!("Metrics listening on {}.", listener.local_addr()?);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

fn gauge_value(timestamp: UnixSeconds) -> i64 {
    i64::try_from(timestamp).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use hashi_types::guardian::WithdrawalID;

    use super::*;
    use crate::domain::MonitorEventId;
    use crate::domain::MonitorEventType;
    use crate::domain::WithdrawalEventType;
    use crate::findings::EventRelation;

    #[tokio::test]
    async fn the_metrics_route_serves_the_registry() {
        use tokio::io::AsyncReadExt as _;
        use tokio::io::AsyncWriteExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let metrics = Arc::new(MonitorMetrics::new());
        metrics.set_checked_through(SOURCE_SUI, 1_700_000_000);
        tokio::spawn(metrics.serve(listener));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(
            response.contains(
                r#"hashi_monitor_checked_through_timestamp_seconds{source="sui"} 1700000000"#
            ),
            "{response}"
        );
    }

    #[test]
    fn every_series_is_exported_before_the_auditor_runs() {
        let rendered = MonitorMetrics::new().render();

        for line in [
            r#"hashi_monitor_last_finding_timestamp_seconds{category="safety"} 0"#,
            r#"hashi_monitor_last_finding_timestamp_seconds{category="liveness"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="sui"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="guardian"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="btc"} 0"#,
        ] {
            assert!(rendered.contains(line), "missing {line} in:\n{rendered}");
        }
    }

    #[test]
    fn findings_set_the_latest_timestamp_of_their_category() {
        let metrics = MonitorMetrics::new();
        let liveness = MonitorFinding::ExpectedEventMissing {
            event_id: MonitorEventId::Withdrawal(WithdrawalID::new([1; 32])),
            event_type: MonitorEventType::Withdrawal(WithdrawalEventType::E3BtcConfirmed),
            relation: EventRelation::Successor,
            deadline: 50,
            cursor: 60,
        };

        metrics.record_findings(
            &[MonitorFinding::InvalidEventAdded("invalid wid".to_string())],
            100,
        );
        metrics.record_findings(&[liveness], 200);
        metrics.set_checked_through(SOURCE_GUARDIAN, 300);

        let rendered = metrics.render();
        for line in [
            r#"hashi_monitor_last_finding_timestamp_seconds{category="safety"} 100"#,
            r#"hashi_monitor_last_finding_timestamp_seconds{category="liveness"} 200"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="guardian"} 300"#,
        ] {
            assert!(rendered.contains(line), "missing {line} in:\n{rendered}");
        }
    }
}
