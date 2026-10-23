// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for continuous audits, served at `/metrics`.

use std::sync::Arc;

use hashi_types::guardian::time::UnixSeconds;
use prometheus::Encoder;
use prometheus::IntGauge;
use prometheus::IntGaugeVec;
use prometheus::Opts;
use prometheus::Registry;
use prometheus::TextEncoder;
use tracing::info;

use crate::findings::MonitorFinding;

pub const SOURCE_SUI: &str = "sui";
pub const SOURCE_GUARDIAN: &str = "guardian";
pub const SOURCE_BTC: &str = "btc";
/// The daily check of every UTXO in the UTXO pool against Bitcoin.
pub const SOURCE_UTXO: &str = "utxo";
/// The snapshot. Its time is the last successful save.
pub const SOURCE_SNAPSHOT: &str = "snapshot";

pub struct MonitorMetrics {
    registry: Registry,
    pool_utxo_count: IntGauge,
    oldest_utxo_timestamp_seconds: IntGauge,
    /// Unix time of the latest finding; 0 until one is reported.
    last_finding_timestamp_seconds: IntGauge,
    /// Unix time each source has been checked through: the Sui and guardian
    /// cursors, and for Bitcoin, which is looked up rather than scanned, the
    /// start of the last pass over every pending confirmation. For the
    /// snapshot, the time of the last successful save.
    /// 0 until the auditor starts, so a monitor that never starts reads stale.
    checked_through_timestamp_seconds: IntGaugeVec,
}

impl Default for MonitorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let last_finding_timestamp_seconds = IntGauge::new(
            "hashi_monitor_last_finding_timestamp_seconds",
            "Unix time of the latest monitor finding",
        )
        .expect("valid metric");
        let checked_through_timestamp_seconds = IntGaugeVec::new(
            Opts::new(
                "hashi_monitor_checked_through_timestamp_seconds",
                "Unix time through which each source has been checked; for btc, the start of the last pass that looked up every pending confirmation",
            ),
            &["source"],
        )
        .expect("valid metric");

        let pool_utxo_count = IntGauge::new(
            "hashi_monitor_pool_utxo_count",
            "Number of UTXOs held in the monitor pool",
        )
        .expect("valid metric");
        let oldest_utxo_timestamp_seconds = IntGauge::new(
            "hashi_monitor_oldest_utxo_timestamp_seconds",
            "Earliest held UTXO block timestamp in Unix seconds; 0 for an empty pool",
        )
        .expect("valid metric");
        registry
            .register(Box::new(pool_utxo_count.clone()))
            .expect("register");
        registry
            .register(Box::new(oldest_utxo_timestamp_seconds.clone()))
            .expect("register");

        registry
            .register(Box::new(last_finding_timestamp_seconds.clone()))
            .expect("register");
        registry
            .register(Box::new(checked_through_timestamp_seconds.clone()))
            .expect("register");

        for source in [
            SOURCE_SUI,
            SOURCE_GUARDIAN,
            SOURCE_BTC,
            SOURCE_UTXO,
            SOURCE_SNAPSHOT,
        ] {
            checked_through_timestamp_seconds
                .with_label_values(&[source])
                .set(0);
        }

        Self {
            registry,
            pool_utxo_count,
            oldest_utxo_timestamp_seconds,
            last_finding_timestamp_seconds,
            checked_through_timestamp_seconds,
        }
    }

    pub fn record_findings(&self, findings: &[MonitorFinding], now: UnixSeconds) {
        if !findings.is_empty() {
            self.last_finding_timestamp_seconds.set(gauge_value(now));
        }
    }

    /// The time of the last finding, or 0. The snapshot keeps it, so a
    /// restart does not lose a finding alerting has not read yet.
    pub fn last_finding(&self) -> UnixSeconds {
        UnixSeconds::try_from(self.last_finding_timestamp_seconds.get()).unwrap_or_default()
    }

    /// Set the last finding time that a snapshot saved.
    pub fn restore_last_finding(&self, timestamp: UnixSeconds) {
        self.last_finding_timestamp_seconds
            .set(gauge_value(timestamp));
    }

    pub fn set_checked_through(&self, source: &str, timestamp: UnixSeconds) {
        self.checked_through_timestamp_seconds
            .with_label_values(&[source])
            .set(gauge_value(timestamp));
    }

    pub fn set_utxo_pool(&self, count: usize, oldest_timestamp: Option<UnixSeconds>) {
        self.pool_utxo_count
            .set(i64::try_from(count).unwrap_or(i64::MAX));
        self.oldest_utxo_timestamp_seconds
            .set(gauge_value(oldest_timestamp.unwrap_or_default()));
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
    use super::*;

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
            "hashi_monitor_last_finding_timestamp_seconds 0",
            r#"hashi_monitor_checked_through_timestamp_seconds{source="sui"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="guardian"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="btc"} 0"#,
            r#"hashi_monitor_checked_through_timestamp_seconds{source="snapshot"} 0"#,
        ] {
            assert!(rendered.contains(line), "missing {line} in:\n{rendered}");
        }
    }

    #[test]
    fn a_finding_sets_the_latest_timestamp() {
        let metrics = MonitorMetrics::new();
        let finding = MonitorFinding::InvalidEventAdded("invalid wid".to_string());

        metrics.record_findings(std::slice::from_ref(&finding), 100);
        metrics.record_findings(&[], 150);
        metrics.record_findings(&[finding], 200);
        metrics.set_checked_through(SOURCE_GUARDIAN, 300);

        let rendered = metrics.render();
        for line in [
            "hashi_monitor_last_finding_timestamp_seconds 200",
            r#"hashi_monitor_checked_through_timestamp_seconds{source="guardian"} 300"#,
        ] {
            assert!(rendered.contains(line), "missing {line} in:\n{rendered}");
        }
    }
}
