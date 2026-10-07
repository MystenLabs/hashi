// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the proxy, served on `METRICS_LISTEN_ADDR`. The
//! `unavailable_*` outcomes are the fail-closed paths. Alert on them, and on
//! a `widlog_cursor_lag_seconds` that grows (the index tail has stalled).

use prometheus::Encoder;
use prometheus::IntCounter;
use prometheus::IntCounterVec;
use prometheus::IntGauge;
use prometheus::Opts;
use prometheus::Registry;
use prometheus::TextEncoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub const OUTCOME_HIT: &str = "hit";
pub const OUTCOME_FORWARDED: &str = "forwarded";
pub const OUTCOME_UNAVAILABLE_LOG_STORE: &str = "unavailable_log_store";

pub struct ProxyMetrics {
    registry: Registry,
    /// `StandardWithdrawal` requests by cache outcome.
    pub requests: IntCounterVec,
    /// Wids in the index.
    pub widlog_index_size: IntGauge,
    /// Seconds the index tail trails the clock. Normally less than 70 minutes.
    pub widlog_cursor_lag_seconds: IntGauge,
    /// Tail ticks that did not list an hour directory.
    pub widlog_tail_failures: IntCounter,
    /// Withdrawal log keys or records that did not parse (schema skew or garbage).
    /// A record that does not parse fails its wid closed.
    pub record_parse_failures: IntCounter,
    /// When the served TLS certificate expires, in unix seconds.
    pub tls_cert_not_after: IntGauge,
    /// Failed TLS certificate reloads; the proxy keeps serving the old one.
    pub tls_cert_reload_failures: IntCounter,
    /// Requests the committee member gate refused, by reason.
    pub member_refused: IntCounterVec,
    /// Members on the current allowlist snapshot.
    pub member_allowlist_size: IntGauge,
    /// Checkpoint time of the chain state on the allowlist; its age is what to alert on.
    pub member_snapshot_timestamp_seconds: IntGauge,
    /// Failed allowlist reads.
    pub member_refresh_failures: IntCounter,
}

impl ProxyMetrics {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let registry = Registry::new();
        let requests = IntCounterVec::new(
            Opts::new(
                "guardian_proxy_withdrawal_requests_total",
                "StandardWithdrawal requests by wid-cache outcome",
            ),
            &["outcome"],
        )
        .expect("valid metric");
        let widlog_index_size = IntGauge::new(
            "guardian_proxy_widlog_index_size",
            "Wids in the withdrawal log index",
        )
        .expect("valid metric");
        let widlog_cursor_lag_seconds = IntGauge::new(
            "guardian_proxy_widlog_cursor_lag_seconds",
            "Seconds the withdrawal log index tail trails the clock",
        )
        .expect("valid metric");
        let widlog_tail_failures = IntCounter::new(
            "guardian_proxy_widlog_tail_failures_total",
            "Withdrawal log index tail ticks that failed",
        )
        .expect("valid metric");
        let record_parse_failures = IntCounter::new(
            "guardian_proxy_widlog_parse_failures_total",
            "Withdrawal log keys or records that failed to parse",
        )
        .expect("valid metric");
        let tls_cert_not_after = IntGauge::new(
            "guardian_proxy_tls_cert_not_after_seconds",
            "Expiry of the served TLS certificate, in unix seconds",
        )
        .expect("valid metric");
        let tls_cert_reload_failures = IntCounter::new(
            "guardian_proxy_tls_cert_reload_failures_total",
            "TLS certificate reloads that failed",
        )
        .expect("valid metric");
        let member_refused = IntCounterVec::new(
            Opts::new(
                "guardian_proxy_member_refused_total",
                "Requests refused by the committee member gate, by reason",
            ),
            &["reason"],
        )
        .expect("valid metric");
        let member_allowlist_size = IntGauge::new(
            "guardian_proxy_member_allowlist_size",
            "Committee members on the current allowlist snapshot",
        )
        .expect("valid metric");
        let member_snapshot_timestamp_seconds = IntGauge::new(
            "guardian_proxy_member_snapshot_timestamp_seconds",
            "Checkpoint time, in unix seconds, of the chain state on the committee member allowlist",
        )
        .expect("valid metric");
        let member_refresh_failures = IntCounter::new(
            "guardian_proxy_member_refresh_failures_total",
            "Failed committee member allowlist reads",
        )
        .expect("valid metric");

        registry
            .register(Box::new(requests.clone()))
            .expect("register");
        registry
            .register(Box::new(widlog_index_size.clone()))
            .expect("register");
        registry
            .register(Box::new(widlog_cursor_lag_seconds.clone()))
            .expect("register");
        registry
            .register(Box::new(widlog_tail_failures.clone()))
            .expect("register");
        registry
            .register(Box::new(record_parse_failures.clone()))
            .expect("register");
        registry
            .register(Box::new(tls_cert_not_after.clone()))
            .expect("register");
        registry
            .register(Box::new(tls_cert_reload_failures.clone()))
            .expect("register");
        registry
            .register(Box::new(member_refused.clone()))
            .expect("register");
        registry
            .register(Box::new(member_allowlist_size.clone()))
            .expect("register");
        registry
            .register(Box::new(member_snapshot_timestamp_seconds.clone()))
            .expect("register");
        registry
            .register(Box::new(member_refresh_failures.clone()))
            .expect("register");

        Self {
            registry,
            requests,
            widlog_index_size,
            widlog_cursor_lag_seconds,
            widlog_tail_failures,
            record_parse_failures,
            tls_cert_not_after,
            tls_cert_reload_failures,
            member_refused,
            member_allowlist_size,
            member_snapshot_timestamp_seconds,
            member_refresh_failures,
        }
    }

    pub fn outcome(&self, outcome: &str) {
        self.requests.with_label_values(&[outcome]).inc();
    }

    /// The registry behind `/metrics`, for the remote-write pusher.
    pub fn registry(&self) -> Registry {
        self.registry.clone()
    }

    fn render(&self) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&self.registry.gather(), &mut buf)
            .expect("encode metrics");
        String::from_utf8(buf).expect("metrics are utf-8")
    }

    /// Serve `GET /metrics` forever; spawned alongside the gRPC server.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> anyhow::Result<()> {
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(move || {
                let metrics = self.clone();
                async move { metrics.render() }
            }),
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!("Metrics listening on {addr}.");
        axum::serve(listener, app).await?;
        Ok(())
    }
}
