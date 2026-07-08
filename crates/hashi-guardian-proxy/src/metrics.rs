// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics for the proxy, served on `METRICS_LISTEN_ADDR`. The
//! request counter's `outcome` label is the wid cache's decision surface —
//! `unavailable_*` outcomes are the fail-closed paths and worth alerting on
//! (`unavailable_verify_failed` in particular: a log record whose signatures
//! don't verify is either bucket tampering or version skew).

use prometheus::Encoder;
use prometheus::Histogram;
use prometheus::HistogramOpts;
use prometheus::IntCounter;
use prometheus::IntCounterVec;
use prometheus::Opts;
use prometheus::Registry;
use prometheus::TextEncoder;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

pub const OUTCOME_L1_HIT: &str = "l1_hit";
pub const OUTCOME_S3_HIT: &str = "s3_hit";
pub const OUTCOME_FORWARDED: &str = "forwarded";
/// A log record existed but the enclave never committed its seq (S3 ack lost
/// before the limiter commit); forwarded so the enclave signs and debits it
/// properly instead of replaying an un-debited record.
pub const OUTCOME_FORWARDED_UNCOMMITTED: &str = "forwarded_uncommitted";
pub const OUTCOME_UNAVAILABLE_LOG_STORE: &str = "unavailable_log_store";
pub const OUTCOME_UNAVAILABLE_SCAN_CAP: &str = "unavailable_scan_cap";
pub const OUTCOME_UNAVAILABLE_VERIFY_FAILED: &str = "unavailable_verify_failed";
pub const OUTCOME_UNAVAILABLE_GUARDIAN_INFO: &str = "unavailable_guardian_info";

pub struct ProxyMetrics {
    registry: Registry,
    /// `StandardWithdrawal` requests by cache outcome.
    pub requests: IntCounterVec,
    /// LIST calls per S3 lookup (hit or miss); the scan cap bounds the tail.
    pub scan_lists: Histogram,
    /// Wid-matching log records that failed to parse (schema skew or garbage).
    pub record_parse_failures: IntCounter,
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
        let scan_lists = Histogram::with_opts(
            HistogramOpts::new(
                "guardian_proxy_widlog_scan_lists",
                "S3 LIST calls per wid log lookup",
            )
            .buckets(vec![2.0, 5.0, 10.0, 25.0, 50.0, 100.0]),
        )
        .expect("valid metric");
        let record_parse_failures = IntCounter::new(
            "guardian_proxy_widlog_parse_failures_total",
            "Wid-matching log records that failed to parse",
        )
        .expect("valid metric");

        registry
            .register(Box::new(requests.clone()))
            .expect("register");
        registry
            .register(Box::new(scan_lists.clone()))
            .expect("register");
        registry
            .register(Box::new(record_parse_failures.clone()))
            .expect("register");

        Self {
            registry,
            requests,
            scan_lists,
            record_parse_failures,
        }
    }

    pub fn outcome(&self, outcome: &str) {
        self.requests.with_label_values(&[outcome]).inc();
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
