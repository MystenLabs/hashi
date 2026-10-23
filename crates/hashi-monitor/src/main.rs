// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `hashi-monitor` command: a continuous monitor.
//!
//! How it works:
//! 1. It loads the config file, binds the metrics port, and monitors from
//!    where its snapshot says the last run stopped, or on a first run from
//!    the bridge's genesis on Sui.
//!
//! Assumptions:
//! - The metrics port must bind before the audit starts, since alerting
//!   reads it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use hashi_monitor::metrics::MonitorMetrics;
use hashi_monitor::store::SnapshotStore;

#[derive(Debug, Parser)]
#[command(name = "hashi-monitor")]
#[command(about = "Monitor correlating Hashi / Guardian / Sui events")]
struct Cli {
    /// Path to YAML config file.
    #[arg(long)]
    config: PathBuf,

    /// GCS bucket that keeps the monitor's snapshot: the audit state and the
    /// UTXO pool. A restart resumes from it. Without a snapshot, the monitor
    /// starts from the bridge's genesis on Sui with an empty pool, which needs
    /// a Sui node that keeps the history from there.
    #[arg(long)]
    snapshot_bucket: String,

    /// Address serving Prometheus metrics at `/metrics`.
    #[arg(long, default_value = "0.0.0.0:9184")]
    metrics_listen_addr: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();

    let cli = Cli::parse();

    let cfg = hashi_monitor::config::Config::load_yaml(&cli.config)?;
    let store = SnapshotStore::gcs(&cli.snapshot_bucket)?;
    let metrics = Arc::new(MonitorMetrics::new());
    // Alerting reads this port, so a monitor that cannot serve it is
    // unobservable. Bind before auditing anything and fail if it can't.
    let listener = tokio::net::TcpListener::bind(cli.metrics_listen_addr)
        .await
        .with_context(|| format!("failed to bind metrics on {}", cli.metrics_listen_addr))?;
    tokio::spawn({
        let metrics = metrics.clone();
        async move {
            if let Err(error) = metrics.serve(listener).await {
                tracing::error!(?error, "metrics server exited");
            }
        }
    });
    let mut auditor = hashi_monitor::audit::ContinuousAuditor::new(&cfg, metrics, store).await?;
    auditor.run().await?;

    Ok(())
}
