// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `hashi-monitor` command: a batch audit or a continuous monitor.
//!
//! How it works:
//! 1. `batch` loads the config file and audits one guardian time range. It
//!    exits with an error if the audit produced findings.
//! 2. `continuous` loads the config file, binds the metrics port, and
//!    monitors from the start time on: where its snapshot says the last run
//!    stopped, or the default start that covers an outage of up to a week.
//!
//! Assumptions:
//! - Timestamps on the command line are whole-second UTC RFC 3339.
//! - The metrics port must bind before the audit starts, since alerting
//!   reads it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use clap::Subcommand;
use hashi_monitor::metrics::MonitorMetrics;
use hashi_monitor::store::SnapshotStore;
use hashi_monitor::time::parse_utc_timestamp;
use hashi_types::guardian::time::now_timestamp_secs;

#[derive(Debug, Parser)]
#[command(name = "hashi-monitor")]
#[command(about = "Monitor correlating Hashi / Guardian / Sui events")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a one-time batch audit over guardian [start, end].
    Batch {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of guardian audit window as UTC, for example 2026-08-04T19:00:00Z.
        #[arg(long, value_parser = parse_utc_timestamp)]
        start: u64,

        /// End of guardian audit window as UTC. Defaults to the current time.
        #[arg(long, value_parser = parse_utc_timestamp)]
        end: Option<u64>,
    },
    /// Run continuous monitoring on guardian timeline.
    Continuous {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of guardian audit period as UTC, for example 2026-08-04T19:00:00Z.
        /// With a snapshot of this deployment, the audit resumes from the snapshot
        /// unless this is earlier. Without one, this defaults to far enough back to
        /// audit a monitor outage of up to a week; a restart reports findings from
        /// that period again.
        #[arg(long, value_parser = parse_utc_timestamp)]
        start: Option<u64>,

        /// GCS bucket that keeps the monitor's snapshot, so a restart resumes where
        /// the last run stopped. Without it, nothing survives a restart.
        #[arg(long)]
        snapshot_bucket: Option<String>,

        /// Address serving Prometheus metrics at `/metrics`.
        #[arg(long, default_value = "0.0.0.0:9184")]
        metrics_listen_addr: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Batch { config, start, end } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let end = end.unwrap_or_else(now_timestamp_secs);
            let mut auditor = hashi_monitor::audit::BatchAuditor::new(&cfg, start, end).await?;
            auditor.run().await?;
            anyhow::ensure!(
                !auditor.violation_found,
                "audit produced findings: see logs"
            );
        }
        Command::Continuous {
            config,
            start,
            snapshot_bucket,
            metrics_listen_addr,
        } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let store = snapshot_bucket
                .as_deref()
                .map(SnapshotStore::gcs)
                .transpose()?;
            let metrics = Arc::new(MonitorMetrics::new());
            // Alerting reads this port, so a monitor that cannot serve it is
            // unobservable. Bind before auditing anything and fail if it can't.
            let listener = tokio::net::TcpListener::bind(metrics_listen_addr)
                .await
                .with_context(|| format!("failed to bind metrics on {metrics_listen_addr}"))?;
            tokio::spawn({
                let metrics = metrics.clone();
                async move {
                    if let Err(error) = metrics.serve(listener).await {
                        tracing::error!(?error, "metrics server exited");
                    }
                }
            });
            let mut auditor =
                hashi_monitor::audit::ContinuousAuditor::new(&cfg, start, metrics, store).await?;
            auditor.run().await?;
        }
    }

    Ok(())
}
