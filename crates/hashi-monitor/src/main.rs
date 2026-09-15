// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use clap::Subcommand;
use hashi_monitor::audit::continuous::ContinuousAuditWindow;
use hashi_monitor::domain::parse_utc_timestamp;
use hashi_monitor::metrics::MonitorMetrics;
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
        /// Defaults to the earliest time whose checks can still be pending, so a
        /// restart resumes open checks; violations anchored earlier are not re-reported.
        #[arg(long, value_parser = parse_utc_timestamp)]
        start: Option<u64>,

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
        }
        Command::Continuous {
            config,
            start,
            metrics_listen_addr,
        } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let start = start.unwrap_or_else(|| {
                ContinuousAuditWindow::default_start(&cfg, now_timestamp_secs())
            });
            let metrics = Arc::new(MonitorMetrics::new());
            tokio::spawn({
                let metrics = metrics.clone();
                async move {
                    if let Err(error) = metrics.serve(metrics_listen_addr).await {
                        tracing::error!(?error, "metrics server exited");
                    }
                }
            });
            let mut auditor =
                hashi_monitor::audit::ContinuousAuditor::new(&cfg, start, metrics).await?;
            auditor.run().await?;
        }
    }

    Ok(())
}
