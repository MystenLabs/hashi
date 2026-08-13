// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use hashi_monitor::domain::parse_utc_timestamp;
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
        #[arg(long, value_parser = parse_utc_timestamp)]
        start: u64,
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
        Command::Continuous { config, start } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let mut auditor = hashi_monitor::audit::ContinuousAuditor::new(&cfg, start).await?;
            auditor.run().await?;
        }
    }

    Ok(())
}
