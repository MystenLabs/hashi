// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use hashi_monitor::domain::now_unix_seconds;

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

        /// Start of guardian audit window, as unix seconds.
        #[arg(long)]
        start: u64,

        /// End of guardian audit window, as unix seconds. Defaults to current time.
        #[arg(long)]
        end: Option<u64>,
    },
    /// Run continuous monitoring on guardian timeline.
    Continuous {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of guardian audit period, as unix seconds.
        #[arg(long)]
        start: u64,
    },
    /// Run key-provisioner init checks against guardian S3 logs.
    KpInit {
        /// Path to kp-init YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = hashi_telemetry::TelemetryConfig::new()
        .with_service_name("hashi-monitor")
        .with_target(false)
        .with_env()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Batch { config, start, end } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let end = end.unwrap_or_else(now_unix_seconds);
            let mut auditor = hashi_monitor::audit::BatchAuditor::new(&cfg, start, end).await?;
            auditor
                .run()
                .await
                .unwrap_or_else(|e| panic!("infra failure: {e:#}"));
        }
        Command::Continuous { config, start } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let mut auditor = hashi_monitor::audit::ContinuousAuditor::new(&cfg, start).await?;
            auditor.run().await?;
        }
        Command::KpInit { config } => {
            let cfg = hashi_monitor::kp::ProvisionerConfig::load_yaml(&config)?;
            hashi_monitor::kp::run(cfg).await?;
        }
    }

    Ok(())
}
