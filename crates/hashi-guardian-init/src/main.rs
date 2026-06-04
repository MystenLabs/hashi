// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap::Subcommand;
use hashi_guardian_init::provisioner_init;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hashi-guardian-init")]
#[command(about = "Off-enclave tooling to initialize a guardian")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a key provisioner's init checks against guardian S3 logs and emit its share.
    Provisioner {
        /// Path to provisioner-init YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    // Operator init lands here as a sibling subcommand.
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();

    match Cli::parse().command {
        Command::Provisioner { config } => {
            let cfg = provisioner_init::ProvisionerConfig::load_yaml(&config)?;
            provisioner_init::run(cfg).await?;
        }
    }
    Ok(())
}
