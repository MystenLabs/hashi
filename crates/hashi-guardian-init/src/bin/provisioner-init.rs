// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use hashi_guardian_init::provisioner_init;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "provisioner-init")]
#[command(
    about = "Run a key provisioner's init checks against guardian S3 logs and emit its share"
)]
struct Cli {
    /// Path to provisioner-init YAML config file.
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();

    let cli = Cli::parse();
    let cfg = provisioner_init::ProvisionerConfig::load_yaml(&cli.config)?;
    provisioner_init::run(cfg).await?;
    Ok(())
}
