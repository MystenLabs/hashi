// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;

mod config;
mod fetch_info;
mod heartbeat_checks;
mod kp_ceremony;
mod kp_provision;
mod kp_roster;
mod limiter_recovery;
mod operator_ceremony;
mod operator_provision;

#[derive(Parser)]
#[command(name = "hashi-guardian-init")]
#[command(about = "Off-enclave tooling to initialize a guardian")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Commands run by the guardian operator.
    Operator {
        #[command(subcommand)]
        command: OperatorCommand,
    },
    /// Commands run by a key provisioner.
    KeyProvisioner {
        #[command(subcommand)]
        command: KeyProvisionerCommand,
    },
    /// Guardian helper tooling.
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand)]
enum OperatorCommand {
    /// Run the one-time production guardian key ceremony.
    Ceremony {
        /// Path to operator ceremony YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Initialize a withdraw-mode guardian with operator-supplied state.
    Provision {
        /// Path to operator provision YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyProvisionerCommand {
    /// Verify this KP can fetch and decrypt its encrypted ceremony share from guardian S3.
    Ceremony {
        /// Path to key-provisioner ceremony YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Run a key provisioner's init checks and submit its share to the relay.
    Provision {
        /// Path to key-provisioner provision YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ToolsCommand {
    /// Fetch deployed guardian public keys.
    FetchInfo {
        #[command(flatten)]
        args: fetch_info::Args,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();
    hashi::init_crypto_provider();

    match Cli::parse().command {
        Command::Operator { command } => match command {
            OperatorCommand::Ceremony { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_ceremony::run(cfg).await?;
            }
            OperatorCommand::Provision { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                operator_provision::run(cfg).await?;
            }
        },
        Command::KeyProvisioner { command } => match command {
            KeyProvisionerCommand::Ceremony { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_ceremony::run(cfg).await?;
            }
            KeyProvisionerCommand::Provision { config } => {
                let cfg = config::Config::load_yaml(&config)?;
                kp_provision::run(cfg).await?;
            }
        },
        Command::Tools { command } => match command {
            ToolsCommand::FetchInfo { args } => fetch_info::run(args).await?,
        },
    }
    Ok(())
}
