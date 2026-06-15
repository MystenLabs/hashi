// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use clap::Parser;
use clap::Subcommand;
use hashi::config::Config;
use hashi::onchain::OnchainState;
use std::path::PathBuf;

mod ceremony;
mod config;
mod dev_bootstrap;
mod fetch_info;
mod generate_master_key;
mod heartbeat_checks;
mod limiter_recovery;
mod provisioner;

#[derive(Parser)]
#[command(name = "hashi-guardian-init")]
#[command(about = "Off-enclave tooling to initialize a guardian")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Production guardian key ceremony commands.
    Ceremony {
        #[command(subcommand)]
        command: CeremonyCommand,
    },
    /// Run a key provisioner's init checks against guardian S3 logs and emit its share.
    Provision {
        /// Path to provisioner-init YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Guardian helper tooling and dev-only shortcuts.
    Tools {
        #[command(subcommand)]
        command: ToolsCommand,
    },
}

#[derive(Subcommand)]
enum CeremonyCommand {
    /// Run the one-time production guardian key ceremony and upload encrypted KP shares.
    Run {
        /// Path to ceremony-run YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
    /// Verify this KP can fetch and decrypt its encrypted ceremony share.
    Verify {
        /// Path to ceremony-verify YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum ToolsCommand {
    /// Drive the current centralized dev guardian bootstrap shortcut.
    DevBootstrap {
        #[command(flatten)]
        config: ConfigArgs,
        #[command(flatten)]
        args: dev_bootstrap::Args,
    },
    /// Fetch deployed guardian public keys.
    FetchInfo {
        #[command(flatten)]
        args: fetch_info::Args,
    },
    /// Generate a fresh BTC master keypair for the dev bootstrap shortcut.
    GenerateMasterKey {
        #[command(flatten)]
        args: generate_master_key::Args,
    },
}

#[derive(Parser)]
struct ConfigArgs {
    /// Path to a node config TOML file (provides sui-rpc and hashi-ids).
    #[arg(long)]
    config: PathBuf,
}

impl ConfigArgs {
    fn load(&self) -> anyhow::Result<Config> {
        let s = std::fs::read_to_string(&self.config)
            .with_context(|| format!("failed to read config: {}", self.config.display()))?;
        toml::from_str(&s).context("failed to parse config TOML")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hashi_types::telemetry::TelemetryConfig::new()
        .with_target(false)
        .with_env()
        .init();
    hashi::init_crypto_provider();

    match Cli::parse().command {
        Command::Ceremony { command } => match command {
            CeremonyCommand::Run { config } => {
                let cfg = ceremony::CeremonyRunConfig::load_yaml(&config)?;
                ceremony::run(cfg).await?;
            }
            CeremonyCommand::Verify { config } => {
                let cfg = ceremony::CeremonyVerifyConfig::load_yaml(&config)?;
                ceremony::verify(cfg).await?;
            }
        },
        Command::Provision { config } => {
            let cfg = provisioner::ProvisionerConfig::load_yaml(&config)?;
            provisioner::run(cfg).await?;
        }
        Command::Tools { command } => match command {
            ToolsCommand::DevBootstrap { config, args } => {
                let cfg = config.load()?;
                let sui_rpc = cfg
                    .sui_rpc
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("config missing sui-rpc"))?;
                println!("Connecting to Sui RPC: {sui_rpc}");
                let (onchain_state, _watcher) =
                    OnchainState::new(sui_rpc, cfg.hashi_ids(), None, None, None)
                        .await
                        .context("failed to connect to Sui RPC")?;
                dev_bootstrap::run(args, &onchain_state).await?;
            }
            ToolsCommand::FetchInfo { args } => fetch_info::run(args).await?,
            ToolsCommand::GenerateMasterKey { args } => generate_master_key::run(args)?,
        },
    }
    Ok(())
}
