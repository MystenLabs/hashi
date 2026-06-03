// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Internal operator tools for the Hashi bridge.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use clap::Parser;
use clap::Subcommand;
use hashi::config::Config;
use hashi::onchain::OnchainState;

mod bootstrap_guardian;
mod fetch_guardian_info;
mod generate_master_key;
mod key_recovery;

#[derive(Parser)]
#[command(name = "internal-tools", about = "Internal operator tools for Hashi")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Shared arguments for subcommands that connect to a Sui node.
#[derive(Parser)]
struct ConfigArgs {
    /// Path to a node config TOML file (provides sui-rpc, chain-id, hashi-ids).
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

#[derive(Subcommand)]
enum Commands {
    KeyRecovery {
        #[command(flatten)]
        config: ConfigArgs,
        #[command(flatten)]
        args: key_recovery::Args,
    },
    BootstrapGuardian {
        #[command(flatten)]
        config: ConfigArgs,
        #[command(flatten)]
        args: bootstrap_guardian::Args,
    },
    FetchGuardianInfo {
        #[command(flatten)]
        args: fetch_guardian_info::Args,
    },
    /// Generate a fresh BTC master keypair for the guardian. Used by the
    /// deploy workflow: pin the pubkey on-chain via `hashi publish`, then
    /// hand the secret to `bootstrap-guardian --master-secret-hex`.
    GenerateMasterKey {
        #[command(flatten)]
        args: generate_master_key::Args,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    hashi::init_crypto_provider();
    let cli = Cli::parse();

    match cli.command {
        Commands::KeyRecovery { config, args } => {
            let cfg = config.load()?;
            let sui_rpc = cfg
                .sui_rpc
                .as_deref()
                .ok_or_else(|| anyhow!("config missing sui-rpc"))?;
            let chain_id = cfg
                .sui_chain_id
                .as_deref()
                .ok_or_else(|| anyhow!("config missing sui-chain-id"))?;
            println!("Connecting to Sui RPC: {sui_rpc}");
            println!("Chain ID: {chain_id}");
            let (onchain_state, _watcher) =
                OnchainState::new(sui_rpc, cfg.hashi_ids(), None, None, None)
                    .await
                    .context("failed to connect to Sui RPC")?;
            key_recovery::run(args, &onchain_state, chain_id).await
        }
        Commands::BootstrapGuardian { config, args } => {
            let cfg = config.load()?;
            let sui_rpc = cfg
                .sui_rpc
                .as_deref()
                .ok_or_else(|| anyhow!("config missing sui-rpc"))?;
            println!("Connecting to Sui RPC: {sui_rpc}");
            let (onchain_state, _watcher) =
                OnchainState::new(sui_rpc, cfg.hashi_ids(), None, None, None)
                    .await
                    .context("failed to connect to Sui RPC")?;
            bootstrap_guardian::run(args, &onchain_state).await
        }
        Commands::FetchGuardianInfo { args } => fetch_guardian_info::run(args).await,
        Commands::GenerateMasterKey { args } => generate_master_key::run(args),
    }
}
