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

mod dump_utxos;
mod key_recovery;
mod sweep_utxos;
mod utxo_csv;

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
    DumpUtxos {
        #[command(flatten)]
        config: ConfigArgs,
    },
    SweepUtxos(sweep_utxos::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    hashi::init_crypto_provider();
    let cli = Cli::parse();

    match cli.command {
        Commands::SweepUtxos(args) => sweep_utxos::run(args).await,
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
        Commands::DumpUtxos { config } => {
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
            dump_utxos::run(&onchain_state)
        }
    }
}
