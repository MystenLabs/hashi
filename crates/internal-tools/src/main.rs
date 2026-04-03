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

#[derive(Parser)]
#[command(name = "internal-tools", about = "Internal operator tools for Hashi")]
struct Cli {
    /// Path to a node config TOML file (provides sui-rpc, chain-id, hashi-ids).
    #[arg(long)]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    KeyRecovery(key_recovery::Args),
    DumpUtxos,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    let config_str = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("failed to read config: {}", cli.config.display()))?;
    let config: Config =
        toml::from_str(&config_str).with_context(|| "failed to parse config TOML")?;

    let sui_rpc = config
        .sui_rpc
        .as_deref()
        .ok_or_else(|| anyhow!("config missing sui-rpc"))?;
    let chain_id = config
        .sui_chain_id
        .as_deref()
        .ok_or_else(|| anyhow!("config missing sui-chain-id"))?;
    let hashi_ids = config.hashi_ids();

    println!("Connecting to Sui RPC: {sui_rpc}");
    println!("Chain ID: {chain_id}");

    let (onchain_state, _watcher) = OnchainState::new(sui_rpc, hashi_ids, None, None, None)
        .await
        .context("failed to connect to Sui RPC")?;

    match cli.command {
        Commands::KeyRecovery(args) => key_recovery::run(args, &onchain_state, chain_id).await,
        Commands::DumpUtxos => dump_utxos::run(&onchain_state),
    }
}
