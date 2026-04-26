// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Example binary that demonstrates running a Bitcoin monitor on testnet4.
//! It uses hardcoded known-working testnet4 seed nodes for peer discovery.
//!
//! # Usage Examples
//!
//! Monitor testnet4:
//! ```bash
//! cargo run --example testnet_monitor -- --bitcoind-url http://localhost:18332 --bitcoind-user myuser --bitcoind-password mypass
//! ```
use std::io::Write;
use std::str::FromStr;

use bitcoin::Network;
use clap::Parser;
use hashi::btc_monitor::config::MonitorConfig;
use hashi::btc_monitor::monitor::Monitor;
use kyoto::TrustedPeer;
use tracing::error;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Run a Bitcoin P2P monitor on testnet4
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of confirmations required for a transaction to be considered canonical
    #[arg(short = 'c', long, default_value = "6")]
    confirmations: u32,

    /// Starting block height for synchronization (defaults to recent testnet4 height)
    #[arg(short = 's', long, default_value = "70000")]
    start_height: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// bitcoind JSON-RPC URL
    #[arg(long, default_value = "http://localhost:18332")]
    bitcoind_url: String,

    /// bitcoind JSON-RPC username (optional)
    #[arg(long)]
    bitcoind_user: Option<String>,

    /// bitcoind JSON-RPC password (optional)
    #[arg(long)]
    bitcoind_password: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if args.verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    info!("Starting BTC testnet4 monitor");

    // Hostname peers are resolved when popped from kyoto's whitelist;
    // re-resolution requires rebuilding the node (handled by the monitor's
    // connectivity supervisor).
    let peer_specs: &[(&str, u16)] = &[
        ("seed.testnet4.bitcoin.sprovoost.nl", 48333),
        ("seed.testnet4.wiz.biz", 48333),
    ];
    let trusted_peers: Vec<TrustedPeer> = peer_specs
        .iter()
        .map(|(host, port)| TrustedPeer::from_hostname(*host, *port))
        .collect();

    let bitcoind_auth = match (args.bitcoind_user, args.bitcoind_password) {
        (Some(user), Some(pass)) => corepc_client::client_sync::Auth::UserPass(user, pass),
        (None, None) => corepc_client::client_sync::Auth::None,
        _ => {
            eprintln!(
                "Error: Both --bitcoind-user and --bitcoind-password must be provided together"
            );
            std::process::exit(1);
        }
    };

    let config = MonitorConfig::builder()
        .network(Network::Testnet4)
        .confirmation_threshold(args.confirmations)
        .trusted_peers(trusted_peers)
        .start_height(args.start_height)
        .bitcoind_rpc_config(args.bitcoind_url.clone(), bitcoind_auth)
        .build();

    info!("Monitor configuration:");
    info!("  Network: {:?}", config.network);
    info!(
        "  Confirmations required: {}",
        config.confirmation_threshold
    );
    info!("  Starting height: {}", config.start_height);
    info!("  bitcoind RPC URL: {}", config.bitcoind_rpc_url);
    info!("  Initial peers: {}", config.trusted_peers.len());
    info!("  Peer addresses:");
    for (host, port) in peer_specs {
        info!("    - {host}:{port}");
    }

    // Create and start the monitor
    info!("Starting monitor...");
    let metrics = std::sync::Arc::new(hashi::metrics::Metrics::new_default());
    let (monitor_client, _service) = Monitor::run(config, metrics)?;

    info!("Monitor is running.");
    info!("Enter Bitcoin OutPoints in the format 'txid:vout' to confirm deposits.");
    info!("Press Ctrl-C to exit.");
    println!();

    // Interactive loop to accept OutPoint inputs
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("Enter OutPoint (txid:vout): ");
        stdout.flush()?;

        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => {
                // EOF reached
                break;
            }
            Ok(_) => {
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }

                // Parse the OutPoint
                match bitcoin::OutPoint::from_str(input) {
                    Ok(outpoint) => {
                        info!("Confirming deposit for OutPoint: {}", outpoint);

                        // Spawn a task to confirm the deposit
                        let client = monitor_client.clone();
                        tokio::spawn(async move {
                            match client.confirm_deposit(outpoint).await {
                                Ok(txout) => {
                                    info!("✓ Deposit confirmed for {}", outpoint);
                                    info!("  Value: {} sats", txout.value.to_sat());
                                    info!("  Script: {}", txout.script_pubkey);
                                }
                                Err(e) => {
                                    error!("✗ Failed to confirm deposit for {}: {}", outpoint, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error: Invalid OutPoint format: {}", e);
                        eprintln!("Expected format: txid:vout (e.g., abcd1234...:0)");
                    }
                }
            }
            Err(e) => {
                error!("Failed to read input: {}", e);
                break;
            }
        }
    }

    info!("Exiting...");
    Ok(())
}
