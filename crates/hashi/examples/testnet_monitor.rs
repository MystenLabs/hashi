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

    let peer_specs: &[(&str, u16)] = &[
        ("seed.testnet4.bitcoin.sprovoost.nl", 48333),
        ("seed.testnet4.wiz.biz", 48333),
    ];
    let trusted_peers: Vec<TrustedPeer> = peer_specs
        .iter()
        .map(|&(host, port)| TrustedPeer::from_hostname(host, port))
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
        .trusted_peers(trusted_peers)
        .start_height(args.start_height)
        .bitcoind_rpc_config(args.bitcoind_url.clone(), bitcoind_auth)
        .build();

    info!("Monitor configuration:");
    info!("  Network: {:?}", config.network);
    info!("  Confirmations required: {}", args.confirmations);
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
    info!("Enter deposits as 'txid:vout amount_sat address' to confirm them.");
    info!("Press Ctrl-C to exit.");
    println!();

    // Interactive loop to accept deposit inputs
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    loop {
        print!("Enter deposit (txid:vout amount_sat address): ");
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

                match parse_deposit(input) {
                    Ok((outpoint, expected_txout)) => {
                        info!("Checking deposit for OutPoint: {}", outpoint);

                        // Spawn a task to check the deposit at the current Bitcoin tip.
                        let client = monitor_client.clone();
                        let confirmations = args.confirmations;
                        tokio::spawn(async move {
                            match client
                                .confirm_deposit(outpoint, expected_txout, confirmations)
                                .await
                            {
                                Ok(hashi::btc_monitor::monitor::DepositConfirmation::Confirmed(
                                    txout,
                                )) => {
                                    info!("✓ Deposit confirmed for {}", outpoint);
                                    info!("  Value: {} sats", txout.value.to_sat());
                                    info!("  Script: {}", txout.script_pubkey);
                                }
                                Ok(hashi::btc_monitor::monitor::DepositConfirmation::NotFound) => {
                                    info!("Deposit transaction not found for {}", outpoint);
                                }
                                Ok(hashi::btc_monitor::monitor::DepositConfirmation::InMempool) => {
                                    info!("Deposit transaction is in the mempool for {}", outpoint);
                                }
                                Ok(
                                    hashi::btc_monitor::monitor::DepositConfirmation::InsufficientConfirmations {
                                        confirmations,
                                        required_confirmations,
                                    },
                                ) => {
                                    info!(
                                        "Deposit has {confirmations}/{required_confirmations} confirmations for {outpoint}"
                                    );
                                }
                                Err(e) => {
                                    error!("✗ Failed to check deposit for {}: {}", outpoint, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        eprintln!(
                            "Expected format: txid:vout amount_sat address (e.g., abcd1234...:0 100000 tb1p...)"
                        );
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

fn parse_deposit(input: &str) -> Result<(bitcoin::OutPoint, bitcoin::TxOut), String> {
    let mut fields = input.split_whitespace();
    let (Some(outpoint), Some(amount), Some(address), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("expected three fields".to_owned());
    };
    let outpoint =
        bitcoin::OutPoint::from_str(outpoint).map_err(|e| format!("invalid OutPoint: {e}"))?;
    let amount = amount.parse().map_err(|e| format!("invalid amount: {e}"))?;
    let address = bitcoin::Address::from_str(address)
        .map_err(|e| format!("invalid address: {e}"))?
        .require_network(Network::Testnet4)
        .map_err(|e| format!("not a testnet4 address: {e}"))?;
    Ok((
        outpoint,
        bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(amount),
            script_pubkey: address.script_pubkey(),
        },
    ))
}
