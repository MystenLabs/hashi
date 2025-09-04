//! Example binary that demonstrates running a Bitcoin P2P pool on testnet4.
//! It uses hardcoded known-working testnet4 seed nodes for peer discovery.
//!
//! # Usage Examples
//!
//! Monitor a single testnet4 address:
//! ```bash
//! cargo run --example testnet_pool -- --addresses tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx
//! ```
//!
//! Monitor multiple addresses with verbose logging:
//! ```bash
//! cargo run --example testnet_pool -- \
//!     --addresses tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx \
//!     --addresses tb1qkqkt3ra8d44lt90t9thgy3lgucsjrtywwgq8yp \
//!     --verbose
//! ```

use std::net::SocketAddr;

use bitcoin::Address;
use bitcoin::Network;
use clap::Parser;
use hashi_btc::config::PoolConfig;
use hashi_btc::pool::Pool;
use kyoto::TrustedPeer;
use tracing::error;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Run a Bitcoin P2P pool monitoring specific addresses on testnet4
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Bitcoin addresses to monitor (can specify multiple)
    #[arg(short, long, value_name = "ADDRESS", required = true)]
    addresses: Vec<String>,

    /// Number of confirmations required for a transaction to be considered canonical
    #[arg(short = 'c', long, default_value = "6")]
    confirmations: u32,

    /// Starting block height for synchronization (defaults to recent testnet4 height)
    #[arg(short = 's', long, default_value = "50000")]
    start_height: u32,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Set up logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    info!("Starting BTC testnet4 pool");
    info!("Monitoring addresses: {:?}", args.addresses);

    // Parse Bitcoin addresses into script pubkeys
    let mut monitored_scripts = Vec::new();
    for addr_str in &args.addresses {
        match Address::from_str(addr_str) {
            Ok(addr) => {
                // Properly check that the address is valid for testnet4
                // Note: Testnet4 uses the same address prefixes as Testnet3
                match addr.clone().require_network(Network::Testnet4) {
                    Ok(checked_addr) => {
                        monitored_scripts.push(checked_addr.script_pubkey());
                        info!("Added address: {}", addr_str);
                    }
                    Err(_) => {
                        // Try Testnet (Testnet3) network as fallback since addresses are compatible
                        match addr.require_network(Network::Testnet) {
                            Ok(checked_addr) => {
                                monitored_scripts.push(checked_addr.script_pubkey());
                                info!("Added address (testnet3 format): {}", addr_str);
                            }
                            Err(_) => {
                                error!("Address '{}' is not valid for testnet4", addr_str);
                                return Err(format!(
                                    "Address '{}' is not valid for testnet4",
                                    addr_str
                                )
                                .into());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Invalid Bitcoin address '{}': {}", addr_str, e);
                return Err(format!("Invalid Bitcoin address '{}': {}", addr_str, e).into());
            }
        }
    }

    if monitored_scripts.is_empty() {
        error!("No valid addresses to monitor");
        return Err("No valid addresses to monitor".into());
    }

    // Known working testnet4 peers (using socket addresses)
    let testnet_peers = vec![
        // seed.testnet4.bitcoin.sprovoost.nl:48333
        TrustedPeer::from("37.27.3.75:48333".parse::<SocketAddr>()?),
        // seed.testnet4.wiz.biz:48333
        TrustedPeer::from("5.9.138.70:48333".parse::<SocketAddr>()?),
        // Additional hardcoded testnet4 nodes (if available)
        // These IPs are examples and may change
        TrustedPeer::from("23.137.57.100:48333".parse::<SocketAddr>()?),
        TrustedPeer::from("91.83.65.73:48333".parse::<SocketAddr>()?),
    ];

    let config = PoolConfig {
        network: Network::Testnet4,
        confirmation_threshold: args.confirmations,
        trusted_peers: testnet_peers,
        start_height: args.start_height,
        monitored_scripts,
    };

    info!("Pool configuration:");
    info!("  Network: {:?}", config.network);
    info!(
        "  Confirmations required: {}",
        config.confirmation_threshold
    );
    info!("  Starting height: {}", config.start_height);
    info!("  Monitored scripts: {}", config.monitored_scripts.len());
    info!("  Initial peers: {}", config.trusted_peers.len());
    info!("  Peer addresses:");
    for peer in &config.trusted_peers {
        info!("    - {:?}:{:?}", peer.address(), peer.port());
    }

    // Create and start the pool
    let pool = Pool::new(config)?;

    info!("Starting pool...");
    let _pool_client = pool.run()?;

    // The pool is now running in background tasks
    // In a real application, you would use pool_client to interact with the pool

    info!("Pool is running. Press Ctrl-C to stop.");

    // Wait for ctrl-c
    tokio::signal::ctrl_c().await?;
    info!("Received shutdown signal");

    // In a real application, you would properly shutdown the pool here
    // For now, the tasks will be cancelled when the program exits

    Ok(())
}

// Helper function for parsing addresses
use std::str::FromStr;
