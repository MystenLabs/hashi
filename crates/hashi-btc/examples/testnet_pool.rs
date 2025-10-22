//! Example binary that demonstrates running a Bitcoin monitor on testnet4.
//! It uses hardcoded known-working testnet4 seed nodes for peer discovery.
//!
//! # Usage Examples
//!
//! Monitor testnet4:
//! ```bash
//! cargo run --example testnet_pool
//! ```
use std::net::SocketAddr;

use bitcoin::Network;
use clap::Parser;
use hashi_btc::config::MontiorConfig;
use hashi_btc::monitor::Monitor;
use kyoto::TrustedPeer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

/// Run a Bitcoin P2P pool monitoring specific addresses on testnet4
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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

    info!("Starting BTC testnet4 monitor");

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

    let config = MontiorConfig {
        network: Network::Testnet4,
        confirmation_threshold: args.confirmations,
        trusted_peers: testnet_peers,
        start_height: args.start_height,
    };

    info!("Pool configuration:");
    info!("  Network: {:?}", config.network);
    info!(
        "  Confirmations required: {}",
        config.confirmation_threshold
    );
    info!("  Starting height: {}", config.start_height);
    info!("  Initial peers: {}", config.trusted_peers.len());
    info!("  Peer addresses:");
    for peer in &config.trusted_peers {
        info!("    - {:?}:{:?}", peer.address(), peer.port());
    }

    // Create and start the pool
    let pool = Monitor::new(config)?;

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
