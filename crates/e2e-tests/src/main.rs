//! CLI binary for managing a local Hashi development environment.
//!
//! This reuses the existing e2e-tests infrastructure (bitcoin node, Sui network,
//! Hashi validators) to provide a long-running localnet for manual testing.

use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use colored::Colorize;
use e2e_tests::TestNetworksBuilder;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

/// Manage a local Hashi development environment.
#[derive(Parser)]
#[command(
    name = "hashi-localnet",
    about = "Manage a local Hashi dev environment"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Shared options for localnet subcommands.
#[derive(Args)]
struct LocalnetOpts {
    /// Directory for localnet data
    #[clap(long, default_value = ".hashi/localnet")]
    data_dir: std::path::PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Start a local development environment (bitcoind + Sui + Hashi validators)
    Start {
        /// Number of Hashi validators to run
        #[clap(long, default_value = "4")]
        num_validators: usize,

        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Stop the running localnet
    Stop {
        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Show localnet process status
    Status {
        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Print localnet connection details
    Info {
        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Mine BTC blocks on the local regtest network
    Mine {
        /// Number of blocks to mine
        #[clap(long, default_value = "1")]
        blocks: u64,

        #[command(flatten)]
        opts: LocalnetOpts,
    },
}

/// Persisted state for a running localnet instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalnetState {
    pid: u32,
    sui_rpc_url: String,
    btc_rpc_url: String,
    btc_rpc_user: String,
    btc_rpc_password: String,
    package_id: String,
    hashi_object_id: String,
    num_validators: usize,
    data_dir: std::path::PathBuf,
}

impl LocalnetState {
    fn state_file_path(data_dir: &Path) -> std::path::PathBuf {
        data_dir.join("state.json")
    }

    fn load(data_dir: &Path) -> Result<Self> {
        let path = Self::state_file_path(data_dir);
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read state file: {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file: {}", path.display()))
    }

    fn save(&self, data_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(data_dir)?;
        let path = Self::state_file_path(data_dir);
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, contents)
            .with_context(|| format!("Failed to write state file: {}", path.display()))
    }

    fn is_alive(&self) -> bool {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(self.pid as i32), None).is_ok()
    }
}

fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

fn print_info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start {
            num_validators,
            opts,
        } => cmd_start(num_validators, &opts.data_dir).await,
        Commands::Stop { opts } => cmd_stop(&opts.data_dir),
        Commands::Status { opts } => cmd_status(&opts.data_dir),
        Commands::Info { opts } => cmd_info(&opts.data_dir),
        Commands::Mine { blocks, opts } => cmd_mine(blocks, &opts.data_dir),
    }
}

async fn cmd_start(num_validators: usize, data_dir: &Path) -> Result<()> {
    // Check for existing running instance
    if let Ok(state) = LocalnetState::load(data_dir) {
        if state.is_alive() {
            anyhow::bail!(
                "Localnet is already running (PID {}). Stop it first with `hashi-localnet stop`.",
                state.pid
            );
        }
        print_warning("Found stale state file, cleaning up...");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .with_target(false)
        .init();

    print_info(&format!(
        "Starting localnet with {} validators...",
        num_validators
    ));

    let test_networks = TestNetworksBuilder::new()
        .with_nodes(num_validators)
        .build()
        .await?;

    let sui_rpc_url = &test_networks.sui_network().rpc_url;
    let btc_rpc_url = test_networks.bitcoin_node().rpc_url();
    let ids = test_networks.hashi_network().ids();

    let state = LocalnetState {
        pid: std::process::id(),
        sui_rpc_url: sui_rpc_url.clone(),
        btc_rpc_url: btc_rpc_url.to_string(),
        btc_rpc_user: e2e_tests::bitcoin_node::RPC_USER.to_string(),
        btc_rpc_password: e2e_tests::bitcoin_node::RPC_PASSWORD.to_string(),
        package_id: ids.package_id.to_string(),
        hashi_object_id: ids.hashi_object_id.to_string(),
        num_validators,
        data_dir: data_dir.to_path_buf(),
    };
    state.save(data_dir)?;

    print_success("Localnet started successfully!");
    println!();
    print_connection_details(&state);

    print_info("Press Ctrl+C to stop the localnet.");

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;

    print_info("Shutting down...");
    // Cleanup happens via Drop on test_networks
    let _ = std::fs::remove_file(LocalnetState::state_file_path(data_dir));
    print_success("Localnet stopped.");

    Ok(())
}

fn cmd_stop(data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)?;

    if !state.is_alive() {
        print_warning("Localnet process is not running.");
        let _ = std::fs::remove_file(LocalnetState::state_file_path(data_dir));
        return Ok(());
    }

    print_info(&format!("Stopping localnet (PID {})...", state.pid));

    // Send SIGTERM
    let pid = nix::unistd::Pid::from_raw(state.pid as i32);
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)?;

    // Wait briefly for process to exit
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if nix::sys::signal::kill(pid, None).is_err() {
            break;
        }
    }

    let _ = std::fs::remove_file(LocalnetState::state_file_path(data_dir));
    print_success("Localnet stopped.");
    Ok(())
}

fn cmd_status(data_dir: &Path) -> Result<()> {
    let state = match LocalnetState::load(data_dir) {
        Ok(s) => s,
        Err(_) => {
            print_info("No localnet instance found.");
            return Ok(());
        }
    };

    if state.is_alive() {
        print_success(&format!(
            "Localnet is running (PID {}, {} validators)",
            state.pid, state.num_validators
        ));
    } else {
        print_warning("Localnet process is not running (stale state file).");
    }

    Ok(())
}

fn cmd_info(data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)
        .context("No localnet state found. Is the localnet running?")?;

    print_connection_details(&state);

    if !state.is_alive() {
        println!();
        print_warning("Note: the localnet process is not currently running.");
    }

    Ok(())
}

fn cmd_mine(blocks: u64, data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)
        .context("No localnet state found. Is the localnet running?")?;

    if !state.is_alive() {
        anyhow::bail!("Localnet process is not running.");
    }

    let client = bitcoincore_rpc::Client::new(
        &state.btc_rpc_url,
        bitcoincore_rpc::Auth::UserPass(state.btc_rpc_user, state.btc_rpc_password),
    )?;

    use bitcoincore_rpc::RpcApi;
    let address = client.get_new_address(None, None)?.assume_checked();
    let hashes = client.generate_to_address(blocks, &address)?;

    print_success(&format!(
        "Mined {} block(s). Latest: {}",
        hashes.len(),
        hashes.last().unwrap()
    ));

    Ok(())
}

fn print_connection_details(state: &LocalnetState) {
    println!("{}", "━".repeat(50));
    println!("{}", "  Localnet Connection Details".bold());
    println!("{}", "━".repeat(50));
    println!("  {} {}", "Sui RPC:".bold(), state.sui_rpc_url);
    println!("  {} {}", "BTC RPC:".bold(), state.btc_rpc_url);
    println!(
        "  {} {}:{}",
        "BTC RPC Auth:".bold(),
        state.btc_rpc_user,
        state.btc_rpc_password
    );
    println!("  {} {}", "Package ID:".bold(), state.package_id);
    println!("  {} {}", "Hashi Object:".bold(), state.hashi_object_id);
    println!("  {} {}", "Validators:".bold(), state.num_validators);
    println!("{}", "━".repeat(50));
}
