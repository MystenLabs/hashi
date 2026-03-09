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

#[derive(Subcommand)]
enum KeygenCommands {
    /// Generate a Sui Ed25519 keypair using `sui keytool`
    Sui {
        /// Output directory for the keypair file
        #[clap(long, default_value = ".hashi/keys")]
        output: std::path::PathBuf,
    },

    /// Generate a Bitcoin secp256k1 keypair
    Btc {
        /// Output path for the WIF key file
        #[clap(long, default_value = ".hashi/keys/btc.wif")]
        output: std::path::PathBuf,

        /// Bitcoin network for WIF encoding
        #[clap(long, default_value = "regtest")]
        network: String,
    },
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

    /// Generate cryptographic keypairs
    Keygen {
        #[command(subcommand)]
        action: KeygenCommands,
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
        Commands::Stop { opts } => cmd_stop(&opts.data_dir).await,
        Commands::Status { opts } => cmd_status(&opts.data_dir),
        Commands::Info { opts } => cmd_info(&opts.data_dir),
        Commands::Mine { blocks, opts } => cmd_mine(blocks, &opts.data_dir),
        Commands::Keygen { action } => cmd_keygen(action),
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

    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_target(false)
            .init();
    }

    use std::io::Write;
    print!(
        "{} Starting localnet with {} validators...",
        "ℹ".blue().bold(),
        num_validators
    );
    std::io::stdout().flush().ok();

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

    // Overwrite the "ℹ Starting..." line with a checkmark
    print!("\r{}", " ".repeat(60));
    println!(
        "\r{} Localnet started with {} validators",
        "✓".green().bold(),
        num_validators
    );
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

async fn cmd_stop(data_dir: &Path) -> Result<()> {
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
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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

fn cmd_keygen(action: KeygenCommands) -> Result<()> {
    match action {
        KeygenCommands::Sui { output } => {
            print_info("Generating Sui Ed25519 keypair via `sui keytool`...");

            std::fs::create_dir_all(&output).with_context(|| {
                format!("Failed to create output directory {}", output.display())
            })?;

            let cmd_output = std::process::Command::new("sui")
                .args(["keytool", "generate", "ed25519", "--json"])
                .current_dir(&output)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output()
                .context(
                    "Failed to run `sui keytool`. Is the `sui` binary installed and in PATH?",
                )?;

            if !cmd_output.status.success() {
                let stderr = String::from_utf8_lossy(&cmd_output.stderr);
                anyhow::bail!("`sui keytool generate` failed: {}", stderr);
            }

            let stdout = String::from_utf8_lossy(&cmd_output.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let address = json
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                print_success(&format!("Sui keypair generated for address {}", address));
                if let Some(path) = json.get("filePath").and_then(|v| v.as_str()) {
                    print_info(&format!("Key file: {}", output.join(path).display()));
                }
            } else {
                print_success("Sui keypair generated.");
            }

            Ok(())
        }
        KeygenCommands::Btc { output, network } => {
            use bitcoin::secp256k1::Secp256k1;
            use bitcoin::secp256k1::rand::thread_rng;

            let btc_network = match network.as_str() {
                "mainnet" => bitcoin::Network::Bitcoin,
                "testnet" => bitcoin::Network::Testnet,
                "regtest" => bitcoin::Network::Regtest,
                other => anyhow::bail!(
                    "Unknown Bitcoin network: {}. Use mainnet, testnet, or regtest",
                    other
                ),
            };

            print_info(&format!(
                "Generating Bitcoin secp256k1 keypair for {}...",
                network
            ));

            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut thread_rng());
            let private_key = bitcoin::PrivateKey::new(secret_key, btc_network);

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create directory {}", parent.display()))?;
            }

            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&output)
                    .with_context(|| format!("Failed to create key file {}", output.display()))?;
                file.write_all(private_key.to_wif().as_bytes())
                    .with_context(|| format!("Failed to write key to {}", output.display()))?;
            }

            let address =
                bitcoin::Address::p2wpkh(&bitcoin::CompressedPublicKey(public_key), btc_network);

            print_success(&format!(
                "Private key (WIF) written to {}",
                output.display()
            ));
            print_info(&format!("Public key: {}", public_key));
            print_info(&format!("Address (P2WPKH): {}", address));

            Ok(())
        }
    }
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
