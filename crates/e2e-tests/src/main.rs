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
    /// Generate a Sui Ed25519 keypair (PEM format)
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

        /// Enable verbose tracing output
        #[clap(long, short)]
        verbose: bool,

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

    /// Fund a Sui address with SUI tokens from the localnet genesis account
    FaucetSui {
        /// Sui address to fund
        address: String,

        /// Amount of SUI to send (in MIST, default 1 SUI = 1_000_000_000 MIST)
        #[clap(long, default_value = "1000000000")]
        amount: u64,

        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Fund a Bitcoin address with regtest BTC (mines blocks to the address)
    FaucetBtc {
        /// Bitcoin address to fund
        address: String,

        /// Number of blocks to mine to the address (each block rewards ~50 BTC)
        #[clap(long, default_value = "1")]
        blocks: u64,

        #[command(flatten)]
        opts: LocalnetOpts,
    },

    /// Execute a full deposit flow: send BTC, mine blocks, and submit deposit request
    Deposit {
        /// Amount of BTC to deposit (in satoshis)
        #[clap(long)]
        amount: u64,

        /// Sui address that will receive hBTC (defaults to the funded keypair address)
        #[clap(long)]
        recipient: Option<String>,

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
    /// Path to a PEM-encoded funded Sui keypair (from genesis)
    #[serde(skip_serializing_if = "Option::is_none")]
    funded_sui_keypair_path: Option<String>,
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
            verbose,
            opts,
        } => cmd_start(num_validators, verbose, &opts.data_dir).await,
        Commands::Stop { opts } => cmd_stop(&opts.data_dir).await,
        Commands::Status { opts } => cmd_status(&opts.data_dir),
        Commands::Info { opts } => cmd_info(&opts.data_dir),
        Commands::Mine { blocks, opts } => cmd_mine(blocks, &opts.data_dir),
        Commands::Keygen { action } => cmd_keygen(action),
        Commands::FaucetSui {
            address,
            amount,
            opts,
        } => cmd_faucet_sui(&address, amount, &opts.data_dir).await,
        Commands::FaucetBtc {
            address,
            blocks,
            opts,
        } => cmd_faucet_btc(&address, blocks, &opts.data_dir),
        Commands::Deposit {
            amount,
            recipient,
            opts,
        } => cmd_deposit(amount, recipient.as_deref(), &opts.data_dir).await,
    }
}

async fn cmd_start(num_validators: usize, verbose: bool, data_dir: &Path) -> Result<()> {
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

    let default_level = if verbose {
        tracing::level_filters::LevelFilter::INFO
    } else {
        tracing::level_filters::LevelFilter::OFF
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(default_level.into())
                .from_env_lossy(),
        )
        .with_target(false)
        .init();

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

    // Write the funded genesis key to disk so faucet/CLI commands can use it
    let funded_key_path = data_dir.join("funded_keypair.pem");
    let funded_key = test_networks
        .sui_network()
        .user_keys
        .first()
        .context("No funded user keys in localnet genesis")?;
    let pem = funded_key
        .to_pem()
        .context("Failed to serialize funded key as PEM")?;
    std::fs::create_dir_all(data_dir)?;
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&funded_key_path)
            .with_context(|| {
                format!(
                    "Failed to write funded key to {}",
                    funded_key_path.display()
                )
            })?;
        file.write_all(pem.as_bytes())?;
    }

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
        funded_sui_keypair_path: Some(funded_key_path.to_string_lossy().into_owned()),
    };
    state.save(data_dir)?;

    // Write a CLI config file so `hashi` CLI can auto-discover the localnet
    write_cli_config(data_dir, &state)?;

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
    let _ = std::fs::remove_file(cli_config_path(data_dir));
    print_success("Localnet stopped.");

    Ok(())
}

async fn cmd_stop(data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)?;

    if !state.is_alive() {
        print_warning("Localnet process is not running.");
        let _ = std::fs::remove_file(LocalnetState::state_file_path(data_dir));
        let _ = std::fs::remove_file(cli_config_path(data_dir));
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
    let _ = std::fs::remove_file(cli_config_path(data_dir));
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
            print_info("Generating Sui Ed25519 keypair...");

            std::fs::create_dir_all(&output).with_context(|| {
                format!("Failed to create output directory {}", output.display())
            })?;

            let seed: [u8; 32] = rand::random();
            let private_key = sui_crypto::ed25519::Ed25519PrivateKey::new(seed);
            let address = private_key.public_key().derive_address();
            let pem = private_key
                .to_pem()
                .context("Failed to serialize key as PEM")?;

            let key_file = output.join(format!("{}.pem", address));
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&key_file)
                    .with_context(|| format!("Failed to create key file {}", key_file.display()))?;
                file.write_all(pem.as_bytes())?;
            }

            print_success(&format!("Sui keypair generated for address {}", address));
            print_info(&format!("Key file: {}", key_file.display()));

            Ok(())
        }
        KeygenCommands::Btc { output, network } => {
            use bitcoin::secp256k1::Secp256k1;
            use bitcoin::secp256k1::rand::thread_rng;

            let btc_network = match network.as_str() {
                "mainnet" => bitcoin::Network::Bitcoin,
                "testnet4" => bitcoin::Network::Testnet4,
                "regtest" => bitcoin::Network::Regtest,
                other => anyhow::bail!(
                    "Unknown Bitcoin network: {}. Use mainnet, testnet4, or regtest",
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

async fn cmd_faucet_sui(address: &str, amount: u64, data_dir: &Path) -> Result<()> {
    use std::str::FromStr;
    use sui_crypto::SuiSigner;
    use sui_rpc::field::FieldMask;
    use sui_rpc::field::FieldMaskUtil;
    use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
    use sui_sdk_types::GasPayment;
    use sui_sdk_types::Input;
    use sui_sdk_types::ProgrammableTransaction;
    use sui_sdk_types::StructTag;
    use sui_sdk_types::Transaction;
    use sui_sdk_types::TransactionExpiration;
    use sui_sdk_types::TransactionKind;
    use sui_sdk_types::TransferObjects;
    use sui_sdk_types::bcs::ToBcs;

    let state = LocalnetState::load(data_dir)
        .context("No localnet state found. Is the localnet running?")?;

    if !state.is_alive() {
        anyhow::bail!("Localnet process is not running.");
    }

    let keypair_path = state
        .funded_sui_keypair_path
        .as_ref()
        .context("No funded keypair path in localnet state. Restart the localnet.")?;

    let funded_key =
        hashi::config::load_ed25519_private_key_from_path(std::path::Path::new(keypair_path))
            .context("Failed to load funded keypair")?;
    let sender = funded_key.public_key().derive_address();

    let recipient = sui_sdk_types::Address::from_str(address).context("Invalid Sui address")?;

    print_info(&format!("Sending {} MIST to {}...", amount, address));

    let mut client = sui_rpc::Client::new(&state.sui_rpc_url)?;
    let price = client.get_reference_gas_price().await?;
    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), amount + 50_000_000, &[])
        .await?;

    // Build: split amount from gas coin, transfer to recipient
    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Pure(recipient.to_bcs().unwrap()),
            Input::Pure(amount.to_bcs().unwrap()),
        ],
        commands: vec![
            sui_sdk_types::Command::SplitCoins(sui_sdk_types::SplitCoins {
                coin: sui_sdk_types::Argument::Gas,
                amounts: vec![sui_sdk_types::Argument::Input(1)],
            }),
            sui_sdk_types::Command::TransferObjects(TransferObjects {
                objects: vec![sui_sdk_types::Argument::NestedResult(0, 0)],
                address: sui_sdk_types::Argument::Input(0),
            }),
        ],
    };

    let tx = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: gas_objects
                .iter()
                .map(|o| (&o.object_reference()).try_into())
                .collect::<Result<_, _>>()?,
            owner: sender,
            price,
            budget: 50_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = funded_key.sign_transaction(&tx)?;

    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(tx.into())
                .with_signatures(vec![signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(10),
        )
        .await?
        .into_inner();

    if response.transaction().effects().status().success() {
        print_success(&format!("Sent {} MIST to {}", amount, address));
    } else {
        anyhow::bail!("Transaction failed");
    }

    Ok(())
}

fn cmd_faucet_btc(address: &str, blocks: u64, data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)
        .context("No localnet state found. Is the localnet running?")?;

    if !state.is_alive() {
        anyhow::bail!("Localnet process is not running.");
    }

    let btc_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        address.parse().context("Invalid Bitcoin address")?;
    let btc_addr = btc_addr
        .require_network(bitcoin::Network::Regtest)
        .context("Faucet BTC address must be a regtest address")?;

    let client = bitcoincore_rpc::Client::new(
        &state.btc_rpc_url,
        bitcoincore_rpc::Auth::UserPass(state.btc_rpc_user, state.btc_rpc_password),
    )?;

    use bitcoincore_rpc::RpcApi;
    let hashes = client.generate_to_address(blocks, &btc_addr)?;

    print_success(&format!(
        "Mined {} block(s) to {}. Each block rewards ~50 BTC.",
        hashes.len(),
        address
    ));

    Ok(())
}

async fn cmd_deposit(amount: u64, recipient: Option<&str>, data_dir: &Path) -> Result<()> {
    let state = LocalnetState::load(data_dir)
        .context("No localnet state found. Is the localnet running?")?;

    if !state.is_alive() {
        anyhow::bail!("Localnet process is not running.");
    }

    let package_id: sui_sdk_types::Address = state
        .package_id
        .parse()
        .context("Invalid package ID in state")?;
    let hashi_object_id: sui_sdk_types::Address = state
        .hashi_object_id
        .parse()
        .context("Invalid hashi object ID in state")?;
    let hashi_ids = hashi::config::HashiIds {
        package_id,
        hashi_object_id,
    };

    // Load the funded keypair for signing
    let keypair_path = state
        .funded_sui_keypair_path
        .as_ref()
        .context("No funded keypair path in localnet state. Restart the localnet.")?;
    let signer =
        hashi::config::load_ed25519_private_key_from_path(std::path::Path::new(keypair_path))
            .context("Failed to load funded keypair")?;

    // Resolve recipient — default to signer address
    let recipient_addr = match recipient {
        Some(r) => r
            .parse::<sui_sdk_types::Address>()
            .context("Invalid recipient Sui address")?,
        None => {
            let addr = signer.public_key().derive_address();
            print_info(&format!(
                "No --recipient specified, defaulting to signer address {}",
                addr
            ));
            addr
        }
    };

    // Fetch MPC public key from on-chain state
    let (onchain_state, _service) =
        hashi::onchain::OnchainState::new(&state.sui_rpc_url, hashi_ids, None, None)
            .await
            .context("Failed to read on-chain state")?;

    let mpc_pubkey = onchain_state.mpc_public_key();

    if mpc_pubkey.is_empty() {
        anyhow::bail!("MPC public key not available on-chain. Has the committee completed DKG?");
    }

    // Derive deposit address
    let btc_network = bitcoin::Network::Regtest;
    let deposit_address = hashi::cli::commands::deposit::cli_derive_deposit_address(
        &mpc_pubkey,
        Some(&recipient_addr),
        btc_network,
    )?;

    // Step 1: Send BTC via wallet RPC
    print_info(&format!(
        "Sending {} sats to deposit address {}",
        amount, deposit_address
    ));

    // Use /wallet/test for Bitcoin Core v28+ regtest
    let wallet_url = format!("{}/wallet/test", state.btc_rpc_url);
    let btc_rpc = bitcoincore_rpc::Client::new(
        &wallet_url,
        bitcoincore_rpc::Auth::UserPass(state.btc_rpc_user, state.btc_rpc_password),
    )?;

    use bitcoincore_rpc::RpcApi;
    let txid = btc_rpc.send_to_address(
        &deposit_address,
        bitcoin::Amount::from_sat(amount),
        None,
        None,
        None,
        None,
        None,
        None,
    )?;

    // Find the vout
    let tx = btc_rpc.get_raw_transaction(&txid, None)?;
    let vout = tx
        .output
        .iter()
        .position(|output| {
            output.value == bitcoin::Amount::from_sat(amount)
                && output.script_pubkey == deposit_address.script_pubkey()
        })
        .context("Could not find matching output in transaction")? as u32;

    print_success(&format!("BTC sent! txid: {} vout: {}", txid, vout));

    // Step 2: Mine blocks
    print_info("Mining 10 blocks...");
    let mine_addr = btc_rpc.get_new_address(None, None)?.assume_checked();
    btc_rpc.generate_to_address(10, &mine_addr)?;
    print_success("Mined 10 blocks");

    // Step 3: Submit deposit request on Sui
    print_info("Submitting deposit request on Sui...");
    use bitcoin::hashes::Hash;
    let txid_address = sui_sdk_types::Address::new(txid.to_byte_array());

    let client = sui_rpc::Client::new(&state.sui_rpc_url)?;
    let mut executor = hashi::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    let request_id = executor
        .execute_create_deposit_request(txid_address, vout, amount, Some(recipient_addr))
        .await?;

    print_success(&format!("Deposit request created: {}", request_id));

    Ok(())
}

/// Path to the CLI config file written by localnet for `hashi` CLI auto-discovery.
fn cli_config_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("hashi-cli.toml")
}

/// Write a `hashi-cli.toml` config file that the main `hashi` CLI can read.
fn write_cli_config(data_dir: &Path, state: &LocalnetState) -> Result<()> {
    let config = hashi::cli::config::CliConfig {
        sui_rpc_url: state.sui_rpc_url.clone(),
        package_id: state.package_id.parse().ok(),
        hashi_object_id: state.hashi_object_id.parse().ok(),
        keypair_path: state
            .funded_sui_keypair_path
            .as_ref()
            .map(std::path::PathBuf::from),
        gas_coin: None,
        bitcoin: Some(hashi::cli::config::BitcoinConfig {
            rpc_url: Some(state.btc_rpc_url.clone()),
            rpc_user: Some(state.btc_rpc_user.clone()),
            rpc_password: Some(state.btc_rpc_password.clone()),
            network: Some("regtest".to_string()),
            private_key_path: None,
        }),
    };

    config
        .save_to_file(&cli_config_path(data_dir))
        .context("Failed to write CLI config file")?;

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
    println!(
        "  {} {}",
        "CLI Config:".bold(),
        cli_config_path(&state.data_dir).display()
    );
    println!("{}", "━".repeat(50));
}
