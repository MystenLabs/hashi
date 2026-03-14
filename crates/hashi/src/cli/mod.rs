//! CLI module for the Hashi bridge
//!
//! Provides governance, committee, and configuration management commands.

use clap::Args;
use clap::Subcommand;
use clap::builder::styling::AnsiColor;
use clap::builder::styling::Effects;
use clap::builder::styling::Styles;
use colored::Colorize;

pub mod client;
pub mod commands;
pub mod config;
pub mod types;

pub const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

/// CLI-specific global options, flattened into each CLI subcommand.
#[derive(Args)]
pub struct CliGlobalOpts {
    /// Path to the CLI configuration file
    #[clap(long, short, env = "HASHI_CLI_CONFIG")]
    pub config: Option<std::path::PathBuf>,

    /// Sui RPC URL (overrides config file)
    #[clap(long, env = "SUI_RPC_URL")]
    pub sui_rpc_url: Option<String>,

    /// Hashi package ID (overrides config file)
    #[clap(long, env = "HASHI_PACKAGE_ID")]
    pub package_id: Option<String>,

    /// Hashi shared object ID (overrides config file)
    #[clap(long, env = "HASHI_OBJECT_ID")]
    pub hashi_object_id: Option<String>,

    /// Path to the keypair file for signing transactions
    #[clap(long, short = 'k', env = "HASHI_KEYPAIR")]
    pub keypair: Option<std::path::PathBuf>,

    /// Bitcoin RPC URL (overrides config file)
    #[clap(long, env = "BTC_RPC_URL")]
    pub btc_rpc_url: Option<String>,

    /// Bitcoin RPC username (overrides config file)
    #[clap(long, env = "BTC_RPC_USER")]
    pub btc_rpc_user: Option<String>,

    /// Bitcoin RPC password (overrides config file)
    #[clap(long, env = "BTC_RPC_PASSWORD")]
    pub btc_rpc_password: Option<String>,

    /// Bitcoin network: regtest, testnet4, or mainnet (overrides config file)
    #[clap(long, env = "BTC_NETWORK")]
    pub btc_network: Option<String>,

    /// Path to Bitcoin private key file in WIF format (overrides config file)
    #[clap(long, env = "BTC_PRIVATE_KEY")]
    pub btc_private_key: Option<std::path::PathBuf>,

    /// Enable verbose output
    #[clap(long, short)]
    pub verbose: bool,

    /// Skip all confirmation prompts
    #[clap(long, short = 'y')]
    pub yes: bool,

    /// Gas budget for transactions (in MIST). If not set, estimates via dry-run.
    #[clap(long, env = "HASHI_GAS_BUDGET")]
    pub gas_budget: Option<u64>,

    /// Simulate the transaction without executing (dry-run)
    #[clap(long)]
    pub dry_run: bool,
}

#[derive(Subcommand)]
pub enum ProposalCommands {
    /// List all active proposals
    List {
        /// Filter by proposal type (upgrade, update-deposit-fee, etc.)
        #[clap(long, short = 't')]
        r#type: Option<String>,

        /// Show detailed information
        #[clap(long, short)]
        detailed: bool,
    },

    /// View details of a specific proposal
    View {
        /// The proposal object ID
        proposal_id: String,
    },

    /// Vote on a proposal
    Vote {
        /// The proposal object ID to vote on
        proposal_id: String,
    },

    /// Remove your vote from a proposal
    RemoveVote {
        /// The proposal object ID
        proposal_id: String,
    },

    /// Create a new proposal
    Create {
        #[clap(subcommand)]
        proposal: CreateProposalCommands,
    },
}

#[derive(Subcommand)]
pub enum CreateProposalCommands {
    /// Propose a package upgrade
    Upgrade {
        /// The digest of the new package (hex encoded)
        digest: String,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose updating a configuration value
    ///
    /// Known config keys and their expected value types:
    ///   deposit_fee (u64), withdrawal_fee_btc (u64), max_fee_rate (u64),
    ///   max_inputs (u64), bitcoin_confirmation_threshold (u64),
    ///   withdrawal_cancellation_cooldown_ms (u64), paused (bool)
    UpdateConfig {
        /// The config key to update
        key: String,

        /// The new value. Prefix with the type: u64:123, bool:true
        value: String,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose enabling a package version
    EnableVersion {
        /// The version to enable
        version: u64,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose disabling a package version
    DisableVersion {
        /// The version to disable
        version: u64,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },
}

/// Shared metadata arguments for proposal creation
///
/// Metadata provides additional context about the proposal (e.g., description, rationale).
/// This information is stored on-chain and displayed when viewing proposals.
#[derive(Args)]
pub struct MetadataArgs {
    /// Metadata key-value pairs (format: key=value). Can be specified multiple times.
    ///
    /// Common keys: description, rationale, link
    ///
    /// Example: -m description="Upgrade to v2" -m link="https://..."
    #[clap(long, short, value_name = "KEY=VALUE")]
    pub metadata: Vec<String>,
}

#[derive(Subcommand)]
pub enum CommitteeCommands {
    /// List current committee members
    List {
        /// Show for a specific epoch (defaults to current)
        #[clap(long)]
        epoch: Option<u64>,
    },

    /// View details of a specific committee member
    View {
        /// The validator address
        address: String,
    },

    /// Show current epoch information
    Epoch,
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Generate a configuration file template
    Template {
        /// Output path for the config file
        #[clap(short, long, default_value = "hashi-cli.toml")]
        output: std::path::PathBuf,
    },

    /// Show the current effective configuration
    Show,

    /// View on-chain configuration values
    OnChain,
}

#[derive(Subcommand)]
pub enum DepositCommands {
    /// Generate a Taproot deposit address from the on-chain MPC public key
    GenerateAddress {
        /// Sui address that will receive hBTC (used as derivation path).
        /// Use empty string for the change address (no recipient).
        #[clap(long)]
        recipient: String,
    },

    /// Submit a deposit request on Sui with existing UTXO info
    Request {
        /// Bitcoin transaction ID containing the deposit
        #[clap(long)]
        txid: String,

        /// Output index in the transaction
        #[clap(long)]
        vout: u32,

        /// Amount deposited (in satoshis)
        #[clap(long)]
        amount: u64,

        /// Sui address that will receive hBTC
        #[clap(long)]
        recipient: Option<String>,
    },

    /// Show the status of a deposit request
    Status {
        /// The deposit request object ID
        request_id: String,
    },

    /// List deposit requests
    List,
}

#[derive(Subcommand)]
pub enum WithdrawCommands {
    /// Submit a withdrawal request on Sui
    Request {
        /// Amount to withdraw (in satoshis)
        #[clap(long)]
        amount: u64,

        /// Bitcoin address to receive the withdrawal
        #[clap(long)]
        btc_address: String,
    },

    /// Cancel a pending withdrawal request
    Cancel {
        /// The withdrawal request object ID
        request_id: String,
    },

    /// Show the status of a withdrawal request
    Status {
        /// The withdrawal request object ID
        request_id: String,
    },

    /// List withdrawal requests
    List,
}

/// Transaction options passed to commands
pub struct TxOptions {
    /// Gas budget - None means estimate via dry-run
    pub gas_budget: Option<u64>,
    pub skip_confirm: bool,
    /// If true, simulate the transaction without executing
    pub dry_run: bool,
}

impl TxOptions {
    /// Get gas budget, using the provided estimate if not explicitly set
    pub fn gas_budget_or(&self, estimate: u64) -> u64 {
        self.gas_budget.unwrap_or(estimate)
    }

    /// Get gas budget with a safety margin (1.2x the estimate)
    pub fn gas_budget_or_with_margin(&self, estimate: u64) -> u64 {
        self.gas_budget.unwrap_or_else(|| {
            // Add 20% safety margin to estimates
            estimate.saturating_mul(120).saturating_div(100)
        })
    }
}

/// Options for the `publish` subcommand.
///
/// Unlike other CLI commands this does *not* use [`CliGlobalOpts`] because
/// `package_id` and `hashi_object_id` do not exist yet – they are the
/// *output* of the publish workflow.
#[derive(Args)]
pub struct PublishOpts {
    /// Sui RPC endpoint URL
    #[clap(
        long,
        env = "SUI_RPC_URL",
        default_value = "https://fullnode.mainnet.sui.io:443"
    )]
    pub sui_rpc_url: String,

    /// Path to the Move package directory
    #[clap(long, short = 'p', default_value = "packages/hashi")]
    pub package_path: std::path::PathBuf,

    /// Path to the `sui` CLI binary
    #[clap(long, env = "SUI_BINARY", default_value = "sui")]
    pub sui_binary: std::path::PathBuf,

    /// Path to the keypair file for signing transactions
    #[clap(long, short = 'k', env = "HASHI_KEYPAIR")]
    pub keypair: std::path::PathBuf,

    /// Network environment for the Move build (e.g. `testnet`, `mainnet`)
    #[clap(long, short = 'e')]
    pub environment: Option<String>,

    /// Optional path to a sui `client.yaml` for dependency resolution
    #[clap(long)]
    pub sui_client_config: Option<std::path::PathBuf>,

    /// Bitcoin chain ID (genesis block hash) to store on-chain
    #[clap(long)]
    pub bitcoin_chain_id: String,

    /// Enable verbose output
    #[clap(long, short)]
    pub verbose: bool,

    /// Skip confirmation prompts
    #[clap(long, short = 'y')]
    pub yes: bool,
}

/// Options for the `register` subcommand.
///
/// Unlike other CLI commands this uses a validator config file (the same one
/// used by `hashi server`) rather than [`CliGlobalOpts`], because registration
/// requires fields like the protocol key and encryption key that only live in
/// the validator config.
#[derive(Args)]
pub struct RegisterOpts {
    /// Path to the validator config file (same as used by `hashi server`)
    #[clap(long, short)]
    pub config: std::path::PathBuf,

    /// Sui RPC URL (overrides config file)
    #[clap(long, env = "SUI_RPC_URL")]
    pub sui_rpc_url: Option<String>,

    /// Optional operator address to set during registration
    #[clap(long)]
    pub operator_address: Option<String>,

    /// Print the unsigned transaction as base64 instead of executing it.
    /// Useful for signing with a hardware wallet. No private key is required.
    #[clap(long)]
    pub print_only: bool,

    /// Enable verbose output
    #[clap(long, short)]
    pub verbose: bool,

    /// Skip confirmation prompts
    #[clap(long, short = 'y')]
    pub yes: bool,
}

/// CLI command variants (without Server)
pub enum CliCommand {
    Proposal { action: ProposalCommands },
    Committee { action: CommitteeCommands },
    Config { action: ConfigCommands },
    Deposit { action: DepositCommands },
    Withdraw { action: WithdrawCommands },
    Balance { address: String },
}

/// Run a CLI command
pub async fn run(opts: CliGlobalOpts, command: CliCommand) -> anyhow::Result<()> {
    crate::init_crypto_provider();
    init_tracing(opts.verbose);

    let btc_overrides = config::BitcoinOverrides {
        rpc_url: opts.btc_rpc_url,
        rpc_user: opts.btc_rpc_user,
        rpc_password: opts.btc_rpc_password,
        network: opts.btc_network,
        private_key: opts.btc_private_key,
    };

    let config = config::CliConfig::load(
        opts.config.as_deref(),
        opts.sui_rpc_url,
        opts.package_id,
        opts.hashi_object_id,
        opts.keypair,
        btc_overrides,
    )?;

    let tx_opts = TxOptions {
        gas_budget: opts.gas_budget,
        skip_confirm: opts.yes,
        dry_run: opts.dry_run,
    };

    match command {
        CliCommand::Proposal { action } => match action {
            ProposalCommands::List { r#type, detailed } => {
                commands::proposal::list_proposals(&config, r#type, detailed).await?;
            }
            ProposalCommands::View { proposal_id } => {
                commands::proposal::view_proposal(&config, &proposal_id).await?;
            }
            ProposalCommands::Vote { proposal_id } => {
                commands::proposal::vote(&config, &proposal_id, &tx_opts).await?;
            }
            ProposalCommands::RemoveVote { proposal_id } => {
                commands::proposal::remove_vote(&config, &proposal_id, &tx_opts).await?;
            }
            ProposalCommands::Create { proposal } => match proposal {
                CreateProposalCommands::Upgrade { digest, metadata } => {
                    commands::proposal::create_upgrade_proposal(
                        &config,
                        &digest,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::UpdateConfig {
                    key,
                    value,
                    metadata,
                } => {
                    commands::proposal::create_update_config_proposal(
                        &config,
                        &key,
                        &value,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::EnableVersion { version, metadata } => {
                    commands::proposal::create_enable_version_proposal(
                        &config,
                        version,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::DisableVersion { version, metadata } => {
                    commands::proposal::create_disable_version_proposal(
                        &config,
                        version,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
            },
        },
        CliCommand::Committee { action } => match action {
            CommitteeCommands::List { epoch } => {
                commands::committee::list_members(&config, epoch).await?;
            }
            CommitteeCommands::View { address } => {
                commands::committee::view_member(&config, &address).await?;
            }
            CommitteeCommands::Epoch => {
                commands::committee::show_epoch(&config).await?;
            }
        },
        CliCommand::Config { action } => match action {
            ConfigCommands::Template { output } => {
                commands::config::generate_template(&output)?;
            }
            ConfigCommands::Show => {
                commands::config::show_config(&config)?;
            }
            ConfigCommands::OnChain => {
                commands::config::show_onchain_config(&config).await?;
            }
        },
        CliCommand::Deposit { action } => {
            commands::deposit::run(action, &config, &tx_opts).await?;
        }
        CliCommand::Withdraw { action } => {
            commands::withdraw::run(action, &config, &tx_opts).await?;
        }
        CliCommand::Balance { address } => {
            commands::balance::run(&config, &address).await?;
        }
    }

    Ok(())
}

/// Parse metadata arguments from "key=value" format into a Vec of tuples
fn parse_metadata(args: Vec<String>) -> Vec<(String, String)> {
    args.into_iter()
        .filter_map(|s| {
            let mut parts = s.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Some((key.to_string(), value.to_string())),
                _ => {
                    print_warning(&format!(
                        "Ignoring invalid metadata format: '{}' (expected key=value)",
                        s
                    ));
                    None
                }
            }
        })
        .collect()
}

fn init_tracing(verbose: bool) {
    let filter = if verbose {
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::DEBUG.into())
            .from_env_lossy()
    } else {
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::WARN.into())
            .from_env_lossy()
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Print a success message
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

/// Print an info message
pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}

/// Print an in-progress status line (no newline) that can be overwritten.
pub fn print_step(msg: &str) {
    use std::io::Write;
    print!("\r\x1b[2K{} {}", "ℹ".blue().bold(), msg);
    let _ = std::io::stdout().flush();
}

/// Overwrite the current status line with a success message.
pub fn complete_step(msg: &str) {
    print!("\r\x1b[2K");
    println!("{} {}", "✓".green().bold(), msg);
}

/// Run the `publish` command – build, publish, and initialise the Hashi package.
pub async fn run_publish(opts: PublishOpts) -> anyhow::Result<()> {
    crate::init_crypto_provider();
    init_tracing(opts.verbose);

    // Load signer
    let signer = crate::config::load_ed25519_private_key_from_path(&opts.keypair)?;
    let sender = signer.public_key().derive_address();
    print_info(&format!("Sender address: {sender}"));

    // Build
    print_info(&format!(
        "Building package at {} ...",
        opts.package_path.display()
    ));
    let params = crate::publish::BuildParams {
        sui_binary: &opts.sui_binary,
        package_path: &opts.package_path,
        client_config: opts.sui_client_config.as_deref(),
        environment: opts.environment.as_deref(),
    };
    let compiled = crate::publish::build_package(&params)?;
    print_success(&format!(
        "Package built ({} module(s))",
        compiled.modules.len()
    ));

    if !opts.yes {
        print_info("This will publish the package and run initialization (2 transactions).");
        print_info("Use --yes / -y to skip this prompt.");
        eprint!("Continue? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            print_warning("Aborted.");
            return Ok(());
        }
    }

    // Connect to RPC
    let mut client = sui_rpc::Client::new(&opts.sui_rpc_url)?;

    // Publish + init
    print_info("Publishing and initializing ...");
    let ids =
        crate::publish::publish_and_init(&mut client, &signer, compiled, &opts.bitcoin_chain_id)
            .await?;
    print_success(&format!("package_id:      {}", ids.package_id));
    print_success(&format!("hashi_object_id: {}", ids.hashi_object_id));

    // Write ids to hashi_ids.json
    let json = serde_json::to_string_pretty(&ids)?;
    let out_path = "hashi_ids.json";
    std::fs::write(out_path, &json)?;
    print_success(&format!("Wrote {out_path}"));

    Ok(())
}

/// Run the `register` command – register a validator on-chain.
pub async fn run_register(opts: RegisterOpts) -> anyhow::Result<()> {
    use sui_sdk_types::bcs::ToBcs;

    init_tracing(opts.verbose);

    // Load the validator config
    let config = crate::config::Config::load(&opts.config)?;

    // Resolve Sui RPC URL: CLI flag > config file
    let sui_rpc_url = opts
        .sui_rpc_url
        .or_else(|| config.sui_rpc.clone())
        .ok_or_else(|| {
            anyhow::anyhow!("Sui RPC URL not provided (use --sui-rpc-url or set in config file)")
        })?;

    // Parse optional operator address
    let operator_address = opts
        .operator_address
        .map(|s| s.parse::<sui_sdk_types::Address>())
        .transpose()?;

    let validator_address = config.validator_address()?;
    print_info(&format!("Validator address: {validator_address}"));
    print_info(&format!("Sui RPC: {sui_rpc_url}"));

    if opts.print_only {
        // Build the transaction and print as base64 without executing.
        // No private key is required for this path.
        let mut client = sui_rpc::Client::new(&sui_rpc_url)?;
        let hashi_ids = config.hashi_ids();

        print_info("Building registration transaction ...");
        let transaction = crate::sui_tx_executor::build_register_or_update_validator_tx(
            &mut client,
            &hashi_ids,
            &config,
            operator_address,
            None,
        )
        .await?;

        match transaction {
            Some(tx) => {
                let tx_base64 = tx.to_bcs_base64()?;
                println!("{tx_base64}");
            }
            None => print_info("Validator metadata is already up-to-date; nothing to do."),
        }
        return Ok(());
    }

    if !opts.yes {
        print_info("This will register the validator on-chain (1 transaction).");
        print_info("Use --yes / -y to skip this prompt.");
        eprint!("Continue? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            print_warning("Aborted.");
            return Ok(());
        }
    }

    let client = sui_rpc::Client::new(&sui_rpc_url)?;
    let signer = config.operator_private_key()?;
    let hashi_ids = config.hashi_ids();
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    print_info("Registering validator ...");
    let updated = executor
        .execute_register_or_update_validator(&config, operator_address)
        .await?;

    if updated {
        print_success("Validator registered/updated successfully");
    } else {
        print_info("Validator metadata is already up-to-date; nothing to do.");
    }
    Ok(())
}
