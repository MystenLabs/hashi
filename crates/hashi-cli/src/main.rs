//! Hashi CLI - Command-line interface for the Hashi bridge
//!
//! A multi-purpose CLI for interacting with the Hashi bridge on Sui, including:
//!
//! - **Governance**: Create, vote on, and manage proposals
//! - **Committee**: View committee members and epoch information
//! - **Deposits**: Inspect and monitor deposit requests (coming soon)
//! - **Configuration**: Manage CLI and on-chain configuration
//!
//! ## Usage
//!
//! ```bash
//! # Governance
//! hashi-cli proposal list
//! hashi-cli proposal vote 0x123... -t upgrade
//!
//! # Committee
//! hashi-cli committee list
//! hashi-cli committee epoch
//!
//! # Configuration
//! hashi-cli config template -o hashi-cli.toml
//! ```

use clap::Args;
use clap::Parser;
use clap::Subcommand;
use colored::Colorize;

mod client;
mod commands;
mod config;
mod types;

#[derive(Parser)]
#[clap(
    name = "hashi-cli",
    about = "CLI for Hashi committee members to manage proposals and vote",
    version = env!("CARGO_PKG_VERSION"),
    author = "Mysten Labs"
)]
struct Cli {
    /// Path to the configuration file
    #[clap(long, short, env = "HASHI_CLI_CONFIG")]
    config: Option<std::path::PathBuf>,

    /// Sui RPC URL (overrides config file)
    #[clap(long, env = "SUI_RPC_URL")]
    sui_rpc_url: Option<String>,

    /// Hashi package ID (overrides config file)
    #[clap(long, env = "HASHI_PACKAGE_ID")]
    package_id: Option<String>,

    /// Hashi shared object ID (overrides config file)
    #[clap(long, env = "HASHI_OBJECT_ID")]
    hashi_object_id: Option<String>,

    /// Path to the keypair file for signing transactions
    #[clap(long, short, env = "HASHI_KEYPAIR")]
    keypair: Option<std::path::PathBuf>,

    /// Enable verbose output
    #[clap(long, short)]
    verbose: bool,

    /// Skip all confirmation prompts
    #[clap(long, short = 'y', global = true)]
    yes: bool,

    /// Gas budget for transactions (in MIST). If not set, estimates via dry-run.
    #[clap(long, global = true, env = "HASHI_GAS_BUDGET")]
    gas_budget: Option<u64>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Proposal management commands
    Proposal {
        #[clap(subcommand)]
        action: ProposalCommands,
    },

    /// Committee information commands
    Committee {
        #[clap(subcommand)]
        action: CommitteeCommands,
    },

    /// Configuration management
    Config {
        #[clap(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Subcommand)]
enum ProposalCommands {
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

        /// The proposal type (required for type-safety)
        #[clap(long, short = 't', value_enum)]
        r#type: ProposalType,
    },

    /// Remove your vote from a proposal
    RemoveVote {
        /// The proposal object ID
        proposal_id: String,

        /// The proposal type
        #[clap(long, short = 't', value_enum)]
        r#type: ProposalType,
    },

    /// Create a new proposal
    Create {
        #[clap(subcommand)]
        proposal: CreateProposalCommands,
    },
}

#[derive(Subcommand)]
enum CreateProposalCommands {
    /// Propose a package upgrade
    Upgrade {
        /// The digest of the new package (hex encoded)
        digest: String,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose updating the deposit fee
    UpdateDepositFee {
        /// The new deposit fee (in satoshis)
        fee: u64,

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
#[derive(Args)]
struct MetadataArgs {
    /// Optional metadata key-value pairs (format: key=value)
    #[clap(long, short, value_name = "KEY=VALUE")]
    metadata: Vec<String>,
}

#[derive(Subcommand)]
enum CommitteeCommands {
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
enum ConfigCommands {
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

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum ProposalType {
    Upgrade,
    UpdateDepositFee,
    EnableVersion,
    DisableVersion,
}

impl std::fmt::Display for ProposalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalType::Upgrade => write!(f, "Upgrade"),
            ProposalType::UpdateDepositFee => write!(f, "UpdateDepositFee"),
            ProposalType::EnableVersion => write!(f, "EnableVersion"),
            ProposalType::DisableVersion => write!(f, "DisableVersion"),
        }
    }
}

/// Transaction options passed to commands
pub struct TxOptions {
    /// Gas budget - None means estimate via dry-run
    pub gas_budget: Option<u64>,
    pub skip_confirm: bool,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_tracing(cli.verbose);

    // Load and merge configuration
    let config = config::Config::load(
        cli.config.as_deref(),
        cli.sui_rpc_url,
        cli.package_id,
        cli.hashi_object_id,
        cli.keypair,
    )?;

    let tx_opts = TxOptions {
        gas_budget: cli.gas_budget,
        skip_confirm: cli.yes,
    };

    match cli.command {
        Commands::Proposal { action } => match action {
            ProposalCommands::List { r#type, detailed } => {
                commands::proposal::list_proposals(&config, r#type, detailed).await?;
            }
            ProposalCommands::View { proposal_id } => {
                commands::proposal::view_proposal(&config, &proposal_id).await?;
            }
            ProposalCommands::Vote {
                proposal_id,
                r#type,
            } => {
                commands::proposal::vote(&config, &proposal_id, r#type, &tx_opts).await?;
            }
            ProposalCommands::RemoveVote {
                proposal_id,
                r#type,
            } => {
                commands::proposal::remove_vote(&config, &proposal_id, r#type, &tx_opts).await?;
            }
            ProposalCommands::Create { proposal } => match proposal {
                CreateProposalCommands::Upgrade { digest, metadata } => {
                    commands::proposal::create_upgrade_proposal(
                        &config,
                        &digest,
                        metadata.metadata,
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::UpdateDepositFee { fee, metadata } => {
                    commands::proposal::create_update_deposit_fee_proposal(
                        &config,
                        fee,
                        metadata.metadata,
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::EnableVersion { version, metadata } => {
                    commands::proposal::create_enable_version_proposal(
                        &config,
                        version,
                        metadata.metadata,
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::DisableVersion { version, metadata } => {
                    commands::proposal::create_disable_version_proposal(
                        &config,
                        version,
                        metadata.metadata,
                        &tx_opts,
                    )
                    .await?;
                }
            },
        },
        Commands::Committee { action } => match action {
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
        Commands::Config { action } => match action {
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
    }

    Ok(())
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
#[allow(dead_code)]
pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green().bold(), msg);
}

/// Print an error message
#[allow(dead_code)]
pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red().bold(), msg);
}

/// Print an info message
pub fn print_info(msg: &str) {
    println!("{} {}", "ℹ".blue().bold(), msg);
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    println!("{} {}", "⚠".yellow().bold(), msg);
}
