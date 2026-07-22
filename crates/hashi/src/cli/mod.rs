// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! CLI module for the Hashi bridge
//!
//! Provides governance, committee, and configuration management commands.

use anyhow::Context;
use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use clap::builder::styling::AnsiColor;
use clap::builder::styling::Effects;
use clap::builder::styling::Styles;
use colored::Colorize;

pub mod client;
pub mod commands;
pub mod config;
pub mod types;
pub mod upgrade;

pub const STYLES: Styles = Styles::styled()
    .header(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .usage(AnsiColor::Yellow.on_default().effects(Effects::BOLD))
    .literal(AnsiColor::Green.on_default().effects(Effects::BOLD))
    .placeholder(AnsiColor::Cyan.on_default());

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum OutputFormat {
    HumanTable,
    Json,
}

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

    /// Build the transaction and print it as base64 (BCS `TransactionData`)
    /// instead of signing/executing. The unsigned transaction is the only thing
    /// written to stdout, ready for `sui keytool sign` + `sui client
    /// execute-signed-tx` (e.g. multisig). No keypair required; pair with
    /// --sender to set the signing address.
    #[clap(long, conflicts_with = "dry_run")]
    pub serialize_unsigned_transaction: bool,

    /// Sender address to build the transaction for (e.g. a multisig address).
    /// Defaults to the configured keypair's address; required when serializing
    /// or dry-running without a keypair.
    #[clap(long)]
    pub sender: Option<String>,

    /// Pin the gas coin (object id) used to pay for the transaction. Only the
    /// id is needed. Defaults to fullnode gas selection, or `gas_coin` from the
    /// config file.
    #[clap(long)]
    pub gas: Option<String>,

    /// Gas price override in MIST per unit. Defaults to the reference gas price.
    #[clap(long)]
    pub gas_price: Option<u64>,
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

        /// Also execute the proposal if this vote pushes it over quorum.
        /// Skipped silently (with an info message) when quorum isn't reached.
        /// Not supported for `Upgrade` proposals — use the dedicated upgrade
        /// flow instead.
        #[clap(long, short = 'e')]
        execute: bool,
    },

    /// Remove your vote from a proposal
    RemoveVote {
        /// The proposal object ID
        proposal_id: String,
    },

    /// Execute a proposal that has reached quorum
    Execute {
        /// The proposal object ID to execute
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
    ///
    /// Exactly one of `--digest` or `--package-path` must be provided.
    /// `--package-path` is recommended: the CLI builds the package, verifies
    /// that its `PACKAGE_VERSION` constant is exactly +1 of the currently
    /// published version, and derives the digest for the proposal.
    Upgrade {
        /// The digest of a pre-built package (hex encoded). Skips pre-flight
        /// checks — prefer `--package-path`.
        #[clap(long, conflicts_with = "package_path")]
        digest: Option<String>,

        /// Path to the upgrade package source. The CLI will run `sui move
        /// build` and verify the `PACKAGE_VERSION` constant before submitting.
        #[clap(long, value_name = "PATH")]
        package_path: Option<std::path::PathBuf>,

        /// Path to the `sui` CLI binary. Only used with `--package-path`.
        #[clap(long, env = "SUI_BINARY", default_value = "sui")]
        sui_binary: std::path::PathBuf,

        /// Optional path to a sui `client.yaml` for dependency resolution.
        /// Only used with `--package-path`.
        #[clap(long)]
        sui_client_config: Option<std::path::PathBuf>,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose updating a configuration value
    ///
    /// Known config keys and their expected value types:
    ///   bitcoin_deposit_minimum (u64),
    ///   bitcoin_withdrawal_minimum (u64),
    ///   bitcoin_confirmation_threshold (u64),
    ///   withdrawal_cancellation_cooldown_ms (u64), paused (bool)
    UpdateConfig {
        /// The config key to update
        key: String,

        /// The new value. Prefix with the type: u64:123, bool:true
        value: String,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose updating MPC parameters (`t`, `f`, `allowed_delta`,
    /// `nonce_generation_protocol`) in one transaction.
    UpdateMpcConfig {
        #[clap(long)]
        threshold_bps: Option<u64>,

        #[clap(long)]
        max_faulty_bps: Option<u64>,

        #[clap(long)]
        weight_reduction_allowed_delta: Option<u64>,

        /// Nonce-generation protocol: 0 = vanilla broadcast, 1 = AVID.
        #[clap(long)]
        nonce_generation_protocol: Option<u64>,

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

    /// Propose aborting a pending Hashi reconfiguration
    AbortReconfig {
        /// Pending Hashi epoch to abort
        #[clap(long)]
        epoch: u64,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose updating the guardian URL
    UpdateGuardian {
        /// The guardian gRPC endpoint URL
        #[clap(long)]
        url: String,

        #[clap(flatten)]
        metadata: MetadataArgs,
    },

    /// Propose pausing the protocol (or unpausing it with `--unpause`).
    ///
    /// Pausing uses a deliberately low quorum (default 5% of committee
    /// weight) so the committee can halt deposits/withdrawals fast in an
    /// emergency; unpausing requires the normal 2/3 supermajority.
    EmergencyPause {
        /// Propose unpausing instead of pausing.
        #[clap(long)]
        unpause: bool,

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
pub enum BackupCommands {
    /// Save an encrypted backup of the node config and referenced files
    Save {
        /// Path to the validator node config file
        node_config_path: std::path::PathBuf,

        /// Armored OpenPGP certificate, or path to one, used to encrypt the backup
        #[clap(long)]
        backup_pgp_cert: Option<String>,

        /// Directory to write the encrypted backup into
        #[clap(long, default_value = ".")]
        output_dir: std::path::PathBuf,
    },

    /// Restore files from a backup archive.
    ///
    /// When `--copy-to-original-paths` is set, files are written to the
    /// absolute paths stored in the manifest at backup time. If the restore
    /// is running on a different host or with a different filesystem layout,
    /// those paths will be used verbatim — extract without the flag and copy
    /// files manually in that case.
    Restore {
        /// Path to the backup tarball (.tar.asc encrypted or .tar unencrypted)
        backup_tarball: std::path::PathBuf,

        /// OpenPGP secret key file used to decrypt encrypted .tar.asc backups locally
        #[clap(long)]
        backup_pgp_secret_key: Option<std::path::PathBuf>,

        /// Decrypt encrypted .tar.asc backups with gpg instead of a local secret key file.
        ///
        /// Supports YubiKeys attached to this machine, and YubiKeys attached
        /// to a laptop over SSH when the laptop's gpg-agent socket is forwarded
        /// to the restore machine.
        #[clap(long)]
        use_gpg_agent: bool,

        /// GNUPGHOME to use with --use-gpg-agent
        #[clap(long, requires = "use_gpg_agent")]
        gpg_homedir: Option<std::path::PathBuf>,

        /// Directory to extract the restored files into
        #[clap(long, default_value = ".")]
        output_dir: std::path::PathBuf,

        /// Copy restored files to their original paths after extraction.
        ///
        /// Uses the absolute paths captured in the backup manifest. Intended
        /// for in-place recovery on the same host the backup came from.
        #[clap(long)]
        copy_to_original_paths: bool,
    },
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

    /// Submit deposit requests for outputs in a Bitcoin transaction.
    /// Without --outputs, requires Bitcoin RPC to look up matching transaction outputs.
    Request {
        /// Bitcoin transaction ID containing the deposit(s)
        #[clap(long)]
        txid: String,

        /// JSON list of [vout, amount_sats] outputs to request, avoiding Bitcoin RPC lookup
        #[clap(long)]
        outputs: Option<String>,

        /// Sui address that will receive hBTC
        #[clap(long)]
        recipient: Option<String>,
    },

    /// Submit a deposit request for a single specific UTXO (manual vout + amount)
    RequestSingle {
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
    List {
        /// Output format
        #[clap(long, value_enum, default_value_t = OutputFormat::HumanTable)]
        output_format: OutputFormat,

        /// Output as JSON (overrides --output-format)
        #[clap(long)]
        json: bool,
    },
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

        /// Submit this many identical requests, batched into PTBs
        #[clap(long, default_value_t = 1)]
        count: usize,
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
    List {
        /// Output format
        #[clap(long, value_enum, default_value_t = OutputFormat::HumanTable)]
        output_format: OutputFormat,

        /// Output as JSON (overrides --output-format)
        #[clap(long)]
        json: bool,
    },
}

/// Transaction options passed to commands
pub struct TxOptions {
    /// Gas budget - None means estimate via dry-run
    pub gas_budget: Option<u64>,
    pub skip_confirm: bool,
    /// If true, simulate the transaction without executing
    pub dry_run: bool,
    /// If true, build and print the unsigned transaction as base64 instead of
    /// signing/executing it.
    pub serialize_unsigned: bool,
    /// Explicit sender address (e.g. a multisig). `None` => derive from the
    /// configured keypair.
    pub sender: Option<sui_sdk_types::Address>,
    /// Pin a specific gas coin object id (`None` => fullnode gas selection).
    pub gas_object: Option<sui_sdk_types::Address>,
    /// Gas price override in MIST/unit (`None` => reference price).
    pub gas_price: Option<u64>,
}

impl TxOptions {
    /// The finalization mode implied by the flags. `--serialize-unsigned-transaction`
    /// wins over `--dry-run` (they are also mutually exclusive at the clap layer).
    pub fn mode(&self) -> crate::sui_tx_executor::TxMode {
        use crate::sui_tx_executor::TxMode;
        if self.serialize_unsigned {
            TxMode::SerializeUnsigned
        } else if self.dry_run {
            TxMode::DryRun
        } else {
            TxMode::Execute
        }
    }

    /// The manual gas overrides implied by the flags.
    pub fn gas_overrides(&self) -> crate::sui_tx_executor::GasOverrides {
        crate::sui_tx_executor::GasOverrides {
            gas_object: self.gas_object,
            gas_budget: self.gas_budget,
            gas_price: self.gas_price,
        }
    }

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

#[cfg(test)]
mod tx_options_tests {
    use super::TxOptions;
    use crate::sui_tx_executor::TxMode;

    fn base() -> TxOptions {
        TxOptions {
            gas_budget: None,
            skip_confirm: false,
            dry_run: false,
            serialize_unsigned: false,
            sender: None,
            gas_object: None,
            gas_price: None,
        }
    }

    #[test]
    fn mode_defaults_to_execute() {
        assert_eq!(base().mode(), TxMode::Execute);
    }

    #[test]
    fn dry_run_maps_to_dry_run() {
        let opts = TxOptions {
            dry_run: true,
            ..base()
        };
        assert_eq!(opts.mode(), TxMode::DryRun);
    }

    #[test]
    fn serialize_unsigned_wins_over_dry_run() {
        // The flags are mutually exclusive at the clap layer, but if both were
        // set, serialize-unsigned must take precedence (we never execute).
        let opts = TxOptions {
            serialize_unsigned: true,
            dry_run: true,
            ..base()
        };
        assert_eq!(opts.mode(), TxMode::SerializeUnsigned);
    }

    #[test]
    fn gas_overrides_pass_through() {
        let gas = sui_sdk_types::Address::from_static("0x2");
        let opts = TxOptions {
            gas_object: Some(gas),
            gas_budget: Some(123),
            gas_price: Some(7),
            ..base()
        };
        let overrides = opts.gas_overrides();
        assert_eq!(overrides.gas_object, Some(gas));
        assert_eq!(overrides.gas_budget, Some(123));
        assert_eq!(overrides.gas_price, Some(7));
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

    /// Enable verbose output
    #[clap(long, short)]
    pub verbose: bool,

    /// Skip confirmation prompts
    #[clap(long, short = 'y')]
    pub yes: bool,
}

/// Options for the `launch` subcommand.
///
/// Like [`PublishOpts`] this does *not* use [`CliGlobalOpts`]: launch is a
/// one-time publisher action driven off the `hashi publish` output rather
/// than an operator CLI config.
#[derive(Args)]
pub struct LaunchOpts {
    /// Sui RPC endpoint URL
    #[clap(
        long,
        env = "SUI_RPC_URL",
        default_value = "https://fullnode.mainnet.sui.io:443"
    )]
    pub sui_rpc_url: String,

    /// Path to the `hashi_ids.json` written by `hashi publish`
    /// (alternative: pass --package-id and --hashi-object-id)
    #[clap(long, default_value = "hashi_ids.json")]
    pub hashi_ids: std::path::PathBuf,

    /// Package ID (overrides --hashi-ids; requires --hashi-object-id)
    #[clap(long)]
    pub package_id: Option<String>,

    /// Hashi shared-object ID (overrides --hashi-ids; requires --package-id)
    #[clap(long)]
    pub hashi_object_id: Option<String>,

    /// Bitcoin chain ID (genesis block hash) to store on-chain
    #[clap(long, required_unless_present = "status")]
    pub bitcoin_chain_id: Option<String>,

    /// Guardian gRPC endpoint URL. Required — every deposit address is a
    /// 2-of-2 (mpc, guardian) taproot leaf.
    #[clap(long, required_unless_present = "status")]
    pub guardian_url: Option<String>,

    /// Guardian BTC pubkey, x-only hex-encoded (32 bytes). Published
    /// on-chain for 2-of-2 deposit address derivation.
    #[clap(long, required_unless_present = "status")]
    pub guardian_btc_public_key: Option<String>,

    /// Override `bitcoin_confirmation_threshold` on-chain at launch time.
    /// Falls back to the Move package's `init_defaults` (currently 6) when omitted.
    #[clap(long)]
    pub bitcoin_confirmation_threshold: Option<u64>,

    /// Override `bitcoin_deposit_time_delay_ms` on-chain at launch time.
    /// Falls back to the Move package's `init_defaults` (currently 600_000) when omitted.
    #[clap(long)]
    pub bitcoin_deposit_time_delay_ms: Option<u64>,

    /// Path to the publisher keypair (the `UpgradeCap` owner)
    #[clap(long, short = 'k', env = "HASHI_KEYPAIR")]
    pub keypair: Option<std::path::PathBuf>,

    /// `UpgradeCap` object ID. Auto-discovered from the sender's owned
    /// objects when omitted.
    #[clap(long)]
    pub upgrade_cap: Option<String>,

    /// Sender address for --serialize-unsigned-transaction when no local
    /// keypair exists (e.g. a multisig publisher)
    #[clap(long)]
    pub sender: Option<String>,

    /// Build the transaction and print it as base64 (BCS `TransactionData`)
    /// instead of executing it — for offline / multisig signing via
    /// `sui keytool sign`. No private key required.
    #[clap(long = "serialize-unsigned-transaction")]
    pub serialize_unsigned: bool,

    /// Report launch readiness and exit — no transaction is built and no
    /// keypair or guardian parameters are needed. Prints exactly one
    /// machine-readable line to stdout (the human roster goes to stderr):
    ///
    /// ```text
    /// LAUNCH_STATUS launched=<bool> registered=<n> ready=<n>
    ///   ready_stake_bps=<n> registered_stake_bps=<n>
    /// ```
    ///
    /// Stake is in basis points of total Sui voting power (10000 = all).
    /// This line is a STABLE CONTRACT parsed by deployment automation
    /// (sui-operations deploy-hashi.yaml) — change it only in lockstep.
    #[clap(long, conflicts_with = "serialize_unsigned")]
    pub status: bool,

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

    /// Build the transaction and print it as base64 (BCS `TransactionData`)
    /// instead of executing it — for offline / multisig signing via
    /// `sui keytool sign`. No private key required. (`--print-only` is a
    /// deprecated alias.)
    #[clap(long = "serialize-unsigned-transaction", alias = "print-only")]
    pub serialize_unsigned: bool,

    /// Enable verbose output
    #[clap(long, short)]
    pub verbose: bool,

    /// Skip confirmation prompts
    #[clap(long, short = 'y')]
    pub yes: bool,
}

/// CLI command variants (without Server)
pub enum CliCommand {
    Proposal {
        action: ProposalCommands,
    },
    Committee {
        action: CommitteeCommands,
    },
    Config {
        action: ConfigCommands,
    },
    Backup {
        action: BackupCommands,
    },
    Deposit {
        action: DepositCommands,
    },
    Withdraw {
        action: WithdrawCommands,
    },
    Balance {
        address: String,
        output_format: OutputFormat,
        json: bool,
    },
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

    let sender = opts
        .sender
        .as_deref()
        .map(str::parse::<sui_sdk_types::Address>)
        .transpose()
        .context("Invalid --sender address")?;
    let gas_object = opts
        .gas
        .as_deref()
        .map(str::parse::<sui_sdk_types::Address>)
        .transpose()
        .context("Invalid --gas object id")?
        .or(config.gas_coin);

    let tx_opts = TxOptions {
        gas_budget: opts.gas_budget,
        skip_confirm: opts.yes,
        dry_run: opts.dry_run,
        serialize_unsigned: opts.serialize_unsigned_transaction,
        sender,
        gas_object,
        gas_price: opts.gas_price,
    };

    // In serialize-unsigned mode, keep stdout clean (base64 only) by sending
    // all human-readable notes to stderr.
    set_notes_to_stderr(tx_opts.serialize_unsigned);

    match command {
        CliCommand::Proposal { action } => match action {
            ProposalCommands::List { r#type, detailed } => {
                commands::proposal::list_proposals(&config, r#type, detailed).await?;
            }
            ProposalCommands::View { proposal_id } => {
                commands::proposal::view_proposal(&config, &proposal_id).await?;
            }
            ProposalCommands::Vote {
                proposal_id,
                execute,
            } => {
                commands::proposal::vote(&config, &proposal_id, execute, &tx_opts).await?;
            }
            ProposalCommands::RemoveVote { proposal_id } => {
                commands::proposal::remove_vote(&config, &proposal_id, &tx_opts).await?;
            }
            ProposalCommands::Execute { proposal_id } => {
                commands::proposal::execute(&config, &proposal_id, &tx_opts).await?;
            }
            ProposalCommands::Create { proposal } => match proposal {
                CreateProposalCommands::Upgrade {
                    digest,
                    package_path,
                    sui_binary,
                    sui_client_config,
                    metadata,
                } => {
                    commands::proposal::create_upgrade_proposal(
                        &config,
                        digest.as_deref(),
                        package_path.as_deref(),
                        &sui_binary,
                        sui_client_config.as_deref(),
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
                CreateProposalCommands::UpdateMpcConfig {
                    threshold_bps,
                    max_faulty_bps,
                    weight_reduction_allowed_delta,
                    nonce_generation_protocol,
                    metadata,
                } => {
                    commands::proposal::create_update_mpc_config_proposal(
                        &config,
                        threshold_bps,
                        max_faulty_bps,
                        weight_reduction_allowed_delta,
                        nonce_generation_protocol,
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
                CreateProposalCommands::AbortReconfig { epoch, metadata } => {
                    commands::proposal::create_abort_reconfig_proposal(
                        &config,
                        epoch,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::UpdateGuardian { url, metadata } => {
                    commands::proposal::create_update_guardian_proposal(
                        &config,
                        &url,
                        parse_metadata(metadata.metadata),
                        &tx_opts,
                    )
                    .await?;
                }
                CreateProposalCommands::EmergencyPause { unpause, metadata } => {
                    commands::proposal::create_emergency_pause_proposal(
                        &config,
                        unpause,
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
        CliCommand::Backup { action } => match action {
            BackupCommands::Save {
                node_config_path,
                backup_pgp_cert,
                output_dir,
            } => {
                commands::backup::save(&node_config_path, backup_pgp_cert, &output_dir)?;
            }
            BackupCommands::Restore {
                backup_tarball,
                backup_pgp_secret_key,
                use_gpg_agent,
                gpg_homedir,
                output_dir,
                copy_to_original_paths,
            } => {
                let decryptor = match crate::backup::archive_format(&backup_tarball)? {
                    crate::backup::BackupArchiveFormat::Unencrypted => {
                        commands::backup::RestoreDecryptor::Unencrypted
                    }
                    crate::backup::BackupArchiveFormat::Encrypted => {
                        match (backup_pgp_secret_key, use_gpg_agent) {
                            (Some(secret_key_path), false) => {
                                commands::backup::RestoreDecryptor::LocalSecretKey {
                                    secret_key_path,
                                }
                            }
                            (None, true) => commands::backup::RestoreDecryptor::GpgAgent {
                                homedir: gpg_homedir,
                            },
                            (Some(_), true) | (None, false) => {
                                anyhow::bail!(
                                    "Pass exactly one restore backend: --backup-pgp-secret-key or --use-gpg-agent"
                                );
                            }
                        }
                    }
                };
                commands::backup::restore(
                    &backup_tarball,
                    decryptor,
                    &output_dir,
                    copy_to_original_paths,
                )?;
            }
        },
        CliCommand::Deposit { action } => {
            commands::deposit::run(action, &config, &tx_opts).await?;
        }
        CliCommand::Withdraw { action } => {
            commands::withdraw::run(action, &config, &tx_opts).await?;
        }
        CliCommand::Balance {
            address,
            output_format,
            json,
        } => {
            let output_format = if json {
                OutputFormat::Json
            } else {
                output_format
            };
            commands::balance::run(&config, &address, output_format).await?;
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
    let level = if verbose {
        tracing::level_filters::LevelFilter::DEBUG
    } else {
        tracing::level_filters::LevelFilter::WARN
    };

    hashi_types::telemetry::TelemetryConfig::new()
        .with_default_level(level)
        .with_target(false)
        .with_env()
        .init();
}

/// When set, human-readable notes/summaries are written to stderr instead of
/// stdout. This is enabled in `--serialize-unsigned-transaction` mode so that
/// stdout carries only the base64 unsigned transaction (safe to pipe into
/// `sui keytool sign`).
static NOTES_TO_STDERR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Route human-readable notes/summaries to stderr (keeping stdout clean for
/// machine-readable output). Call once when entering a serialize-unsigned flow.
pub fn set_notes_to_stderr(enabled: bool) {
    NOTES_TO_STDERR.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

fn notes_to_stderr() -> bool {
    NOTES_TO_STDERR.load(std::sync::atomic::Ordering::Relaxed)
}

/// Print a human-readable note/summary line. Goes to stderr in serialize mode
/// (so stdout stays clean for the base64 transaction), stdout otherwise.
pub fn print_detail(msg: &str) {
    if notes_to_stderr() {
        eprintln!("{msg}");
    } else {
        println!("{msg}");
    }
}

/// Print a success message
pub fn print_success(msg: &str) {
    print_detail(&format!("{} {}", "✓".green().bold(), msg));
}

/// Print an info message
pub fn print_info(msg: &str) {
    print_detail(&format!("{} {}", "ℹ".blue().bold(), msg));
}

/// Print a warning message
pub fn print_warning(msg: &str) {
    print_detail(&format!("{} {}", "⚠".yellow().bold(), msg));
}

/// Render the result of a finalized transaction and return the execution
/// response when one was produced (execute mode only). The serialized unsigned
/// transaction is the only thing written to stdout; everything else is a note.
pub fn print_tx_outcome(
    outcome: crate::sui_tx_executor::TxOutcome,
) -> Option<Box<sui_rpc::proto::sui::rpc::v2::ExecuteTransactionResponse>> {
    use crate::sui_tx_executor::TxOutcome;
    match outcome {
        TxOutcome::Serialized(tx_base64) => {
            println!("{tx_base64}");
            None
        }
        TxOutcome::Simulated {
            sender,
            gas_budget,
            gas_price,
        } => {
            print_detail(&format!("\n{}", "🔍 Dry-run Results:".bold()));
            print_detail(&format!(
                "  {} {}",
                "Sender:".dimmed(),
                sender.to_hex().cyan()
            ));
            print_detail(&format!(
                "  {} {} MIST",
                "Gas Budget:".dimmed(),
                gas_budget.to_string().cyan()
            ));
            print_detail(&format!(
                "  {} {} MIST/unit",
                "Gas Price:".dimmed(),
                gas_price.to_string().cyan()
            ));
            let max_cost_sui = (gas_budget as f64) / 1_000_000_000.0;
            print_detail(&format!(
                "  {} {:.6} SUI",
                "Max Cost:".dimmed(),
                format!("{max_cost_sui:.6}").yellow()
            ));
            print_detail(&format!(
                "\n  {} Transaction simulated successfully (not executed).",
                "✓".green()
            ));
            None
        }
        TxOutcome::Executed(response) => {
            let digest = response.transaction().digest();
            print_detail(&format!(
                "\n{} Transaction submitted: {}",
                "✓".green(),
                digest.to_string().cyan()
            ));
            Some(response)
        }
    }
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
    let signer = crate::keys::load_keypair_from_path(&opts.keypair)?;
    let sender = signer.verifying_key().derive_address();
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
        print_info("This will publish the package (1 transaction).");
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
    let mut client = crate::sui_rpc_client::new_sui_rpc_client(&opts.sui_rpc_url)?;

    // Publish
    print_info("Publishing ...");
    let crate::publish::PublishOutput {
        ids,
        upgrade_cap_id,
    } = crate::publish::publish_package(&mut client, &signer, compiled).await?;
    print_success(&format!("package_id:      {}", ids.package_id));
    print_success(&format!("hashi_object_id: {}", ids.hashi_object_id));
    print_success(&format!("upgrade_cap_id:  {upgrade_cap_id}"));
    print_info(
        "The UpgradeCap stays in the publisher's wallet and the deploy is not yet \
         configured. Once all expected validators have registered, run `hashi launch` \
         with the chain id and guardian parameters to configure the deploy and unlock \
         genesis.",
    );

    // Write ids to hashi_ids.json
    let json = serde_json::to_string_pretty(&ids)?;
    let out_path = "hashi_ids.json";
    std::fs::write(out_path, &json)?;
    print_success(&format!("Wrote {out_path}"));

    Ok(())
}

/// Run the `launch` command – send `hashi::finish_publish` (the launch
/// switch): configure the deploy (chain id, guardian, overrides) and hand
/// the package `UpgradeCap` into on-chain custody, which unlocks genesis.
/// The initial committee forms from the validators fully registered at that
/// moment.
pub async fn run_launch(opts: LaunchOpts) -> anyhow::Result<()> {
    use sui_sdk_types::bcs::ToBcs;

    crate::init_crypto_provider();
    init_tracing(opts.verbose);

    // In serialize/status mode keep stdout clean (base64 / the LAUNCH_STATUS
    // line only); notes go to stderr.
    set_notes_to_stderr(opts.serialize_unsigned || opts.status);

    // Resolve ids: explicit flags win, else the hashi_ids.json from publish.
    let ids: crate::config::HashiIds = match (&opts.package_id, &opts.hashi_object_id) {
        (Some(package_id), Some(hashi_object_id)) => crate::config::HashiIds {
            package_id: package_id.parse()?,
            hashi_object_id: hashi_object_id.parse()?,
        },
        (None, None) => {
            let raw = std::fs::read_to_string(&opts.hashi_ids).with_context(|| {
                format!(
                    "failed to read {} (or pass --package-id and --hashi-object-id)",
                    opts.hashi_ids.display()
                )
            })?;
            serde_json::from_str(&raw)?
        }
        _ => anyhow::bail!("--package-id and --hashi-object-id must be provided together"),
    };

    print_info(&format!("Sui RPC: {}", opts.sui_rpc_url));

    let mut client = crate::sui_rpc_client::new_sui_rpc_client(&opts.sui_rpc_url)?;

    // Pre-flight: read the launch state and who would form the initial
    // committee. No hard failures yet — status mode reports every state.
    let (onchain, _watcher) =
        crate::onchain::OnchainState::new(&opts.sui_rpc_url, ids, None, None, None).await?;
    let (launched, roster): (bool, Vec<(sui_sdk_types::Address, bool)>) = {
        let state = onchain.state();
        (
            state.hashi().config.upgrade_cap.is_some(),
            state
                .hashi()
                .committees
                .members()
                .iter()
                .map(|(address, member)| {
                    (
                        *address,
                        member.next_epoch_encryption_public_key().is_some(),
                    )
                })
                .collect(),
        )
    };

    // Stake-weight the roster: the genesis committee's security is the Sui
    // voting power it carries, not its head-count. Sui voting power sums to
    // 10_000 basis points across the active validator set.
    let voting_powers = fetch_voting_powers(&mut client).await?;
    let total_power: u64 = voting_powers.values().sum();
    let power_of = |address: &sui_sdk_types::Address| -> u64 {
        voting_powers.get(address).copied().unwrap_or(0)
    };
    let percent = |power: u64| -> f64 {
        if total_power == 0 {
            0.0
        } else {
            100.0 * power as f64 / total_power as f64
        }
    };

    print_info(&format!("Registered validators ({}):", roster.len()));
    for (address, ready) in &roster {
        let status = if !voting_powers.contains_key(address) {
            "NOT AN ACTIVE SUI VALIDATOR"
        } else if *ready {
            "ready"
        } else {
            "MISSING NEXT-EPOCH KEYS (will be excluded from the committee)"
        };
        print_info(&format!(
            "  {address}  {:6.2}% stake  {status}",
            percent(power_of(address)),
        ));
    }
    let num_ready = roster.iter().filter(|(_, ready)| *ready).count();
    let ready_power: u64 = roster
        .iter()
        .filter(|(_, ready)| *ready)
        .map(|(address, _)| power_of(address))
        .sum();
    let registered_power: u64 = roster.iter().map(|(address, _)| power_of(address)).sum();
    print_info(&format!(
        "Ready to launch: {num_ready}/{} validators, {:.2}% of total Sui voting power \
         (registered: {:.2}%)",
        roster.len(),
        percent(ready_power),
        percent(registered_power),
    ));

    if opts.status {
        // STABLE CONTRACT: the only stdout line in --status mode, parsed by
        // deployment automation (sui-operations deploy-hashi.yaml). Change
        // only in lockstep with its consumers.
        let bps = |power: u64| -> u64 { (power * 10_000).checked_div(total_power).unwrap_or(0) };
        println!(
            "LAUNCH_STATUS launched={launched} registered={} ready={num_ready} \
             ready_stake_bps={} registered_stake_bps={}",
            roster.len(),
            bps(ready_power),
            bps(registered_power),
        );
        return Ok(());
    }

    anyhow::ensure!(
        !launched,
        "the UpgradeCap is already in on-chain custody — the launch (finish_publish) \
         has already happened"
    );
    anyhow::ensure!(
        !roster.is_empty(),
        "no validators are registered yet; the genesis committee would be empty"
    );
    anyhow::ensure!(
        num_ready > 0,
        "no validator has finished key registration; genesis would stall"
    );
    if num_ready < roster.len() {
        print_warning(&format!(
            "{} of {} registered validators ({:.2}% of total Sui voting power) have not \
             finished key registration and would be excluded from the genesis committee",
            roster.len() - num_ready,
            roster.len(),
            percent(registered_power - ready_power),
        ));
    }

    // Guardian parameters are published on-chain by the launch tx (clap
    // requires them in every mode except --status).
    let bitcoin_chain_id = opts
        .bitcoin_chain_id
        .expect("required unless --status (enforced by clap)");
    let guardian_btc_public_key = opts
        .guardian_btc_public_key
        .expect("required unless --status (enforced by clap)");
    let guardian_url = opts
        .guardian_url
        .expect("required unless --status (enforced by clap)");
    let btc_public_key = hex::decode(
        guardian_btc_public_key
            .strip_prefix("0x")
            .unwrap_or(&guardian_btc_public_key),
    )
    .context("Invalid hex for --guardian-btc-public-key")?;
    anyhow::ensure!(
        btc_public_key.len() == 32,
        "--guardian-btc-public-key must be 32 bytes (x-only), got {} bytes",
        btc_public_key.len(),
    );
    let guardian = crate::publish::GuardianConfig {
        url: guardian_url,
        btc_public_key,
    };
    let bitcoin_overrides = crate::publish::BitcoinConfigOverrides {
        confirmation_threshold: opts.bitcoin_confirmation_threshold,
        deposit_time_delay_ms: opts.bitcoin_deposit_time_delay_ms,
    };

    // Resolve the sender (the UpgradeCap owner): a local keypair, or an
    // explicit --sender for the serialize-unsigned (multisig) path.
    let signer = opts
        .keypair
        .as_deref()
        .map(crate::keys::load_keypair_from_path)
        .transpose()?;
    let sender: sui_sdk_types::Address = match (&signer, &opts.sender) {
        (Some(signer), None) => signer.verifying_key().derive_address(),
        (None, Some(sender)) => sender.parse()?,
        (Some(_), Some(_)) => anyhow::bail!("pass either --keypair or --sender, not both"),
        (None, None) => anyhow::bail!(
            "pass --keypair, or --sender together with --serialize-unsigned-transaction"
        ),
    };
    if signer.is_none() && !opts.serialize_unsigned {
        anyhow::bail!("--sender requires --serialize-unsigned-transaction (no key to sign with)");
    }
    print_info(&format!("Sender (UpgradeCap owner): {sender}"));

    // Locate the cap.
    let upgrade_cap_id: sui_sdk_types::Address = match &opts.upgrade_cap {
        Some(id) => id.parse()?,
        None => {
            print_info("Locating UpgradeCap among the sender's owned objects ...");
            crate::publish::find_upgrade_cap(&mut client, sender, ids.package_id).await?
        }
    };
    print_info(&format!("UpgradeCap: {upgrade_cap_id}"));

    if opts.serialize_unsigned {
        let tx = crate::publish::build_finish_publish_tx(
            &mut client,
            sender,
            &ids,
            upgrade_cap_id,
            &bitcoin_chain_id,
            &guardian,
            &bitcoin_overrides,
        )
        .await?;
        println!("{}", tx.to_bcs_base64()?);
        return Ok(());
    }

    if !opts.yes {
        print_info(
            "This sends hashi::finish_publish: it configures the deploy (chain id, \
             guardian) and hands the UpgradeCap into on-chain custody, UNLOCKING \
             GENESIS — the initial committee forms from the validators that are fully \
             registered right now (1 transaction).",
        );
        print_info("Use --yes / -y to skip this prompt.");
        eprint!("Continue? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            print_warning("Aborted.");
            return Ok(());
        }
    }

    let signer = signer.expect("presence checked during sender resolution");
    print_info("Sending launch transaction (hashi::finish_publish) ...");
    crate::publish::finish_publish(
        &mut client,
        &signer,
        &ids,
        upgrade_cap_id,
        &bitcoin_chain_id,
        &guardian,
        &bitcoin_overrides,
    )
    .await?;
    print_success("finish_publish executed — genesis unlocked. Validators will now run DKG.");
    Ok(())
}

/// Active Sui validators' voting power (basis points of the 10_000 total),
/// keyed by validator address.
async fn fetch_voting_powers(
    client: &mut sui_rpc::Client,
) -> anyhow::Result<std::collections::HashMap<sui_sdk_types::Address, u64>> {
    use sui_rpc::field::FieldMaskUtil;

    let mut request = sui_rpc::proto::sui::rpc::v2::GetEpochRequest::default();
    request.read_mask = Some(sui_rpc::field::FieldMask::from_paths([
        "system_state.validators.active_validators",
    ]));
    let response = client
        .ledger_client()
        .get_epoch(request)
        .await?
        .into_inner();

    let validators = response
        .epoch
        .and_then(|epoch| epoch.system_state)
        .and_then(|system_state| system_state.validators)
        .map(|validator_set| validator_set.active_validators)
        .unwrap_or_default();

    let mut powers = std::collections::HashMap::new();
    for validator in validators {
        if let (Some(address), Some(power)) = (validator.address, validator.voting_power) {
            powers.insert(address.parse::<sui_sdk_types::Address>()?, power);
        }
    }
    Ok(powers)
}

/// Run the `register` command – register a validator on-chain.
pub async fn run_register(opts: RegisterOpts) -> anyhow::Result<()> {
    use sui_sdk_types::bcs::ToBcs;

    init_tracing(opts.verbose);

    // In serialize mode keep stdout clean (base64 only); notes go to stderr.
    set_notes_to_stderr(opts.serialize_unsigned);

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

    if opts.serialize_unsigned {
        // Build the transaction and print as base64 without executing.
        // No private key is required for this path.
        let mut client = crate::sui_rpc_client::new_sui_rpc_client(&sui_rpc_url)?;
        let hashi_ids = config.hashi_ids();

        print_info("Building registration transaction ...");
        let transaction = crate::sui_tx_executor::build_register_or_update_validator_tx(
            &mut client,
            &hashi_ids,
            &config,
            operator_address,
            None,
            None,
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

    let client = crate::sui_rpc_client::new_sui_rpc_client(&sui_rpc_url)?;
    let signer = config.operator_private_key()?;
    let hashi_ids = config.hashi_ids();
    let mut executor = crate::sui_tx_executor::SuiTxExecutor::new(client, signer, hashi_ids);

    print_info("Registering validator ...");
    let updated = executor
        .execute_register_or_update_validator(&config, operator_address, None, None)
        .await?;

    if updated {
        print_success("Validator registered/updated successfully");
    } else {
        print_info("Validator metadata is already up-to-date; nothing to do.");
    }
    Ok(())
}
