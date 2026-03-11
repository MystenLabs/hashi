use clap::Parser;
use clap::Subcommand;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(version = VERSION)]
#[clap(styles = hashi::cli::STYLES)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the Hashi validator server
    Server {
        #[clap(long)]
        config: Option<std::path::PathBuf>,
    },

    /// Proposal management commands
    Proposal {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        #[clap(subcommand)]
        action: hashi::cli::ProposalCommands,
    },

    /// Committee information commands
    Committee {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        #[clap(subcommand)]
        action: hashi::cli::CommitteeCommands,
    },

    /// CLI configuration management
    Config {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        #[clap(subcommand)]
        action: hashi::cli::ConfigCommands,
    },

    /// Build, publish, and initialise the Hashi Move package
    Publish {
        #[clap(flatten)]
        publish_opts: hashi::cli::PublishOpts,
    },

    /// Register a validator on-chain
    Register {
        #[clap(flatten)]
        register_opts: hashi::cli::RegisterOpts,
    },

    /// Deposit BTC into the Hashi bridge
    Deposit {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        #[clap(subcommand)]
        action: hashi::cli::DepositCommands,
    },

    /// Withdraw BTC from the Hashi bridge
    Withdraw {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        #[clap(subcommand)]
        action: hashi::cli::WithdrawCommands,
    },

    /// Check hBTC balance for a Sui address
    Balance {
        #[clap(flatten)]
        cli_opts: hashi::cli::CliGlobalOpts,

        /// Sui address to query
        address: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Server { config } => run_server(config).await,
        Commands::Proposal { cli_opts, action } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Proposal { action }).await
        }
        Commands::Committee { cli_opts, action } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Committee { action }).await
        }
        Commands::Config { cli_opts, action } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Config { action }).await
        }
        Commands::Publish { publish_opts } => hashi::cli::run_publish(publish_opts).await,
        Commands::Register { register_opts } => hashi::cli::run_register(register_opts).await,
        Commands::Deposit { cli_opts, action } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Deposit { action }).await
        }
        Commands::Withdraw { cli_opts, action } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Withdraw { action }).await
        }
        Commands::Balance { cli_opts, address } => {
            hashi::cli::run(cli_opts, hashi::cli::CliCommand::Balance { address }).await
        }
    }
}

async fn run_server(config_path: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    init_tracing_subscriber();

    tracing::info!("welcome to hashi");

    let config = config_path
        .map(|path| Config::load(&path))
        .transpose()
        .unwrap()
        .unwrap_or_default();

    prometheus::default_registry()
        .register(hashi::metrics::uptime_metric(
            VERSION,
            config.sui_chain_id(),
            config.bitcoin_chain_id(),
        ))
        .unwrap();

    let _metrics_server = hashi::metrics::start_prometheus_server(
        config.metrics_http_address(),
        prometheus::default_registry().clone(),
    );

    let server_version = ServerVersion::new(env!("CARGO_BIN_NAME"), VERSION);

    let hashi = Hashi::new(server_version, config)?;
    let hashi_service = hashi.start().await?;
    hashi_service.main().await?;

    tracing::info!("hashi shutting down; goodbye");
    Ok(())
}

fn init_tracing_subscriber() {
    let subscriber = ::tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_file(true)
        .with_line_number(true)
        .finish();
    ::tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}
