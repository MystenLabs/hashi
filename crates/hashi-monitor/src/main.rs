use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use hashi_monitor::domain::now_unix_seconds;

#[derive(Debug, Parser)]
#[command(name = "hashi-monitor")]
#[command(about = "Monitor correlating Hashi / Guardian / Sui events")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a one-time batch audit over guardian [start, end].
    Batch {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of guardian audit window, as unix seconds.
        #[arg(long)]
        start: u64,

        /// End of guardian audit window, as unix seconds. Defaults to current time.
        #[arg(long)]
        end: Option<u64>,
    },
    /// Run continuous monitoring on guardian timeline.
    Continuous {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of guardian audit period, as unix seconds.
        #[arg(long)]
        start: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing_subscriber(false);

    let cli = Cli::parse();

    match cli.command {
        Command::Batch { config, start, end } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let end = end.unwrap_or_else(now_unix_seconds);
            let mut auditor = hashi_monitor::audit::BatchAuditor::new(cfg, start, end)?;
            auditor
                .run()
                .await
                .unwrap_or_else(|e| panic!("infra failure: {e:#}"));
        }
        Command::Continuous { config, start } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let mut auditor = hashi_monitor::audit::ContinuousAuditor::new(cfg, start)?;
            auditor.run().await?;
        }
    }

    Ok(())
}

pub fn init_tracing_subscriber(with_file_line: bool) {
    let mut builder = tracing_subscriber::FmtSubscriber::builder().with_env_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
            .from_env_lossy(),
    );

    if with_file_line {
        builder = builder
            .with_file(true)
            .with_line_number(true)
            .with_target(false);
    }

    let subscriber = builder.finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}
