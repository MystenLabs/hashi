use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

#[derive(Debug, Parser)]
#[command(name = "hashi-monitor")]
#[command(about = "Monitor correlating Hashi / Guardian / Sui events")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a one-time batch audit over [t1, t2].
    Batch {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,

        /// Start of audit window, as unix seconds.
        #[arg(long)]
        t1: u64,

        /// End of audit window, as unix seconds.
        #[arg(long)]
        t2: u64,
    },
    /// Run continuous monitoring.
    Continuous {
        /// Path to YAML config file.
        #[arg(long)]
        config: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    init_tracing_subscriber(false);

    let cli = Cli::parse();

    match cli.command {
        Command::Batch { config, t1, t2 } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let auditor = hashi_monitor::audit::BatchAuditor::new(cfg, t1, t2)?;
            auditor.run()?;
        }
        Command::Continuous { config } => {
            let cfg = hashi_monitor::config::Config::load_yaml(&config)?;
            let mut auditor = hashi_monitor::audit::ContinuousAuditor::new(cfg);
            auditor.run();
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
