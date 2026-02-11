use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "hashi-monitor")]
#[command(about = "Monitor correlating Hashi / Guardian / Sui events")]
struct Cli {
    /// Path to YAML config file.
    #[arg(long)]
    config: std::path::PathBuf,

    /// Start of audit window, as unix seconds.
    #[arg(long)]
    t1: u64,

    /// End of audit window, as unix seconds.
    #[arg(long)]
    t2: u64,
}

fn main() -> anyhow::Result<()> {
    init_tracing_subscriber(false);

    let cli = Cli::parse();

    let cfg = hashi_monitor::config::Config::load_yaml(&cli.config)?;

    hashi_monitor::audit::run_audit(&cfg, cli.t1, cli.t2)?;

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
