use clap::Parser;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config;

// Define the `GIT_REVISION` and `VERSION` consts
bin_version::bin_version!();

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
#[clap(name = env!("CARGO_BIN_NAME"))]
#[clap(version = VERSION)]
struct Args {
    #[clap(long)]
    pub config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() {
    init_tracing_subscriber();

    tracing::info!("welcome to hashi");

    let args = Args::parse();

    let config = args
        .config
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

    Hashi::new(server_version, config).start();

    wait_termination().await;
    tracing::info!("hashi shutting down; goodbye");
}

async fn wait_termination() {
    use futures::FutureExt;
    use tokio::signal::unix::*;

    let sigint = tokio::signal::ctrl_c().boxed();
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let sigterm_recv = sigterm.recv().boxed();

    tokio::select! {
        _ = sigint => {},
        _ = sigterm_recv => {},
    }
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
