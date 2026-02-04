fn main() -> anyhow::Result<()> {
    init_tracing_subscriber(false);
    let store = hashi_monitor::store::InMemoryStore::default();
    hashi_monitor::correlate::correlate_pending_safety_events(&store, 100)?;
    println!("no findings");
    Ok(())
}

pub fn init_tracing_subscriber(with_file_line: bool) {
    let mut builder = tracing_subscriber::FmtSubscriber::builder().with_env_filter(
        tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
            .from_env_lossy(),
    );

    if with_file_line {
        builder = builder.with_file(true).with_line_number(true);
    }

    let subscriber = builder.finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}
