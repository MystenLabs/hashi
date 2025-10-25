use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use log::info;
use shared::S3Config;
use std::sync::{Arc, OnceLock};

mod s3_logger;
use s3_logger::configure_s3;

#[derive(Clone)]
struct AppState {
    pub s3_config: Arc<OnceLock<S3Config>>,
}

async fn hello() -> &'static str {
    "Hello world!"
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let state = AppState {
        s3_config: Arc::new(OnceLock::new()),
    };

    let app = Router::new()
        .route("/", get(hello))
        .route("/configure", post(configure_s3))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Server listening on {}", listener.local_addr().unwrap());
    info!("Waiting for S3 configuration from client...");
    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_test() {
        assert_eq!(2 + 2, 4);
    }
}
