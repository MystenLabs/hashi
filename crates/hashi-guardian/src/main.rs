use anyhow::Result;
use shared::S3Config;
use std::env;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing_subscriber();

    // Load environment variables from .env file
    dotenvy::dotenv().ok();

    let base_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    info!("🔍 Connecting to server at: {}\n", base_url);

    // Read S3 credentials from environment variables
    let s3_config = S3Config {
        access_key: env::var("AWS_ACCESS_KEY_ID").expect("AWS_ACCESS_KEY_ID not found"),
        secret_key: env::var("AWS_SECRET_ACCESS_KEY").expect("AWS_SECRET_ACCESS_KEY not found"),
        bucket_name: env::var("AWS_BUCKET_NAME").expect("AWS_BUCKET_NAME not found"),
    };

    info!("📤 Sending S3 configuration to server...");

    // Send credentials to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/configure", base_url))
        .json(&s3_config)
        .send()
        .await?;

    if response.status().is_success() {
        info!("✅ Configuration sent successfully!");
        let body = response.text().await?;
        info!("   Response: {}", body);
    } else {
        info!("❌ Failed to send configuration: {}", response.status());
    }

    Ok(())
}

fn init_tracing_subscriber() {
    let subscriber = ::tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .finish();
    ::tracing::subscriber::set_global_default(subscriber)
        .expect("unable to initialize tracing subscriber");
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_test() {
        assert_eq!(2 + 2, 4);
    }
}
