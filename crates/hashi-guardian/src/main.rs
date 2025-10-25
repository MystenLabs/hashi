use anyhow::Result;
use shared::S3Config;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    let base_url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://localhost:3000".to_string());

    println!("🔍 Connecting to server at: {}\n", base_url);

    // Read S3 credentials from .env
    let s3_config = S3Config {
        access_key: env::var("AWS_ACCESS_KEY_ID")
            .expect("AWS_ACCESS_KEY_ID not found in .env file"),
        secret_key: env::var("AWS_SECRET_ACCESS_KEY")
            .expect("AWS_SECRET_ACCESS_KEY not found in .env file"),
        bucket_name: env::var("AWS_BUCKET_NAME").expect("AWS_BUCKET_NAME not found in .env file"),
    };

    println!("📤 Sending S3 configuration to server...");

    // Send credentials to server
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/configure", base_url))
        .json(&s3_config)
        .send()
        .await?;

    if response.status().is_success() {
        println!("✅ Configuration sent successfully!");
        let body = response.text().await?;
        println!("   Response: {}", body);
    } else {
        println!("❌ Failed to send configuration: {}", response.status());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dummy_test() {
        assert_eq!(2 + 2, 4);
    }
}
