use crate::AppState;
use axum::{extract::State, http::StatusCode, Json};
use log::{debug, info};
use shared::S3Config;

use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client as S3Client;

use anyhow::Result;

// TODO: Add some kind of authentication, e.g., an API key or token
pub async fn configure_s3(
    State(state): State<AppState>,
    Json(config): Json<S3Config>,
) -> (StatusCode, String) {
    info!("Received S3 configuration");
    info!("bucket name: {}", config.bucket_name);

    // Try to set the configuration (only works if not already set)
    if state.s3_config.set(config.clone()).is_err() {
        return (
            StatusCode::FORBIDDEN,
            "S3 configuration already set".to_string(),
        );
    }

    std::env::set_var("AWS_ACCESS_KEY_ID", &config.access_key);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", &config.secret_key);

    // Test S3 connectivity with the new credentials
    match test_s3_connectivity(&config).await {
        Ok(_) => {
            info!("✅ S3 configuration accepted and tested successfully");
            (
                StatusCode::OK,
                "S3 configuration received and tested successfully".to_string(),
            )
        }
        Err(e) => {
            debug!("❌ S3 connectivity test failed: {}", e);
            (
                StatusCode::OK,
                format!("S3 configuration received but test failed: {}", e),
            )
        }
    }
}

async fn test_s3_connectivity(config: &S3Config) -> Result<()> {
    info!("Testing S3 connectivity...");

    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;

    let s3_client = S3Client::new(&aws_config);

    let response = s3_client
        .list_objects_v2()
        .bucket(&config.bucket_name)
        .max_keys(10)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("S3 error: {}", e))?;

    info!("✅ S3 connectivity test passed!");

    // Print object list for testing
    let contents = response.contents();
    if contents.is_empty() {
        info!("No objects found in bucket");
    } else {
        info!("Found {} objects:", contents.len());
        for (i, object) in contents.iter().enumerate() {
            info!(
                "  [{}] Key: {}, Size: {} bytes",
                i + 1,
                object.key().unwrap_or("<no key>"),
                object.size().unwrap_or(0)
            );
        }
    }

    Ok(())
}
