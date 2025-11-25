use hashi_guardian_shared::S3Config;
use tracing::info;

use aws_sdk_s3::Client as S3Client;

use crate::GuardianError;
use crate::GuardianResult;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::types::ObjectLockEnabled;

#[derive(Debug)]
pub struct S3Logger {
    pub client: S3Client,
    pub config: S3Config,
}

impl S3Logger {
    pub async fn new(config: S3Config) -> GuardianResult<Self> {
        info!("📦 S3 Configuration:");
        info!("   Bucket: {}", config.bucket_name);

        info!("🔧 Setting AWS credentials...");
        std::env::set_var("AWS_ACCESS_KEY_ID", &config.access_key);
        std::env::set_var("AWS_SECRET_ACCESS_KEY", &config.secret_key);

        info!("🌍 Loading AWS configuration...");
        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        let client = S3Client::new(&aws_config);
        Ok(Self { client, config })
    }

    /// Check if an object named in the key exists in the S3 bucket.
    /// Returns an error if the object exists.
    pub async fn is_exists(&self, _key: &str) -> GuardianResult<()> {
        // TODO
        Ok(())
    }

    pub async fn log(&self, _folder: &str, _key: &str, _value: &str) -> GuardianResult<()> {
        // TODO
        Ok(())
    }

    #[cfg(test)]
    pub async fn mock_for_testing() -> Self {
        let mock_s3_config = S3Config {
            bucket_name: "test-bucket".to_string(),
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
        };
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .load()
            .await;
        Self {
            client: S3Client::new(&aws_config),
            config: mock_s3_config,
        }
    }
}

pub async fn test_s3_connectivity(s3logger: &S3Logger) -> GuardianResult<()> {
    info!("Testing S3 connectivity...");
    let s3_client = &s3logger.client;
    let s3_config = &s3logger.config;

    // Verify bucket exists and has Object Lock enabled
    let bucket_config = s3_client
        .get_object_lock_configuration()
        .bucket(&s3_config.bucket_name)
        .send()
        .await;

    match bucket_config {
        Ok(config) => {
            let object_lock_enabled_config = config
                .object_lock_configuration()
                .expect("Object lock configuration missing")
                .object_lock_enabled()
                .expect("Object lock enabled field missing");

            match object_lock_enabled_config {
                ObjectLockEnabled::Enabled => {
                    info!("Bucket {} has Object Lock enabled", s3_config.bucket_name);
                }
                _ => {
                    return Err(GuardianError::GenericError(
                        "Unknown config in object lock".into(),
                    ))
                }
            }
        }
        Err(e) => {
            return Err(GuardianError::GenericError(format!(
                "Failed to verify Object Lock configuration: {}",
                e
            )));
        }
    }

    Ok(())
}
