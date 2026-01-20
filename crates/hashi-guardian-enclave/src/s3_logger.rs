use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::CredentialsBuilder;
use hashi_guardian_shared::S3Config;
use std::time::Duration;
use std::time::SystemTime;

use crate::GuardianResult;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::DateTime;
use aws_sdk_s3::types::ObjectLockEnabled;
use aws_sdk_s3::types::ObjectLockMode;
use aws_sdk_s3::Client as S3Client;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::S3Error;
use serde::Serialize;
use tracing::info;

#[derive(Debug)]
pub struct S3Logger {
    pub session_id: String,
    pub client: S3Client,
    pub config: S3Config,
}

impl S3Logger {
    pub async fn new(session_id: String, config: S3Config) -> Self {
        info!("S3 Configuration:");
        info!("   Bucket: {}", config.bucket_name);

        let creds = CredentialsBuilder::default()
            .access_key_id(config.access_key.clone())
            .secret_access_key(config.secret_key.clone())
            .provider_name("hashi-guardian")
            .build();

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .load()
            .await;
        let client = S3Client::new(&aws_config);

        Self {
            session_id,
            client,
            config,
        }
    }

    // ========================================================================
    // S3 Write
    // ========================================================================

    /// Creates a new S3 Object with:
    ///     key: session-id/<random>.json
    ///     value: JSON representation of value
    pub async fn write<T: Serialize>(&self, value: &T) -> GuardianResult<()> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        // session_id/<random>.json
        let rand_suffix = format!("{:016x}", rand::random::<u64>());
        let key = format!("{}/{}.json", self.session_id, rand_suffix);
        info!("Logging to {}", key);

        // TODO: change duration based on env (test/prod)
        let expiry_time = SystemTime::now()
            .checked_add(Duration::from_mins(5))
            .expect("Cant overflow");

        let body = serde_json::to_string(value)
            .map_err(|e| InternalError(format!("Serialization error: {}", e)))?;
        info!("Log message: {}", body);

        let _result = s3_client
            .put_object()
            .bucket(&s3_config.bucket_name)
            .key(&key)
            .content_type("application/json")
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(expiry_time))
            .body(ByteStream::from(body.into_bytes()))
            .send()
            .await
            .map_err(|e| S3Error(format!("Failed to write to s3: {}", e)))?;

        // TODO: Implement retries

        info!("📝 Logged entry {} to immutable storage", rand_suffix);
        info!("🔒 Object locked until: {:?}", expiry_time);
        info!(
            "🌐 Public URL: https://{}.s3.amazonaws.com/{}",
            &s3_config.bucket_name, key
        );

        Ok(())
    }

    // ========================================================================
    // S3 Connectivity Tests
    // ========================================================================

    pub async fn test_s3_connectivity(&self) -> GuardianResult<()> {
        self.assert_object_lock_enabled().await
    }

    /// Verify that the S3 bucket has object lock enabled and returns an Err if not.
    /// Can be used as a test for S3 connectivity.
    pub async fn assert_object_lock_enabled(&self) -> GuardianResult<()> {
        let s3_client = &self.client;
        let s3_config = &self.config;

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
                    _ => return Err(S3Error("Unknown config in object lock".into())),
                }
            }
            Err(e) => {
                return Err(S3Error(format!(
                    "Failed to verify Object Lock configuration: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// List up to 10 objects in the bucket.
    /// This is intended as a lightweight connectivity/debug helper (primarily for testing).
    pub async fn list_objects(&self) -> GuardianResult<()> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        let bucket_objects = s3_client
            .list_objects_v2()
            .bucket(&s3_config.bucket_name)
            .max_keys(10)
            .send()
            .await
            .map_err(|e| S3Error(format!("Failed to list objects: {}", e)))?;

        let objects = bucket_objects.contents();

        if objects.is_empty() {
            info!(
                "Bucket {} has no objects (or no access to list)",
                s3_config.bucket_name
            );
            return Ok(());
        }

        info!(
            "Bucket {}: listing {} object(s) (max 10)",
            s3_config.bucket_name,
            objects.len()
        );

        for (i, obj) in objects.iter().enumerate() {
            let key = obj.key().unwrap_or("<missing key>");
            info!(
                "  {}. key={} size={:?} last_modified={:?} etag={:?}",
                i + 1,
                key,
                obj.size(),
                obj.last_modified(),
                obj.e_tag()
            );
        }

        Ok(())
    }

    /// Mock S3Logger
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
            session_id: "test-session-id".to_string(),
            client: S3Client::new(&aws_config),
            config: mock_s3_config,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ed25519_consensus::SigningKey;
    use hashi_guardian_shared::init_tracing_subscriber;
    use hashi_guardian_shared::now_timestamp_ms;
    use hashi_guardian_shared::GuardianSigned;
    use hashi_guardian_shared::LogMessage;
    use std::num::NonZeroU16;

    async fn setup_s3_from_env_vars() -> S3Logger {
        dotenvy::dotenv().ok();
        let bucket_name =
            std::env::var("AWS_BUCKET_NAME").expect("missing AWS_BUCKET_NAME in .env");

        let access_key =
            std::env::var("AWS_ACCESS_KEY_ID").expect("missing AWS_ACCESS_KEY_ID in .env");

        let secret_key =
            std::env::var("AWS_SECRET_ACCESS_KEY").expect("missing AWS_SECRET_ACCESS_KEY in .env");

        let config = S3Config {
            bucket_name,
            access_key,
            secret_key,
        };

        // Nullify env vars to make sure they don't interfere with testing
        std::env::set_var("AWS_BUCKET_NAME", "");
        std::env::set_var("AWS_ACCESS_KEY_ID", "");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "");

        S3Logger::new("guardian-test-logs".into(), config).await
    }

    fn mock_signed_log_message() -> GuardianSigned<LogMessage> {
        let data = LogMessage::ProvisionerInitSuccess {
            share_id: NonZeroU16::new(10).unwrap(),
            state_hash: [10u8; 32],
        };
        let timestamp_ms = now_timestamp_ms();
        let kp = SigningKey::new(rand::thread_rng());
        GuardianSigned::new(data, &kp, timestamp_ms)
    }

    /// Integration test: loads AWS/S3 credentials from the workspace root `.env` and
    /// verifies we can reach the bucket by checking Object Lock configuration.
    #[tokio::test]
    #[ignore]
    async fn test_s3_connectivity() {
        init_tracing_subscriber(false);
        let logger = setup_s3_from_env_vars().await;
        logger.assert_object_lock_enabled().await.unwrap();
        logger.list_objects().await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_s3_write() {
        init_tracing_subscriber(false);
        let logger = setup_s3_from_env_vars().await;
        logger.assert_object_lock_enabled().await.unwrap();
        let test_obj = mock_signed_log_message();
        logger.write(&test_obj).await.unwrap();
    }
}
