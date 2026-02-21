use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::CredentialsBuilder;
use aws_sdk_s3::error::DisplayErrorContext;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::S3_DIR_INIT;
use std::time::Duration;
use std::time::SystemTime;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::DateTime;
use aws_sdk_s3::types::ObjectLockEnabled;
use aws_sdk_s3::types::ObjectLockMode;
use aws_sdk_s3::Client as S3Client;
use hashi_types::guardian::s3_utils::S3Directory;
use hashi_types::guardian::GuardianError::S3Error;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::UnixMillis;
use serde::Serialize;
use tracing::info;

const MAX_RETRY_ATTEMPTS: u32 = 5;

pub struct S3Logger {
    /// A unique session ID. Used as a prefix in log keys.
    session_id: String,
    /// S3 config: bucket name, region, API keys
    config: S3Config,
    /// S3 client
    client: S3Client,
}

impl S3Logger {
    // ========================================================================
    // Constructors
    // ========================================================================

    pub async fn new(session_id: String, config: S3Config) -> Self {
        info!("S3 Configuration:");
        info!("   Bucket: {}", config.bucket_name());
        info!("   Region: {}", config.region());

        let creds = CredentialsBuilder::default()
            .access_key_id(config.access_key.clone())
            .secret_access_key(config.secret_key.clone())
            .provider_name("hashi-guardian")
            .build();

        let retry_config = RetryConfig::standard().with_max_attempts(MAX_RETRY_ATTEMPTS); // default is 3

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region().to_string()))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .retry_config(retry_config)
            .load()
            .await;
        let client = S3Client::new(&aws_config);

        Self {
            session_id,
            client,
            config,
        }
    }

    /// Construct an `S3Logger` from an already-configured S3 client.
    /// This is intended for unit tests that use a mock S3 Client.
    /// This is not put behind cfg(test) as tests in the enclave crate also use it.
    pub fn from_client_for_tests(session_id: String, config: S3Config, client: S3Client) -> Self {
        Self {
            session_id,
            client,
            config,
        }
    }

    // ========================================================================
    // Getters
    // ========================================================================

    pub fn bucket_info(&self) -> &S3BucketInfo {
        &self.config.bucket_info
    }

    // ========================================================================
    // S3 Write
    // ========================================================================

    /// Write an init value to S3 under `init/{session_id}-{suffix}.json`.
    pub async fn write_init_with_suffix<T: Serialize>(
        &self,
        suffix: &str,
        value: &T,
        object_lock_duration: Duration,
    ) -> GuardianResult<()> {
        let key = format!("{}/{}-{}.json", S3_DIR_INIT, self.session_id, suffix);
        self.write_at_key(&key, value, object_lock_duration).await
    }

    /// Write values to S3 under
    /// `{prefix}/{yyyy}/{mm}/{dd}/{hh}/{session_id}-{suffix}.json`.
    pub async fn write_hour_partitioned_with_suffix<T: Serialize>(
        &self,
        prefix: &str,
        timestamp_ms: UnixMillis,
        suffix: &str,
        value: &T,
        object_lock_duration: Duration,
    ) -> GuardianResult<()> {
        let dir = S3Directory::new(prefix, timestamp_ms);
        let key = format!("{}/{}-{}.json", dir, self.session_id, suffix);
        self.write_at_key(&key, value, object_lock_duration).await
    }

    /// Write a value to S3 at an explicit key.
    ///
    /// This is intended for ordered log streams where the caller determines the key.
    async fn write_at_key<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        object_lock_duration: Duration,
    ) -> GuardianResult<()> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        info!("Logging to {}", key);

        let expiry_time = SystemTime::now()
            .checked_add(object_lock_duration)
            .expect("Cant overflow");

        let body = serde_json::to_string(value).expect("Cant serialize to JSON");
        info!("Log message: {}", body);

        // TODO(integration-test): Verify on a real S3 bucket with Object Lock enabled that an object written with `Compliance` + `retain_until` cannot be deleted/overwritten before expiry.
        let _result = s3_client
            .put_object()
            .bucket(s3_config.bucket_name())
            .key(key)
            .content_type("application/json")
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(expiry_time))
            .body(ByteStream::from(body.into_bytes()))
            .send()
            .await
            // DisplayErrorContext displays the full error returned by the SDK
            .map_err(|e| {
                S3Error(format!(
                    "Failed to write to s3: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        info!("Logged entry to immutable storage");
        info!("Object locked until: {:?}", expiry_time);
        info!(
            "Public URL: https://{}.s3.amazonaws.com/{}",
            s3_config.bucket_name(),
            key
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
            .bucket(s3_config.bucket_name())
            .send()
            .await;

        match bucket_config {
            Ok(config) => {
                let object_lock_config = config.object_lock_configuration().ok_or_else(|| {
                    S3Error("Object lock configuration missing in S3 response".into())
                })?;

                let object_lock_enabled_config =
                    object_lock_config.object_lock_enabled().ok_or_else(|| {
                        S3Error("Object lock enabled field missing in S3 response".into())
                    })?;

                match object_lock_enabled_config {
                    ObjectLockEnabled::Enabled => {
                        info!("Bucket {} has Object Lock enabled", s3_config.bucket_name());
                    }
                    other => {
                        return Err(S3Error(format!(
                            "Unexpected object lock enabled config: {:?}",
                            other
                        )))
                    }
                }
            }
            Err(e) => {
                return Err(S3Error(format!(
                    "Failed to verify Object Lock configuration: {}",
                    DisplayErrorContext(&e)
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
            .bucket(s3_config.bucket_name())
            .max_keys(10)
            .send()
            .await
            .map_err(|e| {
                S3Error(format!(
                    "Failed to list objects: {}",
                    DisplayErrorContext(&e)
                ))
            })?;

        let objects = bucket_objects.contents();

        if objects.is_empty() {
            info!(
                "Bucket {} has no objects (or no access to list)",
                s3_config.bucket_name()
            );
            return Ok(());
        }

        info!(
            "Bucket {}: listing {} object(s) (max 10)",
            s3_config.bucket_name(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;

    fn mk_logger_with_client(client: Client) -> S3Logger {
        let config = S3Config {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
            bucket_info: S3BucketInfo {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
            },
        };
        S3Logger::from_client_for_tests("session".to_string(), config, client)
    }

    #[derive(Serialize)]
    struct TestPayload {
        a: u64,
    }

    #[tokio::test]
    async fn test_mock_s3_logger_write() {
        let put_ok = mock!(Client::put_object)
            .match_requests(|req| {
                req.bucket() == Some("bucket")
                    && req.key() == Some("init/session-oi-attestation-unsigned.json")
                    && req.content_type() == Some("application/json")
                    && req.object_lock_mode() == Some(&ObjectLockMode::Compliance)
                    && req.object_lock_retain_until_date().is_some()
            })
            .then_output(|| PutObjectOutput::builder().build());

        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let logger = mk_logger_with_client(client);
        let object_lock_duration = Duration::from_mins(5);
        logger
            .write_init_with_suffix(
                "oi-attestation-unsigned",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .unwrap();
        assert_eq!(put_ok.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_write_retries_on_transient_failures() {
        // Two transient failures followed by success.
        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(503, None)
            .times(2)
            .output(|| PutObjectOutput::builder().build())
            .build();

        // Override retry attempts on the test client so the operation has enough attempts
        // to reach the success response.
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(RetryConfig::standard().with_max_attempts(3)));
        let logger = mk_logger_with_client(client);
        let object_lock_duration = Duration::from_mins(5);
        logger
            .write_init_with_suffix(
                "oi-attestation-unsigned",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .unwrap();
        assert_eq!(put_flaky.num_calls(), 3);
    }
}
