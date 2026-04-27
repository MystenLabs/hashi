// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::CredentialsBuilder;
use aws_sdk_s3::error::DisplayErrorContext;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Config;
use std::collections::BTreeSet;
use std::time::Duration;
use std::time::SystemTime;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::DateTime;
use aws_sdk_s3::types::ObjectLockEnabled;
use aws_sdk_s3::types::ObjectLockMode;
use aws_sdk_s3::Client as S3Client;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::Attestation;
use hashi_types::guardian::GuardianError::S3Error;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::VerifiedLogRecord;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tracing::info;

const MAX_RETRY_ATTEMPTS: u32 = 5;

#[derive(Clone)]
pub struct S3Logger {
    /// S3 config: bucket name, region, API keys
    config: S3Config,
    /// S3 client
    client: S3Client,
}

impl S3Logger {
    // ========================================================================
    // Constructors
    // ========================================================================

    pub async fn new(config: &S3Config) -> Self {
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

        // Path-style addressing (required by MinIO) has no SDK env, so read it explicitly.
        let mut s3_builder = aws_sdk_s3::config::Builder::from(&aws_config);
        if std::env::var("AWS_S3_FORCE_PATH_STYLE")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1"))
            .unwrap_or(false)
        {
            s3_builder = s3_builder.force_path_style(true);
        }
        let client = S3Client::from_conf(s3_builder.build());

        Self {
            client,
            config: config.clone(),
        }
    }

    pub async fn new_checked(config: &S3Config) -> GuardianResult<Self> {
        let logger = Self::new(config).await;
        logger.test_s3_connectivity().await?;
        Ok(logger)
    }

    /// Construct an `S3Logger` from an already-configured S3 client.
    /// This is intended for unit tests that use a mock S3 Client.
    /// This is not put behind cfg(test) as tests in the enclave crate also use it.
    pub fn from_client_for_tests(config: S3Config, client: S3Client) -> Self {
        Self { client, config }
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

    pub async fn write_log_record(&self, log: LogRecord) -> GuardianResult<()> {
        let object_lock_duration = log.object_lock_duration();
        let key = log.object_key();
        self.write_at_key(&key, &log, object_lock_duration).await
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
    pub async fn list_objects_sample(&self) -> GuardianResult<()> {
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

    // ========================================================================
    // S3 Reads
    // ========================================================================

    /// Checks that all matching object keys do not have either deletions or overwrites.
    /// The prefix can either correspond to a directory or a complete object key.
    ///
    /// Returns: list of keys.
    async fn ensure_no_duplicates_or_deletions(&self, prefix: &str) -> GuardianResult<Vec<String>> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        let mut key_marker: Option<String> = None;
        let mut version_id_marker: Option<String> = None;
        let mut seen_keys: BTreeSet<String> = BTreeSet::new();

        loop {
            let mut req = s3_client
                .list_object_versions()
                .bucket(s3_config.bucket_name())
                .prefix(prefix);
            if let Some(ref marker) = key_marker {
                req = req.key_marker(marker);
            }
            if let Some(ref marker) = version_id_marker {
                req = req.version_id_marker(marker);
            }

            let response = req.send().await.map_err(|e| {
                S3Error(format!(
                    "Failed to list object versions for prefix {}: {}",
                    prefix,
                    DisplayErrorContext(&e)
                ))
            })?;

            if !response.delete_markers().is_empty() {
                return Err(S3Error(format!(
                    "Delete marker found under prefix {}",
                    prefix
                )));
            }

            // https://docs.aws.amazon.com/AmazonS3/latest/API/API_ObjectVersion.html
            for version in response.versions() {
                let key = version.key().ok_or_else(|| {
                    S3Error("Missing key in list_object_versions response".into())
                })?;

                // NOTE: If an object's lock expires, then all bets are off.
                // For example, is_latest could be true even though an older version of it was deleted (post lock expiry).
                if version.is_latest() != Some(true) {
                    return Err(S3Error(format!(
                        "Non-latest version found for key {} under prefix {}",
                        key, prefix
                    )));
                }

                if !seen_keys.insert(key.to_string()) {
                    // this check is redundant as we ensure is_latest = true above
                    return Err(S3Error(format!(
                        "Duplicate version found for key {} under prefix {}",
                        key, prefix
                    )));
                }
            }

            if response.is_truncated() != Some(true) {
                break;
            }

            key_marker = response.next_key_marker().map(ToString::to_string);
            version_id_marker = response.next_version_id_marker().map(ToString::to_string);

            if key_marker.is_none() {
                return Err(S3Error(format!(
                    "Truncated response but no next_key_marker for prefix {}",
                    prefix
                )));
            }
        }

        Ok(seen_keys.into_iter().collect())
    }

    /// Batch read. Callers must ensure that all objects with prefix `dir.to_string()` have
    /// unexpired compliance-mode object locks.
    ///
    /// Returns: List of objects.
    pub async fn list_all_objects_in_dir<T: DeserializeOwned>(
        &self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<T>> {
        let prefix = dir.to_string();
        let keys = self.ensure_no_duplicates_or_deletions(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in &keys {
            let obj: T = self.get_object_unsafe(key).await?;
            out.push(obj);
        }
        Ok(out)
    }

    /// Point read. This method is unsafe to use since the bucket operator might've overwritten objects.
    async fn get_object_unsafe<T: DeserializeOwned>(&self, key: &str) -> GuardianResult<T> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        let response = s3_client
            .get_object()
            .bucket(s3_config.bucket_name())
            .key(key)
            .send()
            .await
            .map_err(|e| {
                S3Error(format!(
                    "Failed to get object {}: {}",
                    key,
                    DisplayErrorContext(&e)
                ))
            })?;

        // NOTE: Here we are explicitly assuming locks are unexpired.
        if response.object_lock_mode() != Some(&ObjectLockMode::Compliance)
            || response.object_lock_retain_until_date().is_none()
        {
            return Err(S3Error(format!(
                "Missing or invalid object lock metadata for key {}",
                key
            )));
        }

        let bytes = response.body.collect().await.map_err(|e| {
            S3Error(format!(
                "Failed to read object body for key {}: {}",
                key,
                DisplayErrorContext(&e)
            ))
        })?;

        serde_json::from_slice::<T>(&bytes.into_bytes()).map_err(|e| {
            S3Error(format!(
                "Failed to deserialize object {} into target type: {}",
                key, e
            ))
        })
    }

    /// Caller must ensure that the object has unexpired compliance-mode object lock.
    pub async fn get_object<T: DeserializeOwned>(&self, key: &str) -> GuardianResult<T> {
        let keys = self.ensure_no_duplicates_or_deletions(key).await?;
        if keys.len() != 1 || keys[0] != key {
            return Err(S3Error(format!(
                "expected exactly one object for key {}, found {:?}",
                key, keys
            )));
        }

        self.get_object_unsafe::<T>(key).await
    }

    /// Note: Callers must set signing_pubkey to None only for unsigned messages.
    pub async fn get_verified_log_record(
        &self,
        key: &str,
        expected_session_id: &str,
        signing_pubkey: Option<&GuardianPubKey>,
    ) -> GuardianResult<VerifiedLogRecord> {
        let log = self.get_object::<LogRecord>(key).await?;
        if log.session_id != expected_session_id {
            return Err(S3Error(format!("log session_id mismatch for key {}", key)));
        }
        match signing_pubkey {
            Some(pk) => log.verify(pk),
            None => log.verify_unsigned(),
        }
    }

    pub async fn get_attestation(
        &self,
        session_id: &str,
    ) -> GuardianResult<(Attestation, GuardianPubKey)> {
        let key = InitLogMessage::attestation_object_key(session_id);
        self.get_verified_log_record(&key, session_id, None)
            .await?
            .message
            .into_init_log()
            .and_then(|x| match x {
                InitLogMessage::OIAttestationUnsigned {
                    attestation,
                    signing_public_key,
                } => Some((attestation, signing_public_key)),
                _ => None,
            })
            .ok_or_else(|| S3Error(format!("expected OIAttestationUnsigned at key {}", key)))
    }

    pub async fn get_guardian_info(
        &self,
        session_id: &str,
        signing_pubkey: &GuardianPubKey,
    ) -> GuardianResult<GuardianInfo> {
        let key = InitLogMessage::guardian_info_object_key(session_id);
        self.get_verified_log_record(&key, session_id, Some(signing_pubkey))
            .await?
            .message
            .into_init_log()
            .and_then(|x| match x {
                InitLogMessage::OIGuardianInfo(info) => Some(info),
                _ => None,
            })
            .ok_or_else(|| S3Error(format!("expected OIGuardianInfo at key {}", key)))
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
        S3Logger::from_client_for_tests(config, client)
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
            .write_at_key(
                "init/session-oi-attestation-unsigned.json",
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
            .write_at_key(
                "init/session-oi-attestation-unsigned.json",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .unwrap();
        assert_eq!(put_flaky.num_calls(), 3);
    }
}
