// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use aws_credential_types::provider::ProvideCredentials;
use aws_credential_types::provider::SharedCredentialsProvider;
use aws_credential_types::CredentialsBuilder;
use aws_sdk_s3::error::DisplayErrorContext;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::ResolvedS3Config;
use hashi_types::guardian::S3BucketInfo;
use hashi_types::guardian::S3Credentials;
use hashi_types::guardian::S3ObjectLockPolicy;
use hashi_types::guardian::UnresolvedS3Config;
use std::collections::BTreeSet;
use std::sync::Once;
use std::time::Duration;
use std::time::SystemTime;

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::primitives::DateTime;
use aws_sdk_s3::types::ObjectLockEnabled;
use aws_sdk_s3::types::ObjectLockMode;
use aws_sdk_s3::Client as S3Client;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianError::S3Error;
use hashi_types::guardian::GuardianResult;
use serde::Serialize;
use tracing::info;
use tracing::warn;

/// Maximum attempts the AWS SDK makes for reads and control-plane operations.
/// Log PUTs override this because the Guardian log writer owns their retries.
const MAX_RETRY_ATTEMPTS: u32 = 5;
// TODO(testnet-wipe): Remove this escape hatch after the planned testnet wipe.
/// Temporary testnet escape hatch for logs whose legacy seven-day locks expired.
const SKIP_S3_OBJECT_LOCK_CHECK_ENV: &str = "HASHI_SKIP_S3_OBJECT_LOCK_CHECK";
static SKIP_S3_OBJECT_LOCK_CHECK_WARNING: Once = Once::new();

/// Resolve explicit credentials or, when both are omitted, use AWS's default
/// provider chain.
pub async fn resolve_s3_config(config: &UnresolvedS3Config) -> anyhow::Result<ResolvedS3Config> {
    let access_key = config
        .access_key
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    let secret_key = config
        .secret_key
        .as_deref()
        .filter(|value| !value.trim().is_empty());

    let (access_key, secret_key, session_token) = match (access_key, secret_key) {
        (Some(access_key), Some(secret_key)) => {
            (access_key.to_string(), secret_key.to_string(), None)
        }
        (None, None) => {
            let provider =
                aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
                    .build()
                    .await;
            let credentials = provider
                .provide_credentials()
                .await
                .context("failed to resolve AWS credentials from the default provider chain")?;
            (
                credentials.access_key_id().to_string(),
                credentials.secret_access_key().to_string(),
                credentials.session_token().map(ToOwned::to_owned),
            )
        }
        _ => anyhow::bail!(
            "guardian_s3 access_key and secret_key must either both be set or both be omitted"
        ),
    };

    Ok(ResolvedS3Config {
        credentials: S3Credentials {
            access_key,
            secret_key,
            session_token,
        },
        bucket_info: config.bucket_info.clone(),
        retention_environment: config.retention_environment,
    })
}

#[derive(Clone)]
pub struct GuardianS3Client {
    /// S3 connection and retention config.
    config: ResolvedS3Config,
    /// S3 client
    client: S3Client,
    /// Expected object-lock policy for this Guardian deployment.
    object_lock_policy: S3ObjectLockPolicy,
}

impl GuardianS3Client {
    // ========================================================================
    // Constructors
    // ========================================================================

    pub async fn new(config: &ResolvedS3Config) -> Self {
        info!("S3 Configuration:");
        info!("   Bucket: {}", config.bucket_name());
        info!("   Region: {}", config.region());

        let mut creds = CredentialsBuilder::default()
            .access_key_id(config.credentials.access_key.clone())
            .secret_access_key(config.credentials.secret_key.clone())
            .provider_name("hashi-guardian");
        creds.set_session_token(config.credentials.session_token.clone());
        let creds = creds.build();

        let retry_config = RetryConfig::standard().with_max_attempts(MAX_RETRY_ATTEMPTS); // default is 3

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region().to_string()))
            .credentials_provider(SharedCredentialsProvider::new(creds))
            .retry_config(retry_config)
            .load()
            .await;

        // A custom endpoint implies an S3-compatible service (MinIO, LocalStack), which
        // need path-style addressing.
        let mut s3_builder = aws_sdk_s3::config::Builder::from(&aws_config);
        if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
            s3_builder = s3_builder.force_path_style(true);
        }
        let client = S3Client::from_conf(s3_builder.build());

        Self {
            client,
            config: config.clone(),
            object_lock_policy: S3ObjectLockPolicy::for_environment(config.retention_environment),
        }
    }

    pub async fn new_checked(config: &ResolvedS3Config) -> GuardianResult<Self> {
        let logger = Self::new(config).await;
        logger.test_s3_connectivity().await?;
        Ok(logger)
    }

    /// Construct an `GuardianS3Client` from an already-configured S3 client.
    /// This is intended for unit tests that use a mock S3 Client.
    /// This is not put behind cfg(test) as tests in the enclave crate also use it.
    pub fn from_client_for_tests(config: ResolvedS3Config, client: S3Client) -> Self {
        let object_lock_policy = S3ObjectLockPolicy::for_environment(config.retention_environment);
        Self {
            client,
            config,
            object_lock_policy,
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

    /// Attempt one immutable log PUT. The Guardian log writer owns retries and
    /// deadlines, so SDK retries are disabled for this operation.
    pub(crate) async fn write_log_record_once(&self, log: &LogRecord) -> GuardianResult<()> {
        let key = log.object_key();
        let object_lock_duration = self.object_lock_duration(log);
        self.write_at_key_once(key, log, object_lock_duration).await
    }

    fn object_lock_duration(&self, log: &LogRecord) -> Duration {
        log.object_lock_duration(self.object_lock_policy)
    }

    /// Write a value to S3 at an explicit key.
    ///
    /// This is intended for ordered log streams where the caller determines the key.
    async fn write_at_key_once<T: Serialize>(
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

        let body = serde_json::to_vec(value).expect("Cant serialize to JSON");

        // `If-None-Match: *` makes retries safe: a lost-ack write that already
        // landed returns 412 instead of creating another version. A 412 is only
        // success if the existing immutable object is exactly this record.
        let result = s3_client
            .put_object()
            .bucket(s3_config.bucket_name())
            .key(key)
            .content_type("application/json")
            .object_lock_mode(ObjectLockMode::Compliance)
            .object_lock_retain_until_date(DateTime::from(expiry_time))
            .if_none_match("*")
            .body(ByteStream::from(body.clone()))
            .customize()
            .config_override(
                aws_sdk_s3::config::Builder::new().retry_config(RetryConfig::disabled()),
            )
            .send()
            .await;
        if let Err(e) = result {
            let already_written = e
                .raw_response()
                .is_some_and(|resp| resp.status().as_u16() == 412);
            if !already_written {
                // DisplayErrorContext displays the full error returned by the SDK
                return Err(S3Error(format!(
                    "Failed to write to s3: {}",
                    DisplayErrorContext(&e)
                )));
            }
            self.verify_existing_write(key, &body).await?;
            info!("Object {} already contains the intended record", key);
        }

        info!("Logged entry to immutable storage");
        info!("Object locked until: {:?}", expiry_time);
        info!(
            "Public URL: https://{}.s3.amazonaws.com/{}",
            s3_config.bucket_name(),
            key
        );

        Ok(())
    }

    /// Similar to `get_object_unsafe`, but compares the raw bytes and treats
    /// invalid lock metadata as a fatal conflict at this write-once key.
    async fn verify_existing_write(&self, key: &str, expected_body: &[u8]) -> GuardianResult<()> {
        let response = self
            .client
            .get_object()
            .bucket(self.config.bucket_name())
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
        let has_compliance_lock = response.object_lock_mode() == Some(&ObjectLockMode::Compliance)
            && response.object_lock_retain_until_date().is_some();
        let actual_body = response.body.collect().await.map_err(|e| {
            S3Error(format!(
                "Failed to read object body for key {}: {}",
                key,
                DisplayErrorContext(&e)
            ))
        })?;

        if actual_body.into_bytes().as_ref() != expected_body {
            // A 412 revealed different content at this write-once key. Retrying
            // cannot replace it, so continuing would violate log durability.
            panic!("existing object {key} differs from the intended record");
        }
        if !has_compliance_lock {
            // The intended record exists but is not immutable. Retrying cannot
            // replace it, so it cannot satisfy the durable-write requirement.
            panic!("existing object {key} is missing a valid compliance lock");
        }

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
}

/// Controls whether an S3 read establishes that the object is still immutable.
#[derive(Clone, Copy)]
pub(crate) enum ImmutabilityCheck {
    /// Validate the exact key has no mutation history and reject the object
    /// unless its Compliance lock is still unexpired, except when the
    /// process-wide temporary testnet override is set.
    Required,
    /// The caller already validated the enclosing prefix has no mutations;
    /// still reject the object unless its Compliance lock is unexpired, except
    /// when the process-wide temporary testnet override is set.
    MutationAlreadyChecked,
    /// Do not claim S3 immutability. Used for signed records whose short locks
    /// are expected to expire, such as KP-share state.
    Skipped,
}

impl GuardianS3Client {
    // ========================================================================
    // S3 Reads
    // ========================================================================

    /// Lists immediate subdirectories under `prefix` (S3 `CommonPrefixes`,
    /// returned by `list_objects_v2` with `delimiter='/'`). Used to tree-walk
    /// the hour-partitioned withdraw layout (`withdraw/YYYY/MM/DD/HH/`)
    /// without paginating every object key. Returned prefixes are unique and
    /// sorted lexicographically.
    pub async fn list_common_prefixes(&self, prefix: &str) -> GuardianResult<Vec<String>> {
        let mut continuation_token: Option<String> = None;
        let mut out: BTreeSet<String> = BTreeSet::new();
        loop {
            let mut req = self
                .client
                .list_objects_v2()
                .bucket(self.config.bucket_name())
                .prefix(prefix)
                .delimiter("/");
            if let Some(ref token) = continuation_token {
                req = req.continuation_token(token);
            }
            let response = req.send().await.map_err(|e| {
                S3Error(format!(
                    "Failed to list common prefixes under {}: {}",
                    prefix,
                    DisplayErrorContext(&e)
                ))
            })?;
            for cp in response.common_prefixes() {
                if let Some(p) = cp.prefix() {
                    out.insert(p.to_string());
                }
            }
            if response.is_truncated() != Some(true) {
                break;
            }
            let Some(token) = response.next_continuation_token() else {
                return Err(S3Error(format!(
                    "Truncated response but no next_continuation_token for prefix {}",
                    prefix
                )));
            };
            continuation_token = Some(token.to_string());
        }
        Ok(out.into_iter().collect())
    }

    /// Lists the currently visible keys under `prefix` using S3 version
    /// history. When `reject_mutations` is true, any overwrite or deletion is
    /// rejected; otherwise it is logged and only the latest visible versions
    /// are returned. Mutation validation establishes immutability only when
    /// each selected object also has an unexpired lock.
    pub(crate) async fn list_keys(
        &self,
        prefix: &str,
        reject_mutations: bool,
    ) -> GuardianResult<Vec<String>> {
        let s3_client = &self.client;
        let s3_config = &self.config;

        let mut key_marker: Option<String> = None;
        let mut version_id_marker: Option<String> = None;
        let mut seen_keys: BTreeSet<String> = BTreeSet::new();
        let mut found_mutation = false;

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
                if reject_mutations {
                    return Err(S3Error(format!(
                        "Delete marker found under prefix {}",
                        prefix
                    )));
                }
                found_mutation = true;
            }

            // https://docs.aws.amazon.com/AmazonS3/latest/API/API_ObjectVersion.html
            for version in response.versions() {
                let key = version.key().ok_or_else(|| {
                    S3Error("Missing key in list_object_versions response".into())
                })?;

                // NOTE: If an object's lock expires, then all bets are off.
                // For example, is_latest could be true even though an older version of it was deleted (post lock expiry).
                if version.is_latest() != Some(true) {
                    if reject_mutations {
                        return Err(S3Error(format!(
                            "Non-latest version found for key {} under prefix {}",
                            key, prefix
                        )));
                    }
                    found_mutation = true;
                    continue;
                }

                if !seen_keys.insert(key.to_string()) {
                    if reject_mutations {
                        // This check is redundant as we ensure is_latest = true above.
                        return Err(S3Error(format!(
                            "Duplicate version found for key {} under prefix {}",
                            key, prefix
                        )));
                    }
                    found_mutation = true;
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

        if found_mutation {
            warn!(
                prefix,
                "S3 object mutation found; continuing because mutation rejection is disabled"
            );
        }
        Ok(seen_keys.into_iter().collect())
    }

    /// Batch read with prefix-history and object-lock validation. The temporary
    /// process-wide testnet override skips only the object-lock validation.
    ///
    /// Each returned record's signed object key is checked against the actual
    /// S3 key from which it was read.
    pub async fn list_all_log_records_in_dir(
        &self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<LogRecord>> {
        let prefix = dir.to_string();
        self.list_all_log_records_with_prefix(&prefix).await
    }

    /// Batch read all immutable log records whose keys begin with `prefix`.
    /// The prefix history is validated before any records are fetched.
    pub(crate) async fn list_all_log_records_with_prefix(
        &self,
        prefix: &str,
    ) -> GuardianResult<Vec<LogRecord>> {
        let keys = self.list_keys(prefix, true).await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // The prefix history was checked above. Immutable batch logs also
            // require an unexpired Compliance lock unless the temporary
            // process-wide testnet override is set.
            out.push(
                self.get_log_record_inner(&key, ImmutabilityCheck::MutationAlreadyChecked)
                    .await?,
            );
        }
        Ok(out)
    }

    /// Fetches and deserializes a record with the requested S3 immutability
    /// policy, always rejecting a mismatch between its signed intended key and
    /// the actual S3 key. `ImmutabilityCheck::MutationAlreadyChecked` requires
    /// the caller to have validated the key's enclosing prefix.
    pub(crate) async fn get_log_record_inner(
        &self,
        key: &str,
        immutability_check: ImmutabilityCheck,
    ) -> GuardianResult<LogRecord> {
        if matches!(immutability_check, ImmutabilityCheck::Required) {
            let keys = self.list_keys(key, true).await?;
            if keys.len() != 1 || keys[0] != key {
                return Err(S3Error(format!(
                    "expected exactly one object for key {}, found {:?}",
                    key, keys
                )));
            }
        }

        let response = self
            .client
            .get_object()
            .bucket(self.config.bucket_name())
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

        if !matches!(immutability_check, ImmutabilityCheck::Skipped)
            && !skip_s3_object_lock_check()
            && !has_unexpired_compliance_lock(
                response.object_lock_mode(),
                response.object_lock_retain_until_date(),
                SystemTime::now(),
            )
        {
            return Err(S3Error(format!(
                "Missing, invalid, or expired object lock metadata for key {}",
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

        let record = serde_json::from_slice::<LogRecord>(&bytes.into_bytes()).map_err(|e| {
            InvalidS3Log(format!(
                "Failed to deserialize object {} into target type: {}",
                key, e
            ))
        })?;
        if record.object_key() != key {
            return Err(InvalidS3Log(format!(
                "S3 object key mismatch: record contains {}, actual key is {key}",
                record.object_key()
            )));
        }
        Ok(record)
    }

    /// Read an immutable-log object with history and Compliance-lock checks.
    /// The temporary process-wide testnet override skips only the lock check.
    pub(crate) async fn get_log_record(&self, key: &str) -> GuardianResult<LogRecord> {
        self.get_log_record_inner(key, ImmutabilityCheck::Required)
            .await
    }
}

// TODO(testnet-wipe): Once legacy seven-day logs are gone, also verify that the
// retain-until date covers the record timestamp plus this log type's duration
// from `object_lock_policy`.
fn has_unexpired_compliance_lock(
    mode: Option<&ObjectLockMode>,
    retain_until: Option<&DateTime>,
    now: SystemTime,
) -> bool {
    mode == Some(&ObjectLockMode::Compliance)
        && retain_until.is_some_and(|retain_until| *retain_until > DateTime::from(now))
}

fn skip_s3_object_lock_check() -> bool {
    let skip = std::env::var_os(SKIP_S3_OBJECT_LOCK_CHECK_ENV).is_some();
    if skip {
        SKIP_S3_OBJECT_LOCK_CHECK_WARNING.call_once(|| {
            warn!(
                env = SKIP_S3_OBJECT_LOCK_CHECK_ENV,
                "S3 object-lock validation is disabled for this process"
            );
        });
    }
    skip
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::HeartbeatLogMessage;
    use hashi_types::guardian::InitLogMessage;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::NitroAttestation;
    use hashi_types::guardian::SessionID;

    fn mk_logger_with_client(client: Client) -> GuardianS3Client {
        let config = ResolvedS3Config {
            credentials: S3Credentials {
                access_key: "test-access-key".to_string(),
                secret_key: "test-secret-key".to_string(),
                session_token: None,
            },
            bucket_info: S3BucketInfo {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
            },
            retention_environment: hashi_types::guardian::S3RetentionEnvironment::Testnet,
        };
        GuardianS3Client::from_client_for_tests(config, client)
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
                    && req.key() == Some("init/session/01-oi-attestation-unsigned.json")
                    && req.content_type() == Some("application/json")
                    && req.object_lock_mode() == Some(&ObjectLockMode::Compliance)
                    && req.object_lock_retain_until_date().is_some()
                    && req.if_none_match() == Some("*")
            })
            .then_output(|| PutObjectOutput::builder().build());

        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
        let logger = mk_logger_with_client(client);
        let object_lock_duration = Duration::from_mins(5);
        logger
            .write_at_key_once(
                "init/session/01-oi-attestation-unsigned.json",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .unwrap();
        assert_eq!(put_ok.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_412_accepts_identical_locked_object() {
        let put_precondition_failed = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(412, None)
            .build();
        let get_existing = mock!(Client::get_object)
            .match_requests(|req| req.bucket() == Some("bucket") && req.key() == Some("key"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from(
                        SystemTime::now() + Duration::from_mins(5),
                    ))
                    .body(ByteStream::from_static(br#"{"a":1}"#))
                    .build()
            });

        let client = mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            &[&put_precondition_failed, &get_existing],
            |builder| builder.retry_config(RetryConfig::standard().with_max_attempts(1))
        );
        let logger = mk_logger_with_client(client);
        logger
            .write_at_key_once("key", &TestPayload { a: 1 }, Duration::from_mins(5))
            .await
            .unwrap();

        assert_eq!(put_precondition_failed.num_calls(), 1);
        assert_eq!(get_existing.num_calls(), 1);
    }

    #[tokio::test]
    #[should_panic(expected = "differs from the intended record")]
    async fn test_412_mismatch_panics() {
        let put_precondition_failed = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(412, None)
            .build();
        let get_existing = mock!(Client::get_object)
            .match_requests(|req| req.bucket() == Some("bucket") && req.key() == Some("key"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(br#"{"a":2}"#))
                    .build()
            });

        let client = mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            &[&put_precondition_failed, &get_existing],
            |builder| builder.retry_config(RetryConfig::standard().with_max_attempts(1))
        );
        let logger = mk_logger_with_client(client);
        logger
            .write_at_key_once("key", &TestPayload { a: 1 }, Duration::from_mins(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "is missing a valid compliance lock")]
    async fn test_412_identical_unlocked_object_panics() {
        let put_precondition_failed = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(412, None)
            .build();
        let get_existing = mock!(Client::get_object)
            .match_requests(|req| req.bucket() == Some("bucket") && req.key() == Some("key"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(br#"{"a":1}"#))
                    .build()
            });

        let client = mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            &[&put_precondition_failed, &get_existing],
            |builder| builder.retry_config(RetryConfig::standard().with_max_attempts(1))
        );
        let logger = mk_logger_with_client(client);
        logger
            .write_at_key_once("key", &TestPayload { a: 1 }, Duration::from_mins(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn log_put_disables_sdk_retries() {
        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(503, None)
            .times(2)
            .output(|| PutObjectOutput::builder().build())
            .build();

        // The client would retry three times, but log PUTs override that policy
        // so the serialized writer is the only retry controller.
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(RetryConfig::standard().with_max_attempts(3)));
        let logger = mk_logger_with_client(client);
        let object_lock_duration = Duration::from_mins(5);
        let error = logger
            .write_at_key_once(
                "init/session/01-oi-attestation-unsigned.json",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .expect_err("one PUT failure must be returned to the log writer");

        assert!(matches!(error, S3Error(_)));
        assert_eq!(put_flaky.num_calls(), 1);
    }

    #[test]
    fn compliance_lock_expiry_is_strict() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let expired = DateTime::from(now - Duration::from_secs(1));
        let expires_now = DateTime::from(now);
        let unexpired = DateTime::from(now + Duration::from_secs(1));

        assert!(!has_unexpired_compliance_lock(
            Some(&ObjectLockMode::Compliance),
            Some(&expired),
            now,
        ));
        assert!(!has_unexpired_compliance_lock(
            Some(&ObjectLockMode::Compliance),
            Some(&expires_now),
            now,
        ));
        assert!(has_unexpired_compliance_lock(
            Some(&ObjectLockMode::Compliance),
            Some(&unexpired),
            now,
        ));
    }

    #[tokio::test]
    async fn required_read_rejects_expired_compliance_lock() {
        let get_expired = mock!(Client::get_object)
            .match_requests(|req| req.bucket() == Some("bucket") && req.key() == Some("key"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .object_lock_mode(ObjectLockMode::Compliance)
                    .object_lock_retain_until_date(DateTime::from(
                        SystemTime::now() - Duration::from_secs(1),
                    ))
                    .body(ByteStream::from_static(b"not read"))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&get_expired]);
        let logger = mk_logger_with_client(client);

        let error = logger
            .get_log_record_inner("key", ImmutabilityCheck::MutationAlreadyChecked)
            .await
            .expect_err("an expired required lock must be rejected");

        assert!(
            matches!(error, S3Error(message) if message.contains("expired object lock metadata"))
        );
        assert_eq!(get_expired.num_calls(), 1);
    }

    #[tokio::test]
    async fn unsigned_log_replay_is_rejected_during_deserialization() {
        let signing_key = GuardianSignKeyPair::from([14u8; 32]);
        let session_id = SessionID::from_signing_pubkey(&signing_key.verification_key());
        let record = LogRecord::new_at_timestamp(
            session_id,
            LogMessage::Init(Box::new(InitLogMessage::OIAttestationUnsigned {
                attestation: NitroAttestation::new(vec![1, 2, 3]),
                signing_public_key: signing_key.verification_key(),
            })),
            &signing_key,
            1_700_000_000_000,
        );
        let mut record_json = serde_json::to_value(record).unwrap();
        record_json["object_key"] = "init/copied-attestation.json".into();
        let body = serde_json::to_vec(&record_json).unwrap();
        let get_copied = mock!(Client::get_object)
            .match_requests(|req| {
                req.bucket() == Some("bucket") && req.key() == Some("init/copied-attestation.json")
            })
            .then_output(move || {
                GetObjectOutput::builder()
                    .body(ByteStream::from(body.clone()))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&get_copied]);
        let logger = mk_logger_with_client(client);

        let error = logger
            .get_log_record_inner("init/copied-attestation.json", ImmutabilityCheck::Skipped)
            .await
            .expect_err("the copied key must fail canonical validation during deserialization");

        assert!(
            matches!(error, InvalidS3Log(message) if message.contains("non-canonical S3 object key"))
        );
        assert_eq!(get_copied.num_calls(), 1);
    }

    async fn assert_log_read_rejects_relocation(relocated_key: &str) {
        let signing_key = GuardianSignKeyPair::from([13u8; 32]);
        let record = LogRecord::new_at_timestamp(
            "session".into(),
            LogMessage::Heartbeat(HeartbeatLogMessage::new(42)),
            &signing_key,
            1_700_000_000_000,
        );
        let intended_key = record.object_key().to_string();
        let body = serde_json::to_vec(&record).unwrap();
        let relocated_key = relocated_key.to_string();
        let mock_key = relocated_key.clone();
        let get_relocated = mock!(Client::get_object)
            .match_requests(move |req| {
                req.bucket() == Some("bucket") && req.key() == Some(mock_key.as_str())
            })
            .then_output(move || {
                GetObjectOutput::builder()
                    .body(ByteStream::from(body.clone()))
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&get_relocated]);
        let logger = mk_logger_with_client(client);

        let error = logger
            .get_log_record_inner(&relocated_key, ImmutabilityCheck::Skipped)
            .await
            .expect_err("a relocated record must be rejected");

        assert!(matches!(
            error,
            InvalidS3Log(message)
                if message == format!(
                    "S3 object key mismatch: record contains {intended_key}, actual key is {relocated_key}"
                )
        ));
        assert_eq!(get_relocated.num_calls(), 1);
    }

    #[tokio::test]
    async fn signed_log_rejects_cross_prefix_relocation() {
        assert_log_read_rejects_relocation(
            "withdraw/2023/11/14/22/session-00000000000000000042.json",
        )
        .await;
    }

    #[tokio::test]
    async fn signed_log_rejects_lexicographically_higher_key_relocation() {
        assert_log_read_rejects_relocation(
            "heartbeat/2023/11/14/22/session-00000000000000000043.json",
        )
        .await;
    }

    #[tokio::test]
    async fn signed_log_rejects_future_hour_relocation() {
        assert_log_read_rejects_relocation(
            "heartbeat/2023/11/14/23/session-00000000000000000042.json",
        )
        .await;
    }

    #[tokio::test]
    async fn signed_log_rejects_changed_session_relocation() {
        assert_log_read_rejects_relocation(
            "heartbeat/2023/11/14/22/aliased-session-00000000000000000042.json",
        )
        .await;
    }
}
