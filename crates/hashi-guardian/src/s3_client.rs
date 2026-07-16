// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::MAX_S3_WRITE_FAILURE_INTERVAL;
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
use hashi_types::guardian::GuardianError::S3Error;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::VerifiedSessionInfo;
use serde::Serialize;
use tracing::info;
use tracing::warn;

/// Maximum attempts the AWS SDK makes before returning one write failure.
const MAX_RETRY_ATTEMPTS: u32 = 5;
/// Delay between application-level retries of an immutable S3 log write.
const S3_WRITE_RETRY_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct GuardianS3Client {
    /// S3 config: bucket name, region, API keys
    config: S3Config,
    /// S3 client
    client: S3Client,
}

impl GuardianS3Client {
    // ========================================================================
    // Constructors
    // ========================================================================

    pub async fn new(config: &S3Config) -> Self {
        info!("S3 Configuration:");
        info!("   Bucket: {}", config.bucket_name());
        info!("   Region: {}", config.region());

        let mut creds = CredentialsBuilder::default()
            .access_key_id(config.access_key.clone())
            .secret_access_key(config.secret_key.clone())
            .provider_name("hashi-guardian");
        creds.set_session_token(config.session_token.clone());
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
        }
    }

    pub async fn new_checked(config: &S3Config) -> GuardianResult<Self> {
        let logger = Self::new(config).await;
        logger.test_s3_connectivity().await?;
        Ok(logger)
    }

    /// Construct an `GuardianS3Client` from an already-configured S3 client.
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

    /// Attempt one immutable log write, relying on the AWS SDK retry policy.
    pub async fn write_log_record(&self, log: LogRecord) -> GuardianResult<()> {
        let key = log.object_key().to_string();
        let object_lock_duration = log.object_lock_duration();
        self.write_at_key(&key, &log, object_lock_duration).await
    }

    /// Retry an immutable log write through the grace period, then abort. The
    /// worker is detached so caller cancellation cannot abandon an in-flight PUT.
    pub async fn write_log_record_or_abort(&self, log: LogRecord) -> GuardianResult<()> {
        let writer = self.clone();
        tokio::spawn(async move {
            writer
                .write_log_record_or_abort_inner(
                    log,
                    MAX_S3_WRITE_FAILURE_INTERVAL,
                    S3_WRITE_RETRY_INTERVAL,
                )
                .await
        })
        .await
        .expect("S3 log writer task failed")
    }

    async fn write_log_record_or_abort_inner(
        &self,
        log: LogRecord,
        max_failure_interval: Duration,
        retry_interval: Duration,
    ) -> GuardianResult<()> {
        let object_lock_duration = log.object_lock_duration();
        let key = log.object_key();
        let write_until_success = async {
            loop {
                match self.write_at_key(key, &log, object_lock_duration).await {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        warn!(%key, ?error, "S3 log write failed; retrying");
                        tokio::time::sleep(retry_interval).await;
                    }
                }
            }
        };

        match tokio::time::timeout(max_failure_interval, write_until_success).await {
            Ok(result) => result,
            Err(_) => panic!(
                "S3 log {} was not written within {:?}",
                key, max_failure_interval
            ),
        }
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

/// Controls whether an S3 read requires Compliance-mode object-lock metadata.
pub(crate) enum LockCheck {
    /// Reject the object unless Compliance lock metadata is present.
    Required,
    /// Do not inspect lock metadata. Used for signed records whose short lock
    /// is expected to expire, such as KP-share state.
    Skipped,
}

/// Controls whether an S3 read validates that the key has no overwrite or
/// deletion history.
pub(crate) enum HistoryCheck {
    /// Validate the exact key's history before fetching it.
    Required,
    /// The caller already validated the history of the enclosing prefix.
    AlreadyChecked,
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

    /// Lists every key under `prefix`, refusing to proceed if any matching
    /// object has a delete marker or non-latest version. The prefix may be a
    /// directory or a complete object key. Returned keys are unique and sorted.
    pub async fn validate_prefix_history_and_list_keys(
        &self,
        prefix: &str,
    ) -> GuardianResult<Vec<String>> {
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
    /// Each returned record's signed object key is checked against the actual
    /// S3 key from which it was read.
    pub async fn list_all_log_records_in_dir(
        &self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<LogRecord>> {
        let prefix = dir.to_string();
        let keys = self.validate_prefix_history_and_list_keys(&prefix).await?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // The prefix history was checked above. Immutable batch logs are
            // also expected to remain under Compliance lock.
            out.push(
                self.get_log_record_inner(&key, LockCheck::Required, HistoryCheck::AlreadyChecked)
                    .await?,
            );
        }
        Ok(out)
    }

    /// Fetches and deserializes a record with explicit S3 integrity checks,
    /// always rejecting a mismatch between its signed intended key and the
    /// actual S3 key. `HistoryCheck::AlreadyChecked` requires the caller to have
    /// validated the key's enclosing prefix.
    pub(crate) async fn get_log_record_inner(
        &self,
        key: &str,
        lock_check: LockCheck,
        history_check: HistoryCheck,
    ) -> GuardianResult<LogRecord> {
        if matches!(history_check, HistoryCheck::Required) {
            let keys = self.validate_prefix_history_and_list_keys(key).await?;
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

        // NOTE: When required, we are explicitly assuming locks are unexpired.
        if matches!(lock_check, LockCheck::Required)
            && (response.object_lock_mode() != Some(&ObjectLockMode::Compliance)
                || response.object_lock_retain_until_date().is_none())
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

        let record = serde_json::from_slice::<LogRecord>(&bytes.into_bytes()).map_err(|e| {
            S3Error(format!(
                "Failed to deserialize object {} into target type: {}",
                key, e
            ))
        })?;
        record.validate_actual_object_key(key)?;
        Ok(record)
    }

    /// Reads an immutable-log object, asserting its Compliance lock metadata is
    /// present but not that it is unexpired.
    /// TODO: also reject when `retain_until <= now` — once the lock lapses the
    /// version check below no longer detects tampering (see
    /// `validate_prefix_history_and_list_keys`).
    pub(crate) async fn get_log_record(&self, key: &str) -> GuardianResult<LogRecord> {
        self.get_log_record_inner(key, LockCheck::Required, HistoryCheck::Required)
            .await
    }

    /// Resolve a session's [`VerifiedSessionInfo`]: read the AWS-self-signed
    /// attestation (anchoring the signing pubkey), then the signed `GuardianInfo`,
    /// and pin the attestation's PCR0 against the `allowlist` entry named by the
    /// info's reported build. No caller needs the raw attestation bytes.
    pub(crate) async fn get_verified_session_info(
        &self,
        session_id: &str,
        allowlist: &PcrAllowlist,
    ) -> GuardianResult<VerifiedSessionInfo> {
        // 1. Attestation (unsigned: authenticated by AWS, not the enclave key) →
        //    the signing pubkey it commits to.
        let att_key = InitLogMessage::attestation_object_key(session_id);
        let attestation_record = self.get_log_record(&att_key).await?;
        let (_, _, attestation_message) = attestation_record.validate_unsigned()?;
        let (attestation, signing_pubkey) = attestation_message
            .into_v1()
            .and_then(LogMessageV1::into_init_log)
            .and_then(|x| match x {
                InitLogMessage::OIAttestationUnsigned {
                    attestation,
                    signing_public_key,
                } => Some((attestation, signing_public_key)),
                _ => None,
            })
            .ok_or_else(|| S3Error(format!("expected OIAttestationUnsigned at key {att_key}")))?;

        // 2. GuardianInfo, signature-verified under that pubkey → the reported build.
        let info_key = InitLogMessage::guardian_info_object_key(session_id);
        let info_record = self.get_log_record(&info_key).await?;
        let (_, _, info_message) = info_record.verify(&signing_pubkey)?;
        let info = info_message
            .into_v1()
            .and_then(LogMessageV1::into_init_log)
            .and_then(|x| match x {
                InitLogMessage::OIGuardianInfo(info) => Some(*info),
                _ => None,
            })
            .ok_or_else(|| S3Error(format!("expected OIGuardianInfo at key {info_key}")))?;

        // 3. Anchor the pubkey and pin PCR0 to the allowlist entry for the
        //    reported build. This replays a logged attestation whose short-lived
        //    leaf cert has typically expired, so the chain is checked at the
        //    document's own signed timestamp, not now.
        let build_pcrs = allowlist.resolve(&info.untrusted_git_revision)?.clone();
        attestation.verify_replay(&signing_pubkey, &build_pcrs)?;

        Ok(VerifiedSessionInfo {
            signing_pubkey,
            info,
            build_pcrs,
        })
    }
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
    use hashi_types::guardian::LogMessageV1;

    fn mk_logger_with_client(client: Client) -> GuardianS3Client {
        let config = S3Config {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
            session_token: None,
            bucket_info: S3BucketInfo {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
            },
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
            .write_at_key(
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
            .write_at_key("key", &TestPayload { a: 1 }, Duration::from_mins(5))
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
            .write_at_key("key", &TestPayload { a: 1 }, Duration::from_mins(5))
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
            .write_at_key("key", &TestPayload { a: 1 }, Duration::from_mins(5))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_log_writer_retries_beyond_sdk_attempts() {
        let put_flaky = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(500, None)
            .times(5)
            .output(|| PutObjectOutput::builder().build())
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::Sequential, &[&put_flaky], |b| b
            .retry_config(RetryConfig::standard().with_max_attempts(1)));
        let logger = mk_logger_with_client(client);
        let signing_key = GuardianSignKeyPair::new(rand::thread_rng());
        let log = LogRecord::new(
            "session".into(),
            LogMessageV1::Heartbeat(HeartbeatLogMessage::new(7)),
            &signing_key,
        );

        // The generous deadline avoids CI timing sensitivity without slowing success;
        // zero delay keeps the application-level retry sequence immediate.
        logger
            .write_log_record_or_abort_inner(log, Duration::from_secs(10), Duration::ZERO)
            .await
            .unwrap();
        assert_eq!(put_flaky.num_calls(), 6);
    }

    #[tokio::test]
    #[should_panic(expected = "was not written within")]
    async fn test_log_writer_panics_after_failure_interval() {
        let put_fail = mock!(Client::put_object)
            .match_requests(|req| req.bucket() == Some("bucket"))
            .sequence()
            .http_status(500, None)
            .times(100)
            .build();
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_fail], |builder| {
            builder.retry_config(RetryConfig::standard().with_max_attempts(1))
        });
        let logger = mk_logger_with_client(client);
        let signing_key = GuardianSignKeyPair::new(rand::thread_rng());
        let log = LogRecord::new(
            "session".into(),
            LogMessageV1::Heartbeat(HeartbeatLogMessage::new(7)),
            &signing_key,
        );

        // The first PUT runs immediately, then retries every 5ms until the 50ms
        // deadline panics (roughly 10 attempts; scheduling makes the count inexact).
        logger
            .write_log_record_or_abort_inner(
                log,
                Duration::from_millis(50),
                Duration::from_millis(5),
            )
            .await
            .unwrap();
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
                "init/session/01-oi-attestation-unsigned.json",
                &TestPayload { a: 1 },
                object_lock_duration,
            )
            .await
            .unwrap();
        assert_eq!(put_flaky.num_calls(), 3);
    }
}
