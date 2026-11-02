// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One-shot remote transfers for backup archives.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Builder;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::primitives::ByteStream;
use google_cloud_gax::retry_policy::NeverRetry;
use google_cloud_storage::client::Storage;
use google_cloud_storage::read_resume_policy::NeverResume;
use tokio::io::AsyncWriteExt;

use crate::config::BackupProvider;
use crate::config::BackupRemoteConfig;

const CONFIG_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectVersion {
    S3(String),
    Gcs(i64),
}

#[derive(Debug)]
pub struct UploadReceipt {
    pub version: Option<ObjectVersion>,
    pub e_tag: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    #[error("remote backup already exists: {0:#}")]
    AlreadyExists(#[source] anyhow::Error),
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

impl UploadError {
    pub(crate) fn context(self, message: String) -> Self {
        match self {
            Self::AlreadyExists(error) => Self::AlreadyExists(error.context(message)),
            Self::Other(error) => Self::Other(error.context(message)),
        }
    }
}

#[derive(Clone)]
pub enum BackupRemoteClient {
    S3(aws_sdk_s3::Client),
    Gcs(Box<Storage>),
}

impl BackupRemoteClient {
    fn provider(&self) -> BackupProvider {
        match self {
            Self::S3(_) => BackupProvider::S3,
            Self::Gcs(_) => BackupProvider::Gcs,
        }
    }

    pub async fn connect(config: &BackupRemoteConfig) -> anyhow::Result<Self> {
        tokio::time::timeout(CONFIG_TIMEOUT, async {
            match config {
                BackupRemoteConfig::S3(config) => {
                    let config = aws_config::defaults(BehaviorVersion::latest())
                        .region(Region::new(config.region().to_owned()))
                        .retry_config(RetryConfig::standard().with_max_attempts(1))
                        .timeout_config(timeouts())
                        .load()
                        .await;
                    let mut builder = client_builder(Builder::from(&config));
                    // Preserve the existing S3-compatible endpoint convention.
                    if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
                        builder = builder.force_path_style(true);
                    }
                    Ok(Self::S3(aws_sdk_s3::Client::from_conf(builder.build())))
                }
                BackupRemoteConfig::Gcs(_) => {
                    crate::init_crypto_provider();
                    let client = Storage::builder()
                        .with_retry_policy(NeverRetry)
                        .with_read_resume_policy(NeverResume)
                        .build()
                        .await
                        .context("failed to load GCS backup configuration")?;
                    Ok(Self::Gcs(Box::new(client)))
                }
            }
        })
        .await
        .context("timed out loading remote backup configuration")?
    }

    pub async fn upload(
        &self,
        bucket: &str,
        key: &str,
        archive: &Path,
    ) -> Result<UploadReceipt, UploadError> {
        // The outer deadline also covers credential resolution and opening/streaming
        // the file, not just the SDK's HTTP request. Never remove the local archive.
        tokio::time::timeout(TRANSFER_TIMEOUT, async {
            match self {
                Self::S3(client) => {
                    let body = ByteStream::from_path(archive)
                        .await
                        .context("failed to open backup archive for upload")?;
                    client
                        .put_object()
                        .bucket(bucket)
                        .key(key)
                        .if_none_match("*")
                        .body(body)
                        .send()
                        .await
                        .map(|receipt| UploadReceipt {
                            version: receipt.version_id.map(ObjectVersion::S3),
                            e_tag: receipt.e_tag,
                        })
                        .map_err(|error| {
                            let already_exists = error
                                .raw_response()
                                .is_some_and(|response| response.status().as_u16() == 412);
                            let error =
                                anyhow::Error::new(error).context("S3 backup PutObject failed");
                            if already_exists {
                                UploadError::AlreadyExists(error)
                            } else {
                                UploadError::Other(error)
                            }
                        })
                }
                Self::Gcs(client) => {
                    let file = tokio::fs::File::open(archive)
                        .await
                        .context("failed to open backup archive for upload")?;
                    let receipt = client
                        .write_object(format!("projects/_/buckets/{bucket}"), key, file)
                        .set_if_generation_match(0_i64)
                        .send_unbuffered()
                        .await
                        .map_err(|error| {
                            let already_exists = error.http_status_code() == Some(412);
                            let error =
                                anyhow::Error::new(error).context("GCS backup upload failed");
                            if already_exists {
                                UploadError::AlreadyExists(error)
                            } else {
                                UploadError::Other(error)
                            }
                        })?;
                    if receipt.generation <= 0 {
                        return Err(anyhow::anyhow!(
                            "GCS upload returned a nonpositive generation"
                        )
                        .into());
                    }
                    Ok(UploadReceipt {
                        version: Some(ObjectVersion::Gcs(receipt.generation)),
                        e_tag: (!receipt.etag.is_empty()).then_some(receipt.etag),
                    })
                }
            }
        })
        .await
        .context("remote backup upload deadline exceeded")
        .map_err(UploadError::from)
        .and_then(|result| result)
    }

    /// Stream an object into a caller-owned file. The caller owns private file
    /// creation and cleanup, including cleanup if this future is cancelled.
    pub async fn download(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&ObjectVersion>,
        destination: &mut tokio::fs::File,
    ) -> anyhow::Result<()> {
        // Include credentials, response body consumption, and file writes in the
        // deadline: SDK operation timeouts alone only cover the response headers.
        tokio::time::timeout(TRANSFER_TIMEOUT, async {
            match self {
                Self::S3(client) => {
                    let version_id = match version {
                        Some(ObjectVersion::S3(value)) => Some(value.clone()),
                        Some(ObjectVersion::Gcs(_)) => anyhow::bail!("GCS generation cannot select an S3 object"),
                        None => None,
                    };
            let mut response = client
                .get_object()
                .bucket(bucket)
                .key(key)
                .set_version_id(version_id)
                .send()
                .await
                .context("S3 backup GetObject failed")?;
            let expected_length = response.content_length();
            let mut downloaded = 0_u64;
            while let Some(chunk) = response
                .body
                .try_next()
                .await
                .context("failed to read S3 backup body")?
            {
                destination
                    .write_all(&chunk)
                    .await
                    .context("failed to write downloaded backup")?;
                downloaded += chunk.len() as u64;
            }
            if let Some(expected) = expected_length {
                anyhow::ensure!(
                    u64::try_from(expected).ok() == Some(downloaded),
                    "incomplete S3 backup body: expected {expected} bytes, received {downloaded}"
                );
            }
                }
                Self::Gcs(client) => {
                    // The SDK leaves '%' and '\' unescaped. Protect literal keys from
                    // server-side percent decoding and URL backslash normalization.
                    let escapes = key.bytes().filter(|&byte| matches!(byte, b'%' | b'\\')).count();
                    let mut object = String::with_capacity(key.len() + 2 * escapes);
                    for character in key.chars() {
                        match character {
                            '%' => object.push_str("%25"),
                            '\\' => object.push_str("%5C"),
                            other => object.push(other),
                        }
                    }
                    let mut request = client
                        .read_object(format!("projects/_/buckets/{bucket}"), object)
                        .with_automatic_decompression(false);
                    match version {
                        Some(ObjectVersion::Gcs(generation)) => {
                            anyhow::ensure!(*generation > 0, "GCS generation must be positive");
                            request = request.set_generation(*generation);
                        }
                        Some(ObjectVersion::S3(_)) => anyhow::bail!("S3 version ID cannot select a GCS object"),
                        None => {}
                    }
                    let mut response = request.send().await.context("GCS backup download failed")?;
                    let expected = response.object().size;
                    let mut downloaded = 0_u64;
                    // Read through EOF: checksum validation can fail after the last data chunk.
                    while let Some(chunk) = response.next().await.transpose()
                        .context("failed to read GCS backup body")?
                    {
                        destination.write_all(&chunk).await
                            .context("failed to write downloaded backup")?;
                        downloaded += chunk.len() as u64;
                    }
                    anyhow::ensure!(
                        u64::try_from(expected).ok() == Some(downloaded),
                        "incomplete GCS backup body: expected {expected} bytes, received {downloaded}"
                    );
                }
            }
            destination
                .flush()
                .await
                .context("failed to flush downloaded backup")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("remote backup download deadline exceeded")
        .and_then(|result| result)
        .with_context(|| {
            let scheme = self.provider().scheme();
            format!("failed to download backup from {scheme}://{bucket}/{key} (revision {version:?})")
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test_endpoint(endpoint: &str) -> Self {
        let builder = Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "smoke",
                "smoke",
                None,
                None,
                "backup-test",
            ))
            .endpoint_url(endpoint)
            .force_path_style(true);
        Self::S3(aws_sdk_s3::Client::from_conf(
            client_builder(builder).build(),
        ))
    }

    #[cfg(test)]
    fn gcs_test_builder(endpoint: &str) -> google_cloud_storage::builder::storage::ClientBuilder {
        crate::init_crypto_provider();
        Storage::builder()
            .with_endpoint(endpoint)
            .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
            .with_retry_policy(NeverRetry)
            .with_read_resume_policy(NeverResume)
    }

    #[cfg(test)]
    pub(crate) async fn for_gcs_test_endpoint(endpoint: &str) -> Self {
        Self::Gcs(Box::new(
            Self::gcs_test_builder(endpoint).build().await.unwrap(),
        ))
    }
}

fn timeouts() -> TimeoutConfig {
    TimeoutConfig::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        // The SDK read timeout covers the request through response headers, not
        // idle reads, so it must allow the full upload transfer.
        .read_timeout(TRANSFER_TIMEOUT)
        .operation_timeout(TRANSFER_TIMEOUT)
        .operation_attempt_timeout(TRANSFER_TIMEOUT)
        .build()
}

fn client_builder(builder: Builder) -> Builder {
    builder
        .retry_config(RetryConfig::standard().with_max_attempts(1))
        .timeout_config(timeouts())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Bytes;
    use axum::extract::Query;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::routing::put;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct ObjectStore {
        requests: usize,
        object: Option<Bytes>,
        versions: HashMap<String, Bytes>,
        fail: bool,
    }

    async fn put_object(
        State(store): State<Arc<Mutex<ObjectStore>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> (StatusCode, &'static str) {
        let mut store = store.lock().await;
        store.requests += 1;
        if store.fail {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "<Error><Code>SlowDown</Code><Message>try later</Message></Error>",
            );
        }
        if headers.get("if-none-match").and_then(|h| h.to_str().ok()) != Some("*") {
            return (StatusCode::BAD_REQUEST, "missing no-overwrite condition");
        }
        if store.object.is_some() {
            return (
                StatusCode::PRECONDITION_FAILED,
                "<Error><Code>PreconditionFailed</Code></Error>",
            );
        }
        store.object = Some(body);
        (StatusCode::OK, "")
    }

    async fn get_object(
        State(store): State<Arc<Mutex<ObjectStore>>>,
        Query(query): Query<HashMap<String, String>>,
    ) -> (StatusCode, Bytes) {
        let mut store = store.lock().await;
        store.requests += 1;
        if store.fail {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Bytes::from_static(
                    b"<Error><Code>SlowDown</Code><Message>try later</Message></Error>",
                ),
            );
        }
        let object = match query.get("versionId") {
            Some(version) => store.versions.get(version),
            None => store.object.as_ref(),
        };
        match object {
            Some(bytes) => (StatusCode::OK, bytes.clone()),
            None => (
                StatusCode::NOT_FOUND,
                Bytes::from_static(b"<Error><Code>NoSuchKey</Code></Error>"),
            ),
        }
    }

    async fn server(
        fail: bool,
    ) -> (
        BackupRemoteClient,
        Arc<Mutex<ObjectStore>>,
        tokio::task::JoinHandle<()>,
    ) {
        let store = Arc::new(Mutex::new(ObjectStore {
            fail,
            ..ObjectStore::default()
        }));
        let router = Router::new()
            .route(
                "/backup-bucket/testnet/validator/epoch-7.tar",
                put(put_object).get(get_object),
            )
            .with_state(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            BackupRemoteClient::for_test_endpoint(&endpoint),
            store,
            task,
        )
    }

    #[tokio::test]
    async fn conditional_upload_does_not_overwrite_existing_object() {
        let (client, store, server) = server(false).await;
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.tar");
        let original = b"published archive bytes";
        tokio::fs::write(&archive, original).await.unwrap();
        client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap();
        let remote_bytes = store.lock().await.object.clone().unwrap();
        assert!(!remote_bytes.is_empty());

        let replacement = b"different local archive bytes";
        tokio::fs::write(&archive, replacement).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::AlreadyExists(_)));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), replacement);
        let store = store.lock().await;
        assert_eq!(store.requests, 2);
        assert_eq!(store.object.as_ref().unwrap(), &remote_bytes);
        server.abort();
    }

    #[tokio::test]
    async fn server_failure_is_not_retried_and_preserves_local_archive() {
        let (client, store, server) = server(true).await;
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.tar");
        let bytes = b"published archive must survive a failed upload";
        tokio::fs::write(&archive, bytes).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::Other(_)));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), bytes);
        let store = store.lock().await;
        assert_eq!(store.requests, 1);
        server.abort();
    }

    #[tokio::test]
    async fn download_selects_stored_older_version_instead_of_latest() {
        let (client, store, server) = server(false).await;
        let older = Bytes::from_static(b"older archived database snapshot");
        let latest = Bytes::from_static(b"latest different database snapshot");
        {
            let mut store = store.lock().await;
            store
                .versions
                .insert("old+/version".to_owned(), older.clone());
            store.object = Some(latest.clone());
        }
        let directory = tempfile::tempdir().unwrap();
        let historical_version = ObjectVersion::S3("old+/version".to_owned());
        for (version, expected) in [(None, latest), (Some(&historical_version), older)] {
            let path = directory.path().join("download");
            let mut destination = tokio::fs::File::create(&path).await.unwrap();
            client
                .download(
                    "backup-bucket",
                    "testnet/validator/epoch-7.tar",
                    version,
                    &mut destination,
                )
                .await
                .unwrap();
            assert_eq!(tokio::fs::read(path).await.unwrap(), expected);
        }
        assert_eq!(store.lock().await.requests, 2);
        server.abort();
    }

    #[tokio::test]
    async fn download_service_failure_is_not_retried() {
        let (client, store, server) = server(true).await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download");
        let mut destination = tokio::fs::File::create(&path).await.unwrap();
        client
            .download(
                "backup-bucket",
                "testnet/validator/epoch-7.tar",
                Some(&ObjectVersion::S3("old-version".to_owned())),
                &mut destination,
            )
            .await
            .unwrap_err();
        assert_eq!(store.lock().await.requests, 1);
        assert!(tokio::fs::read(path).await.unwrap().is_empty());
        server.abort();
    }

    // This fixture exercises the real SDK's JSON HTTP transport without changing
    // production endpoint or credential discovery.
    #[derive(Default)]
    struct GcsStore {
        requests: Vec<(axum::http::Method, String, HashMap<String, String>)>,
        uploaded: Option<Bytes>,
        fail: bool,
        interrupted: bool,
        bad_checksum: bool,
        session_url: String,
    }

    async fn gcs_request(
        State(store): State<Arc<Mutex<GcsStore>>>,
        method: axum::http::Method,
        uri: axum::http::Uri,
        Query(query): Query<HashMap<String, String>>,
        body: Bytes,
    ) -> axum::response::Response {
        use axum::body::Body;
        use axum::response::IntoResponse;

        let mut store = store.lock().await;
        store
            .requests
            .push((method.clone(), uri.path().to_owned(), query.clone()));
        if store.fail {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": {"code": 503, "message": "service unavailable"}
                })),
            )
                .into_response();
        }
        if method == axum::http::Method::POST {
            if query.get("ifGenerationMatch").map(String::as_str) != Some("0") {
                return (StatusCode::BAD_REQUEST, "missing create-only condition").into_response();
            }
            if query.get("uploadType").map(String::as_str) == Some("resumable") {
                // A competing writer publishes after initiation but before completion.
                store.uploaded = Some(Bytes::from_static(b"competing archive"));
                return (StatusCode::OK, [("location", store.session_url.clone())]).into_response();
            }
            if store.uploaded.is_some() {
                return (
                    StatusCode::PRECONDITION_FAILED,
                    axum::Json(serde_json::json!({
                        "error": {"code": 412, "message": "object already exists"}
                    })),
                )
                    .into_response();
            }
            store.uploaded = Some(body);
            return axum::Json(serde_json::json!({
                "bucket": "backup-bucket",
                "name": "testnet/validator/epoch-7.tar",
                "generation": "123",
                "etag": "test-etag"
            }))
            .into_response();
        }
        if method == axum::http::Method::PUT && uri.path() == "/upload-session" {
            return (
                StatusCode::PRECONDITION_FAILED,
                axum::Json(serde_json::json!({
                    "error": {"code": 412, "message": "object already exists"}
                })),
            )
                .into_response();
        }
        // Only these objects exist; decoding percent escapes or normalizing backslashes selects a missing object.
        if !matches!(
            uri.path(),
            "/storage/v1/b/backup-bucket/o/testnet%2Fvalidator%2Fepoch-7.tar"
                | "/storage/v1/b/backup-bucket/o/literal%252Fprefix%5C..%5Cname%2F..%2Farchive.tar.asc"
        ) {
            return (StatusCode::NOT_FOUND, "object not found").into_response();
        }

        // CRC32C("123456789") = 0xe3069283, encoded big-endian as base64.
        let historical = query.get("generation").map(String::as_str) == Some("123");
        let bytes = if historical {
            "123456789"
        } else {
            "latest archive"
        };
        let mut response = axum::http::Response::builder()
            .header("x-goog-generation", if historical { "123" } else { "456" })
            .header("x-goog-stored-content-length", bytes.len().to_string());
        if historical {
            response = response.header(
                "x-goog-hash",
                if store.bad_checksum {
                    "crc32c=AAAAAA=="
                } else {
                    "crc32c=4waSgw=="
                },
            );
        }
        let interrupted = store.interrupted;
        let body = Body::from_stream(futures::stream::unfold(0, move |chunk| async move {
            match chunk {
                0 => Some((Ok(Bytes::copy_from_slice(&bytes.as_bytes()[..3])), 1)),
                1 if interrupted => {
                    // Flush the first chunk before the transport is interrupted.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    Some((Err(std::io::Error::other("interrupted body")), 2))
                }
                1 => Some((Ok(Bytes::copy_from_slice(&bytes.as_bytes()[3..])), 2)),
                _ => None,
            }
        }));
        response.body(body).unwrap()
    }

    async fn gcs_server(
        resumable: bool,
    ) -> (
        BackupRemoteClient,
        Arc<Mutex<GcsStore>>,
        tokio::task::JoinHandle<()>,
    ) {
        let store = Arc::new(Mutex::new(GcsStore::default()));
        let router = Router::new()
            .fallback(gcs_request)
            .with_state(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        store.lock().await.session_url = format!("{endpoint}/upload-session");
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = if resumable {
            BackupRemoteClient::Gcs(Box::new(
                BackupRemoteClient::gcs_test_builder(&endpoint)
                    .with_resumable_upload_threshold(0_usize)
                    .build()
                    .await
                    .unwrap(),
            ))
        } else {
            BackupRemoteClient::for_gcs_test_endpoint(&endpoint).await
        };
        (client, store, task)
    }

    #[tokio::test]
    async fn gcs_upload_is_create_only_and_preserves_duplicate_archive() {
        let (client, store, server) = gcs_server(false).await;
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.tar");
        let original = b"published archive bytes";
        tokio::fs::write(&archive, original).await.unwrap();
        let receipt = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap();
        assert_eq!(receipt.version, Some(ObjectVersion::Gcs(123)));
        assert_eq!(receipt.e_tag.as_deref(), Some("test-etag"));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), original);
        let remote = store.lock().await.uploaded.clone().unwrap();
        assert!(
            remote
                .windows(original.len())
                .any(|window| window == original)
        );

        let replacement = b"different local archive";
        tokio::fs::write(&archive, replacement).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::AlreadyExists(_)));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), replacement);
        let store = store.lock().await;
        assert_eq!(store.uploaded.as_ref(), Some(&remote));
        assert_eq!(store.requests.len(), 2);
        for (method, path, query) in &store.requests {
            assert_eq!(method, axum::http::Method::POST);
            assert_eq!(path, "/upload/storage/v1/b/backup-bucket/o");
            assert_eq!(
                query.get("uploadType").map(String::as_str),
                Some("multipart")
            );
            assert_eq!(
                query.get("name").map(String::as_str),
                Some("testnet/validator/epoch-7.tar")
            );
        }
        server.abort();
    }

    #[tokio::test]
    async fn gcs_download_selects_literal_percent_key_and_historical_generation_and_streams_to_file()
     {
        let (client, store, server) = gcs_server(false).await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download");
        let historical = ObjectVersion::Gcs(123);
        for (version, expected) in [(None, "latest archive"), (Some(&historical), "123456789")] {
            let mut destination = tokio::fs::File::create(&path).await.unwrap();
            client
                .download(
                    "backup-bucket",
                    r"literal%2Fprefix\..\name/../archive.tar.asc",
                    version,
                    &mut destination,
                )
                .await
                .unwrap();
            assert_eq!(tokio::fs::read(&path).await.unwrap(), expected.as_bytes());
        }
        let store = store.lock().await;
        assert_eq!(store.requests.len(), 2);
        for (method, path, query) in &store.requests {
            assert_eq!(method, axum::http::Method::GET);
            assert_eq!(
                path,
                "/storage/v1/b/backup-bucket/o/literal%252Fprefix%5C..%5Cname%2F..%2Farchive.tar.asc"
            );
            assert_eq!(query.get("alt").map(String::as_str), Some("media"));
            assert!(!query.contains_key("ifGenerationMatch"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn gcs_service_failure_is_not_retried_and_preserves_local_archive() {
        let (client, store, server) = gcs_server(false).await;
        store.lock().await.fail = true;
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.tar");
        let bytes = b"archive must survive a failed upload";
        tokio::fs::write(&archive, bytes).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::Other(_)));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), bytes);
        assert_eq!(store.lock().await.requests.len(), 1);

        let path = directory.path().join("download");
        let mut destination = tokio::fs::File::create(&path).await.unwrap();
        assert!(
            client
                .download(
                    "backup-bucket",
                    "testnet/validator/epoch-7.tar",
                    None,
                    &mut destination
                )
                .await
                .is_err()
        );
        assert_eq!(store.lock().await.requests.len(), 2);
        assert!(tokio::fs::read(path).await.unwrap().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn gcs_interrupted_download_is_not_resumed() {
        let (client, store, server) = gcs_server(false).await;
        store.lock().await.interrupted = true;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download");
        let mut destination = tokio::fs::File::create(&path).await.unwrap();
        assert!(
            client
                .download(
                    "backup-bucket",
                    "testnet/validator/epoch-7.tar",
                    Some(&ObjectVersion::Gcs(123)),
                    &mut destination,
                )
                .await
                .is_err()
        );
        assert_eq!(store.lock().await.requests.len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn gcs_download_rejects_bad_checksum_at_eof() {
        let (client, store, server) = gcs_server(false).await;
        store.lock().await.bad_checksum = true;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("download");
        let mut destination = tokio::fs::File::create(&path).await.unwrap();
        assert!(
            client
                .download(
                    "backup-bucket",
                    "testnet/validator/epoch-7.tar",
                    Some(&ObjectVersion::Gcs(123)),
                    &mut destination,
                )
                .await
                .is_err()
        );
        assert_eq!(store.lock().await.requests.len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn gcs_resumable_completion_collision_preserves_both_archives() {
        let (client, store, server) = gcs_server(true).await;
        let directory = tempfile::tempdir().unwrap();
        let archive = directory.path().join("epoch-7.tar");
        let bytes = b"local archive";
        tokio::fs::write(&archive, bytes).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/epoch-7.tar", &archive)
            .await
            .unwrap_err();
        assert!(matches!(error, UploadError::AlreadyExists(_)));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), bytes);
        let store = store.lock().await;
        assert_eq!(
            store.uploaded.as_deref(),
            Some(b"competing archive".as_slice())
        );
        assert_eq!(store.requests.len(), 2);
        server.abort();
    }
}
