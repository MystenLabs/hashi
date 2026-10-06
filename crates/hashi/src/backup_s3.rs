// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One-shot transfers of backup archives.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Builder;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::primitives::ByteStream;
use tokio::io::AsyncWriteExt;

const CONFIG_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct BackupS3Client {
    client: aws_sdk_s3::Client,
}

/// Parse an S3 object URI without decoding or normalizing its literal object key.
pub fn parse_s3_uri(uri: &str) -> anyhow::Result<(&str, &str)> {
    let (bucket, key) = uri
        .strip_prefix("s3://")
        .and_then(|path| path.split_once('/'))
        .context("expected s3://bucket/key")?;
    anyhow::ensure!(
        !bucket.is_empty()
            && bucket
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-".contains(&byte)),
        "S3 URI must contain a bucket name, not credentials, a port, or an encoded authority"
    );
    anyhow::ensure!(!key.is_empty(), "S3 URI must contain an object key");
    anyhow::ensure!(
        !key.contains(['?', '#']) && !key.chars().any(char::is_control),
        "S3 URI key must not contain a query, fragment, or control characters; use --version-id for versions"
    );
    Ok((bucket, key))
}

impl BackupS3Client {
    pub async fn connect(region: &str) -> anyhow::Result<Self> {
        tokio::time::timeout(CONFIG_TIMEOUT, async {
            let config = aws_config::defaults(BehaviorVersion::latest())
                .region(Region::new(region.to_owned()))
                .retry_config(RetryConfig::standard().with_max_attempts(1))
                .timeout_config(timeouts())
                .load()
                .await;
            let mut builder = client_builder(Builder::from(&config));
            // Match the existing S3-compatible endpoint convention. Production AWS
            // uses the SDK's normal endpoint resolution and virtual-host addressing.
            if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
                builder = builder.force_path_style(true);
            }
            Self {
                client: aws_sdk_s3::Client::from_conf(builder.build()),
            }
        })
        .await
        .context("timed out loading S3 backup configuration")
    }

    pub async fn upload(&self, bucket: &str, key: &str, archive: &Path) -> anyhow::Result<()> {
        // The outer deadline also covers credential resolution and opening/streaming
        // the file, not just the SDK's HTTP request. Never remove the local archive.
        tokio::time::timeout(TRANSFER_TIMEOUT, async {
            let body = ByteStream::from_path(archive)
                .await
                .context("failed to open backup archive for upload")?;
            self.client
                .put_object()
                .bucket(bucket)
                .key(key)
                .if_none_match("*")
                .body(body)
                .send()
                .await
                .context("S3 backup PutObject failed")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("S3 backup upload deadline exceeded")
        .and_then(|result| result)
    }

    /// Stream an object into a caller-owned file. The caller owns private file
    /// creation and cleanup, including cleanup if this future is cancelled.
    pub async fn download(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        destination: &mut tokio::fs::File,
    ) -> anyhow::Result<()> {
        // Include credentials, response body consumption, and file writes in the
        // deadline: SDK operation timeouts alone only cover the response headers.
        tokio::time::timeout(TRANSFER_TIMEOUT, async {
            let mut response = self
                .client
                .get_object()
                .bucket(bucket)
                .key(key)
                .set_version_id(version_id.map(str::to_owned))
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
            destination
                .flush()
                .await
                .context("failed to flush downloaded backup")?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("S3 backup download deadline exceeded")
        .and_then(|result| result)
        .with_context(|| match version_id {
            Some(version) => {
                format!("failed to download backup from s3://{bucket}/{key} (version {version})")
            }
            None => format!("failed to download backup from s3://{bucket}/{key}"),
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
        Self {
            client: aws_sdk_s3::Client::from_conf(client_builder(builder).build()),
        }
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
        BackupS3Client,
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
        (BackupS3Client::for_test_endpoint(&endpoint), store, task)
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
        let message = format!("{error:#}");
        assert!(message.contains("PreconditionFailed"));
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
        let message = format!("{error:#}");
        assert!(message.contains("SlowDown"));
        assert!(message.contains("try later"));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), bytes);
        let store = store.lock().await;
        assert_eq!(store.requests, 1);
        assert!(store.object.is_none());
        server.abort();
    }

    #[test]
    fn s3_uri_preserves_literal_keys() {
        let uri = String::from("s3://backup-bucket/a%2Fb/../archive%20name.tar");
        let (bucket, key) = parse_s3_uri(&uri).unwrap();
        assert_eq!(bucket, "backup-bucket");
        assert_eq!(key, "a%2Fb/../archive%20name.tar");
        assert_eq!(
            parse_s3_uri("s3://bucket/key with spaces.tar").unwrap().1,
            "key with spaces.tar"
        );
    }

    #[test]
    fn s3_uri_rejects_ambiguous_authorities_and_keys() {
        for uri in [
            "",
            "https://bucket/key",
            "s3://bucket",
            "s3:///key",
            "s3://bucket/",
            "s3://user:password@bucket/key",
            "s3://user@bucket/key",
            "s3://bucket:443/key",
            "s3://bucket%2Fother/key",
            "s3://bucket\\other/key",
            "s3://bucket?query/key",
            "s3://bucket#fragment/key",
            "s3://bucket/key?versionId=old",
            "s3://bucket/key#fragment",
            "s3://bucket/key\n.tar",
        ] {
            assert!(parse_s3_uri(uri).is_err(), "{uri:?}");
        }
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
        for (version, expected) in [(None, latest), (Some("old+/version"), older)] {
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
        let error = client
            .download(
                "backup-bucket",
                "testnet/validator/epoch-7.tar",
                Some("old-version"),
                &mut destination,
            )
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("s3://backup-bucket/testnet/validator/epoch-7.tar"));
        assert!(message.contains("old-version"));
        assert!(message.contains("SlowDown"));
        assert!(message.contains("try later"));
        assert_eq!(store.lock().await.requests, 1);
        assert!(tokio::fs::read(path).await.unwrap().is_empty());
        server.abort();
    }
}
