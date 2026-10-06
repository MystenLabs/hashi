// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! One-shot uploads of already-published local backup archives.

use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::Builder;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::primitives::ByteStream;

const CONFIG_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone)]
pub struct BackupS3Client {
    client: aws_sdk_s3::Client,
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

    pub async fn upload(
        &self,
        bucket: &str,
        namespace: &str,
        archive: &Path,
    ) -> anyhow::Result<String> {
        let filename = archive
            .file_name()
            .and_then(|name| name.to_str())
            .context("backup archive must have a UTF-8 filename")?;
        let key = format!("{namespace}{filename}");
        let uri = format!("s3://{bucket}/{key}");
        // The outer deadline also covers credential resolution and opening/streaming
        // the file, not just the SDK's HTTP request. Never remove the local archive.
        let result = tokio::time::timeout(UPLOAD_TIMEOUT, async {
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
        .and_then(|result| result);
        result.with_context(|| {
            format!(
                "failed to upload backup to {uri}; local archive retained at {}",
                archive.display()
            )
        })?;
        Ok(uri)
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
        .read_timeout(READ_TIMEOUT)
        .operation_timeout(UPLOAD_TIMEOUT)
        .operation_attempt_timeout(UPLOAD_TIMEOUT)
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
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::http::StatusCode;
    use axum::routing::put;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct ObjectStore {
        requests: usize,
        object: Option<Bytes>,
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
                put(put_object),
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
        let uri = client
            .upload("backup-bucket", "testnet/validator/", &archive)
            .await
            .unwrap();
        assert_eq!(uri, "s3://backup-bucket/testnet/validator/epoch-7.tar");
        let remote_bytes = store.lock().await.object.clone().unwrap();
        assert!(!remote_bytes.is_empty());

        let replacement = b"different local archive bytes";
        tokio::fs::write(&archive, replacement).await.unwrap();
        let error = client
            .upload("backup-bucket", "testnet/validator/", &archive)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(&uri));
        assert!(message.contains(archive.to_str().unwrap()));
        assert!(message.contains("local archive retained"));
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
            .upload("backup-bucket", "testnet/validator/", &archive)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("s3://backup-bucket/testnet/validator/epoch-7.tar"));
        assert!(message.contains(archive.to_str().unwrap()));
        assert!(message.contains("local archive retained"));
        assert!(message.contains("SlowDown"));
        assert!(message.contains("try later"));
        assert_eq!(tokio::fs::read(&archive).await.unwrap(), bytes);
        let store = store.lock().await;
        assert_eq!(store.requests, 1);
        assert!(store.object.is_none());
        server.abort();
    }
}
