// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only access to the guardian's S3 log bucket, which holds the withdrawal
//! log ([`crate::node::widlog`]) and the KP share log ([`crate::kp::roster`]).
//! The proxy never writes.

use aws_sdk_s3::error::DisplayErrorContext;
use hashi_types::guardian::log::S3_DIR_WITHDRAW;

/// Minimal object-store surface the log readers need. `list_dirs` is an S3
/// delimiter listing (returns immediate sub-prefixes), `list_keys` a plain
/// prefix listing in ascending key order, both fully paginated.
#[tonic::async_trait]
pub trait LogStore: Send + Sync + 'static {
    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
    async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>>;
    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>>;
}

/// The guardian's log bucket over the AWS SDK, read-only. Credentials come
/// from the default provider chain (task role on Fargate, env vars for MinIO).
/// Cloning shares the underlying SDK client (the cache and relay each hold one).
#[derive(Clone)]
pub struct S3LogStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl S3LogStore {
    pub async fn connect(bucket: String, region: String) -> Self {
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&aws_config);
        if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
            builder = builder.force_path_style(true);
        }
        Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket,
        }
    }

    /// One-key LIST to prove bucket access at boot (an empty result is fine —
    /// the withdraw log may not exist yet).
    pub async fn probe(&self) -> anyhow::Result<()> {
        self.client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(format!("{S3_DIR_WITHDRAW}/"))
            .max_keys(1)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("list {}: {}", self.bucket, DisplayErrorContext(e)))?;
        Ok(())
    }
}

#[tonic::async_trait]
impl LogStore for S3LogStore {
    async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut dirs = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .delimiter("/")
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page
                .map_err(|e| anyhow::anyhow!("list dirs {prefix}: {}", DisplayErrorContext(e)))?;
            dirs.extend(
                page.common_prefixes()
                    .iter()
                    .filter_map(|p| p.prefix().map(String::from)),
            );
        }
        Ok(dirs)
    }

    async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut pages = self
            .client
            .list_objects_v2()
            .bucket(&self.bucket)
            .prefix(prefix)
            .into_paginator()
            .send();
        while let Some(page) = pages.next().await {
            let page = page
                .map_err(|e| anyhow::anyhow!("list keys {prefix}: {}", DisplayErrorContext(e)))?;
            keys.extend(
                page.contents()
                    .iter()
                    .filter_map(|o| o.key().map(String::from)),
            );
        }
        Ok(keys)
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        let object = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("get {key}: {}", DisplayErrorContext(e)))?;
        let bytes = object
            .body
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("read {key}: {e}"))?;
        Ok(bytes.into_bytes().to_vec())
    }
}

#[cfg(test)]
pub(crate) mod test_store {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;

    /// In-memory `LogStore` with S3 listing semantics (delimiter dirs, ascending
    /// keys) and failure toggles.
    #[derive(Default)]
    pub(crate) struct MemStore {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        pub(crate) fail_lists: AtomicBool,
        pub(crate) fail_gets: AtomicBool,
        pub(crate) list_calls: AtomicUsize,
    }

    impl MemStore {
        pub(crate) fn insert(&self, key: impl Into<String>, bytes: Vec<u8>) {
            self.objects.lock().unwrap().insert(key.into(), bytes);
        }
    }

    #[tonic::async_trait]
    impl LogStore for MemStore {
        async fn list_dirs(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_lists.load(Ordering::SeqCst) {
                anyhow::bail!("simulated list failure");
            }
            let objects = self.objects.lock().unwrap();
            let mut dirs: Vec<String> = objects
                .keys()
                .filter_map(|k| {
                    let rest = k.strip_prefix(prefix)?;
                    let end = rest.find('/')?;
                    Some(format!("{prefix}{}", &rest[..=end]))
                })
                .collect();
            dirs.dedup();
            Ok(dirs)
        }

        async fn list_keys(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_lists.load(Ordering::SeqCst) {
                anyhow::bail!("simulated list failure");
            }
            let objects = self.objects.lock().unwrap();
            Ok(objects
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }

        async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
            if self.fail_gets.load(Ordering::SeqCst) {
                anyhow::bail!("simulated get failure");
            }
            self.objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no such key {key}"))
        }
    }
}
