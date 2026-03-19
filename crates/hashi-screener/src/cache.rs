// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lru::LruCache;
use std::num::NonZeroUsize;
use tokio::sync::Mutex;
use tracing::debug;

const CACHE_TTL: Duration = Duration::from_secs(600); // 10 minutes
const CACHE_CAPACITY: usize = 10_000;

struct CacheEntry {
    approved: bool,
    inserted_at: Instant,
}

#[derive(Clone)]
pub struct ScreenerCache {
    inner: Arc<Mutex<LruCache<String, CacheEntry>>>,
}

impl Default for ScreenerCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenerCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(CACHE_CAPACITY).unwrap(),
            ))),
        }
    }

    pub async fn get(&self, key: &str) -> Option<bool> {
        let mut cache = self.inner.lock().await;
        match cache.get(key) {
            Some(entry) if entry.inserted_at.elapsed() < CACHE_TTL => {
                debug!(cache_key = %key, "Cache hit");
                Some(entry.approved)
            }
            Some(_) => {
                cache.pop(key);
                None
            }
            None => None,
        }
    }

    pub async fn insert(&self, key: String, approved: bool) {
        let mut cache = self.inner.lock().await;
        cache.put(
            key,
            CacheEntry {
                approved,
                inserted_at: Instant::now(),
            },
        );
    }
}
