// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::mpc::stored_rows;
use crate::mpc::types::EXPECT_SERIALIZATION_SUCCESS;
use crate::mpc::types::MessagesHash;
use crate::mpc::types::RotationMessages;
use bytes::Bytes;
use fastcrypto_tbls::threshold_schnorr::avss;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use sui_sdk_types::Address;

pub trait CachedPayload: Serialize {
    fn payload_hash(bytes: &[u8]) -> MessagesHash;
}

impl CachedPayload for avss::Message {
    fn payload_hash(bytes: &[u8]) -> MessagesHash {
        stored_rows::dkg_message_hash(bytes)
    }
}

impl CachedPayload for RotationMessages {
    fn payload_hash(bytes: &[u8]) -> MessagesHash {
        stored_rows::rotation_messages_hash(bytes)
    }
}

pub struct Cached<T> {
    value: T,
    bytes: Bytes,
    hash: MessagesHash,
}

impl<T: CachedPayload> Cached<T> {
    pub fn new(value: T) -> Arc<Self> {
        let mut encoded = bcs::to_bytes(&value).expect(EXPECT_SERIALIZATION_SUCCESS);
        encoded.shrink_to_fit();
        let bytes = Bytes::from(encoded);
        let hash = T::payload_hash(&bytes);
        Arc::new(Self { value, bytes, hash })
    }

    pub fn certified(bytes: &[u8], expected: MessagesHash) -> Result<Arc<Self>, String>
    where
        T: DeserializeOwned,
    {
        if T::payload_hash(bytes) != expected {
            return Err("bytes don't match the certificate's hash".into());
        }
        let bytes = Bytes::copy_from_slice(bytes);
        let value = bcs::from_bytes(&bytes).map_err(|e| format!("certified bytes: {e}"))?;
        Ok(Arc::new(Self {
            value,
            bytes,
            hash: expected,
        }))
    }
}

impl<T: Clone> Cached<T> {
    pub fn into_value(self: Arc<Self>) -> T {
        Arc::try_unwrap(self).map_or_else(|shared| shared.value.clone(), |entry| entry.value)
    }
}

impl<T> Cached<T> {
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn hash(&self) -> MessagesHash {
        self.hash
    }
}

impl<T> Deref for Cached<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

pub struct MessageCache<T> {
    entries: HashMap<Address, Arc<Cached<T>>>,
}

impl<T> Default for MessageCache<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }
}

impl<T: CachedPayload> MessageCache<T> {
    pub fn insert(&mut self, dealer: Address, value: T) {
        self.entries.insert(dealer, Cached::new(value));
    }
}

impl<T> MessageCache<T> {
    pub fn insert_entry(&mut self, dealer: Address, entry: Arc<Cached<T>>) {
        self.entries.insert(dealer, entry);
    }

    pub fn get(&self, dealer: &Address) -> Option<&T> {
        self.entries.get(dealer).map(|entry| &entry.value)
    }

    pub fn get_entry(&self, dealer: &Address) -> Option<&Arc<Cached<T>>> {
        self.entries.get(dealer)
    }

    pub fn contains_key(&self, dealer: &Address) -> bool {
        self.entries.contains_key(dealer)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn remove(&mut self, dealer: &Address) -> Option<Arc<Cached<T>>> {
        self.entries.remove(dealer)
    }
}
