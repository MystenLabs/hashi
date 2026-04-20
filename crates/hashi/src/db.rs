// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::Context as _;
use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fjall::Keyspace;
use fjall::KeyspaceCreateOptions;
use fjall::Readable;
use fjall::Result;
use sui_sdk_types::Address;

use hashi_types::committee::EncryptionPrivateKey;

use serde::de::DeserializeOwned;

use crate::mpc::types::RotationMessages;

pub struct Database {
    db: fjall::Database,
    // keyspaces

    // Column Family used to store encryption keys.
    //
    // key: big endian u64 for the epoch the key is used for
    // value: 32-byte RistrettoScalar
    encryption_keys: Keyspace,

    // Column Family used to store dealer messages for DKG.
    //
    // key: (big endian u64 epoch) + (32-byte validator address)
    // value: avss::Message
    dealer_messages: Keyspace,

    // Column Family used to store rotation messages for key rotation.
    //
    // key: (big endian u64 epoch) + (32-byte validator address)
    // value: BCS-serialized RotationMessages (BTreeMap<ShareIndex, avss::Message>)
    rotation_messages: Keyspace,

    // Column Family used to store nonce messages for presignature generation.
    //
    // key: (big endian u64 epoch) + (big endian u32 batch_index) + (32-byte validator address)
    // value: BCS-serialized batch_avss::Message
    nonce_messages: Keyspace,
}

const ENCRYPTION_KEYS_CF_NAME: &str = "encryption_keys";
const DEALER_MESSAGES_CF_NAME: &str = "dealer_messages";
const ROTATION_MESSAGES_CF_NAME: &str = "rotation_messages";
const NONCE_MESSAGES_CF_NAME: &str = "nonce_messages";

impl Database {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        // Preserve the underlying `fjall::Error` as the source so callers can
        // `downcast_ref::<fjall::Error>()` and match on variants like
        // `fjall::Error::Locked`. Using `anyhow!("...: {e}")` with a format
        // string would stringify the error and drop the source chain.
        let db = fjall::Database::builder(path).open().map_err(|e| {
            anyhow::Error::new(e).context(format!("failed to open database at {}", path.display()))
        })?;
        let encryption_keys =
            db.keyspace(ENCRYPTION_KEYS_CF_NAME, KeyspaceCreateOptions::default)?;
        let dealer_messages =
            db.keyspace(DEALER_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        let rotation_messages =
            db.keyspace(ROTATION_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        let nonce_messages = db.keyspace(NONCE_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        Ok(Self {
            db,
            encryption_keys,
            dealer_messages,
            rotation_messages,
            nonce_messages,
        })
    }

    /// Returns all keyspaces paired with their names. When adding a new
    /// keyspace, add it here so that it is included in snapshots and backups.
    ///
    /// Returns a `Vec` rather than a fixed-size array so callers don't have
    /// to know the keyspace count, and so adding a new keyspace is a one-line
    /// change here. Only invoked on the snapshot path, so the per-call
    /// allocation is irrelevant.
    fn all_keyspaces(&self) -> Vec<(&str, &Keyspace)> {
        vec![
            (ENCRYPTION_KEYS_CF_NAME, &self.encryption_keys),
            (DEALER_MESSAGES_CF_NAME, &self.dealer_messages),
            (ROTATION_MESSAGES_CF_NAME, &self.rotation_messages),
            (NONCE_MESSAGES_CF_NAME, &self.nonce_messages),
        ]
    }

    /// Create a consistent snapshot of this database and write it as a new fjall
    /// database at `dest`.
    ///
    /// Uses fjall's MVCC snapshot to get a point-in-time view of all keyspaces
    /// while the source database remains open for writes. The destination is a
    /// fully self-contained fjall database that can later be opened with
    /// [`Database::open`].
    ///
    /// `dest` must not already exist. The function refuses to write into an
    /// existing directory because fjall would otherwise happily merge the
    /// snapshot rows into whatever's already there, producing a hybrid DB that
    /// looks valid but isn't a true point-in-time snapshot.
    pub fn snapshot_to_path(&self, dest: &Path) -> anyhow::Result<()> {
        // Bound batch memory by serialized payload size rather than entry
        // count: keyspaces in this DB hold values ranging from 32-byte
        // scalars to multi-MB BCS-encoded MPC messages, so a fixed entry
        // count would spike memory unpredictably for the large-value keyspaces.
        //
        // 16 MiB is a comfortable middle ground: small enough that the
        // worst-case batch fits easily in RAM on any host that can run a
        // validator, large enough to amortise per-batch journal commit cost.
        const BATCH_BYTE_BUDGET: usize = 16 * 1024 * 1024;

        if dest
            .try_exists()
            .with_context(|| format!("failed to stat snapshot destination {}", dest.display()))?
        {
            anyhow::bail!(
                "snapshot destination {} already exists; refusing to merge into an existing directory",
                dest.display()
            );
        }

        let snapshot = self.db.snapshot();

        let dest_db = fjall::Database::builder(dest).open().map_err(|e| {
            anyhow::Error::new(e).context(format!(
                "failed to open destination database at {}",
                dest.display()
            ))
        })?;

        for (name, source_ks) in self.all_keyspaces() {
            let dest_ks = dest_db.keyspace(name, KeyspaceCreateOptions::default)?;
            let mut batch = dest_db.batch();
            let mut batch_bytes = 0usize;

            for guard in snapshot.iter(source_ks) {
                let (key, value) = guard.into_inner()?;
                let entry_bytes = key.len() + value.len();
                batch.insert(&dest_ks, &*key, &*value);
                batch_bytes += entry_bytes;

                if batch_bytes >= BATCH_BYTE_BUDGET {
                    batch.commit()?;
                    batch = dest_db.batch();
                    batch_bytes = 0;
                }
            }

            if batch_bytes > 0 {
                batch.commit()?;
            }
        }

        // `persist(SyncAll)` fsyncs the destination journal. Freshly inserted
        // rows live in the active memtable and are recovered from the journal
        // on next open, so the destination directory is self-contained and
        // safe to archive after this call returns. We do not fsync the dest
        // directory entry here: this function's caller immediately tars the
        // directory in the same process, so a crash before archival just
        // discards an incomplete backup and loses no committed state.
        dest_db.persist(fjall::PersistMode::SyncAll)?;

        Ok(())
    }

    /// Store encryption key for the given epoch.
    ///
    /// No-op if a key already exists for this epoch (idempotent for restart safety).
    pub fn store_encryption_key(
        &self,
        epoch: u64,
        encryption_key: &EncryptionPrivateKey,
    ) -> Result<()> {
        let key = epoch.to_be_bytes();
        if !self.encryption_keys.contains_key(key)? {
            let value = bcs::to_bytes(encryption_key).unwrap();
            self.encryption_keys.insert(key, value)?;
        }
        Ok(())
    }

    pub fn latest_encryption_key_epoch(&self) -> Result<Option<u64>> {
        let mut latest: Option<u64> = None;
        for guard in self.encryption_keys.iter() {
            let key = guard.key()?;
            if let Ok(bytes) = <[u8; 8]>::try_from(key.as_ref()) {
                let epoch = u64::from_be_bytes(bytes);
                latest = Some(latest.map_or(epoch, |l: u64| l.max(epoch)));
            }
        }
        Ok(latest)
    }

    pub fn get_encryption_key(&self, epoch: u64) -> Result<Option<EncryptionPrivateKey>> {
        let key = epoch.to_be_bytes();
        let bytes = match self.encryption_keys.get(key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let byte_array = (&*bytes).try_into().map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid point",
            ))
        })?;
        let scalar = RistrettoScalar::from_byte_array(&byte_array).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid point",
            ))
        })?;
        Ok(Some(EncryptionPrivateKey::from(scalar)))
    }

    pub fn store_dealer_message(
        &self,
        epoch: u64,
        dealer: &Address,
        message: &avss::Message,
    ) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        let value = bcs::to_bytes(message).unwrap();
        self.dealer_messages.insert(key, value)
    }

    pub fn get_dealer_message(
        &self,
        epoch: u64,
        dealer: &Address,
    ) -> Result<Option<avss::Message>> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();

        let bytes = match self.dealer_messages.get(key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

        let message = bcs::from_bytes(&bytes).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid message",
            ))
        })?;

        Ok(Some(message))
    }

    pub fn list_all_dealer_messages(&self, epoch: u64) -> Result<Vec<(Address, avss::Message)>> {
        list_messages_by_prefix(&self.dealer_messages, &epoch.to_be_bytes())
    }

    pub fn store_rotation_messages(
        &self,
        epoch: u64,
        dealer: &Address,
        messages: &RotationMessages,
    ) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        let value = bcs::to_bytes(messages).unwrap();
        self.rotation_messages.insert(key, value)
    }

    pub fn get_rotation_messages(
        &self,
        epoch: u64,
        dealer: &Address,
    ) -> Result<Option<RotationMessages>> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        let bytes = match self.rotation_messages.get(key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let messages = bcs::from_bytes(&bytes).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid rotation messages",
            ))
        })?;
        Ok(Some(messages))
    }

    pub fn list_all_rotation_messages(
        &self,
        epoch: u64,
    ) -> Result<Vec<(Address, RotationMessages)>> {
        list_messages_by_prefix(&self.rotation_messages, &epoch.to_be_bytes())
    }

    pub fn store_nonce_message(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
        message: &batch_avss::Message,
    ) -> Result<()> {
        let key = [
            epoch.to_be_bytes().as_slice(),
            batch_index.to_be_bytes().as_slice(),
            dealer.as_bytes(),
        ]
        .concat();
        let value = bcs::to_bytes(message).unwrap();
        self.nonce_messages.insert(key, value)
    }

    pub fn get_nonce_message(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> Result<Option<batch_avss::Message>> {
        let key = [
            epoch.to_be_bytes().as_slice(),
            batch_index.to_be_bytes().as_slice(),
            dealer.as_bytes(),
        ]
        .concat();
        let bytes = match self.nonce_messages.get(key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let message = bcs::from_bytes(&bytes).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid nonce message",
            ))
        })?;
        Ok(Some(message))
    }

    pub fn list_nonce_messages(
        &self,
        epoch: u64,
        batch_index: u32,
    ) -> Result<Vec<(Address, batch_avss::Message)>> {
        let prefix = [
            epoch.to_be_bytes().as_slice(),
            batch_index.to_be_bytes().as_slice(),
        ]
        .concat();
        list_messages_by_prefix(&self.nonce_messages, &prefix)
    }

    pub fn delete_dealer_message(&self, epoch: u64, dealer: &Address) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        self.dealer_messages.remove(key)
    }

    pub fn delete_rotation_messages(&self, epoch: u64, dealer: &Address) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        self.rotation_messages.remove(key)
    }

    pub fn delete_nonce_message(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> Result<()> {
        let key = [
            epoch.to_be_bytes().as_slice(),
            batch_index.to_be_bytes().as_slice(),
            dealer.as_bytes(),
        ]
        .concat();
        self.nonce_messages.remove(key)
    }

    /// Prune all MPC keyspaces, deleting entries with `epoch < cutoff_epoch`.
    pub fn prune_messages_below(&self, cutoff_epoch: u64) -> Result<()> {
        prune_keyspace(&self.encryption_keys, cutoff_epoch)?;
        prune_keyspace(&self.dealer_messages, cutoff_epoch)?;
        prune_keyspace(&self.rotation_messages, cutoff_epoch)?;
        prune_keyspace(&self.nonce_messages, cutoff_epoch)?;
        Ok(())
    }
}

/// List all `(Address, T)` pairs from a keyspace where keys match the given prefix.
/// Keys are expected to end with a 32-byte address suffix.
fn list_messages_by_prefix<T: DeserializeOwned>(
    keyspace: &Keyspace,
    prefix: &[u8],
) -> Result<Vec<(Address, T)>> {
    let addr_len = 32;
    let mut results = Vec::new();
    for guard in keyspace.prefix(prefix) {
        let (key, value) = guard.into_inner()?;
        let addr_start = key.len().checked_sub(addr_len).ok_or_else(|| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "key too short for address",
            ))
        })?;
        let address_bytes: [u8; 32] = key[addr_start..].try_into().map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid key length",
            ))
        })?;
        let address = Address::new(address_bytes);
        let message: T = bcs::from_bytes(&value).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid message data",
            ))
        })?;
        results.push((address, message));
    }
    Ok(results)
}

/// Delete entries from `keyspace` whose leading big-endian u64 epoch is `< cutoff_epoch`.
fn prune_keyspace(keyspace: &Keyspace, cutoff_epoch: u64) -> Result<()> {
    let keys_to_delete: Vec<_> = keyspace
        .iter()
        .filter_map(|guard| {
            let key = guard.key().ok()?;
            let epoch_bytes: [u8; 8] = key.as_ref().get(..8)?.try_into().ok()?;
            let epoch = u64::from_be_bytes(epoch_bytes);
            (epoch < cutoff_epoch).then(|| key.to_vec())
        })
        .collect();
    for key in keys_to_delete {
        keyspace.remove(key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::mpc::EncryptionGroupElement;
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use sui_sdk_types::Address;

    use super::Database;

    fn create_test_nodes(count: u16) -> Nodes<EncryptionGroupElement> {
        let nodes: Vec<_> = (0..count)
            .map(|i| {
                let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
                let public_key = EncryptionPublicKey::from_private_key(&private_key);
                Node {
                    id: i,
                    pk: public_key,
                    weight: 1,
                }
            })
            .collect();
        Nodes::new(nodes).unwrap()
    }

    fn create_test_message() -> avss::Message {
        // Need n >= 2*max_faulty + threshold, so 5 >= 2*1 + 3 = 5
        let nodes = create_test_nodes(5);
        let dealer = avss::Dealer::new(
            None,
            nodes,
            3, // threshold
            b"test-session".to_vec(),
        )
        .unwrap();
        dealer.create_message(&mut rand::thread_rng())
    }

    fn create_test_nonce_message() -> batch_avss::Message {
        let nodes = create_test_nodes(5);
        let dealer = batch_avss::Dealer::new(
            nodes,
            0, // party_id
            3, // threshold
            b"test-nonce-session".to_vec(),
            10, // batch_size_per_weight
        )
        .unwrap();
        dealer.create_message(&mut rand::thread_rng()).unwrap()
    }

    #[test]
    fn test_encryption_key() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());

        db.store_encryption_key(100, &private_key).unwrap();
        let key_from_db = db.get_encryption_key(100).unwrap().unwrap();

        assert_eq!(private_key, key_from_db);

        assert!(db.get_encryption_key(101).unwrap().is_none());
        drop(db);

        // Test persistence across reopen
        let db = Database::open(tmpdir.path()).unwrap();
        assert_eq!(private_key, db.get_encryption_key(100).unwrap().unwrap());
        assert!(db.get_encryption_key(101).unwrap().is_none());

        // Test that storing twice is idempotent
        let another_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(100, &another_key).unwrap();
        assert_eq!(private_key, db.get_encryption_key(100).unwrap().unwrap());
    }

    #[test]
    fn test_latest_encryption_key_epoch() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        // Empty DB returns None
        assert!(db.latest_encryption_key_epoch().unwrap().is_none());

        // Single key
        let key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(5, &key).unwrap();
        assert_eq!(db.latest_encryption_key_epoch().unwrap(), Some(5));

        // Two keys — returns the latest
        let key2 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(8, &key2).unwrap();
        assert_eq!(db.latest_encryption_key_epoch().unwrap(), Some(8));

        // Storing more keys keeps returning the latest
        let key3 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(10, &key3).unwrap();
        assert_eq!(db.latest_encryption_key_epoch().unwrap(), Some(10));
    }

    #[test]
    fn test_dealer_messages() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let message1 = create_test_message();
        let message2 = create_test_message();

        // Initially empty
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_none());

        // Store and retrieve
        db.store_dealer_message(1, &dealer1, &message1).unwrap();
        let retrieved = db.get_dealer_message(1, &dealer1).unwrap().unwrap();
        assert_eq!(
            bcs::to_bytes(&message1).unwrap(),
            bcs::to_bytes(&retrieved).unwrap()
        );

        // Different epoch, same dealer - should be empty
        assert!(db.get_dealer_message(2, &dealer1).unwrap().is_none());

        // Same epoch, different dealer - should be empty
        assert!(db.get_dealer_message(1, &dealer2).unwrap().is_none());

        // Store multiple messages in same epoch
        db.store_dealer_message(1, &dealer2, &message2).unwrap();
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_some());
        assert!(db.get_dealer_message(1, &dealer2).unwrap().is_some());

        // Store in different epoch
        db.store_dealer_message(2, &dealer1, &message1).unwrap();

        // Verify persistence across reopen
        drop(db);
        let db = Database::open(tmpdir.path()).unwrap();
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_some());
        assert!(db.get_dealer_message(2, &dealer1).unwrap().is_some());
    }

    #[test]
    fn test_list_all_dealer_messages() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let dealer3 = Address::new([3u8; 32]);
        let message1 = create_test_message();
        let message2 = create_test_message();
        let message3 = create_test_message();

        // Empty epoch returns empty list
        let result = db.list_all_dealer_messages(1).unwrap();
        assert!(result.is_empty());

        // Store messages in epoch 1
        db.store_dealer_message(1, &dealer1, &message1).unwrap();
        db.store_dealer_message(1, &dealer2, &message2).unwrap();

        // Store message in epoch 2
        db.store_dealer_message(2, &dealer3, &message3).unwrap();

        // List epoch 1 - should return 2 messages
        let result = db.list_all_dealer_messages(1).unwrap();
        assert_eq!(result.len(), 2);

        let result_map: std::collections::HashMap<_, _> = result.into_iter().collect();
        assert!(result_map.contains_key(&dealer1));
        assert!(result_map.contains_key(&dealer2));
        assert!(!result_map.contains_key(&dealer3));

        // Verify message content
        assert_eq!(
            bcs::to_bytes(&result_map[&dealer1]).unwrap(),
            bcs::to_bytes(&message1).unwrap()
        );
        assert_eq!(
            bcs::to_bytes(&result_map[&dealer2]).unwrap(),
            bcs::to_bytes(&message2).unwrap()
        );

        // List epoch 2 - should return 1 message
        let result = db.list_all_dealer_messages(2).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, dealer3);

        // List non-existent epoch - should return empty
        let result = db.list_all_dealer_messages(99).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_rotation_messages() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);

        // Create rotation messages (multiple messages per dealer, keyed by share index)
        let mut messages1: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages1.insert(NonZeroU16::new(1).unwrap(), create_test_message());
        messages1.insert(NonZeroU16::new(2).unwrap(), create_test_message());

        let mut messages2: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages2.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        // Initially empty
        assert!(db.list_all_rotation_messages(1).unwrap().is_empty());

        // Store and list
        db.store_rotation_messages(1, &dealer1, &messages1).unwrap();
        let all = db.list_all_rotation_messages(1).unwrap();
        assert_eq!(all.len(), 1);
        let retrieved = &all[0].1;
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains_key(&NonZeroU16::new(1).unwrap()));
        assert!(retrieved.contains_key(&NonZeroU16::new(2).unwrap()));

        // Different epoch, same dealer - should be empty
        assert!(db.list_all_rotation_messages(2).unwrap().is_empty());

        // Store multiple dealers in same epoch
        db.store_rotation_messages(1, &dealer2, &messages2).unwrap();
        let all = db.list_all_rotation_messages(1).unwrap();
        assert_eq!(all.len(), 2);

        // Verify persistence across reopen
        drop(db);
        let db = Database::open(tmpdir.path()).unwrap();
        let all = db.list_all_rotation_messages(1).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_list_all_rotation_messages() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);

        let mut messages1: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages1.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        let mut messages2: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages2.insert(NonZeroU16::new(2).unwrap(), create_test_message());

        // Empty epoch returns empty list
        let result = db.list_all_rotation_messages(1).unwrap();
        assert!(result.is_empty());

        // Store messages in epoch 1
        db.store_rotation_messages(1, &dealer1, &messages1).unwrap();
        db.store_rotation_messages(1, &dealer2, &messages2).unwrap();

        // List epoch 1 - should return 2 entries
        let result = db.list_all_rotation_messages(1).unwrap();
        assert_eq!(result.len(), 2);

        let result_map: std::collections::HashMap<_, _> = result.into_iter().collect();
        assert!(result_map.contains_key(&dealer1));
        assert!(result_map.contains_key(&dealer2));

        // Verify content
        assert!(result_map[&dealer1].contains_key(&NonZeroU16::new(1).unwrap()));
        assert!(result_map[&dealer2].contains_key(&NonZeroU16::new(2).unwrap()));

        // List non-existent epoch - should return empty
        let result = db.list_all_rotation_messages(99).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_nonce_messages() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let message1 = create_test_nonce_message();
        let message2 = create_test_nonce_message();

        // Initially empty
        let result = db.list_nonce_messages(1, 0).unwrap();
        assert!(result.is_empty());

        // Store and list
        db.store_nonce_message(1, 0, &dealer1, &message1).unwrap();
        let result = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, dealer1);
        assert_eq!(
            bcs::to_bytes(&result[0].1).unwrap(),
            bcs::to_bytes(&message1).unwrap()
        );

        // Same epoch+batch, different dealer
        db.store_nonce_message(1, 0, &dealer2, &message2).unwrap();
        let result = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(result.len(), 2);

        // Different batch_index - should be empty
        let result = db.list_nonce_messages(1, 1).unwrap();
        assert!(result.is_empty());

        // Different epoch - should be empty
        let result = db.list_nonce_messages(2, 0).unwrap();
        assert!(result.is_empty());

        // Verify persistence across reopen
        drop(db);
        let db = Database::open(tmpdir.path()).unwrap();
        let result = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_nonce_message() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let message = create_test_nonce_message();

        // Not found before storing
        assert!(db.get_nonce_message(1, 0, &dealer).unwrap().is_none());

        // Store and retrieve
        db.store_nonce_message(1, 0, &dealer, &message).unwrap();
        let retrieved = db.get_nonce_message(1, 0, &dealer).unwrap().unwrap();
        assert_eq!(
            bcs::to_bytes(&retrieved).unwrap(),
            bcs::to_bytes(&message).unwrap()
        );

        // Wrong epoch
        assert!(db.get_nonce_message(2, 0, &dealer).unwrap().is_none());

        // Wrong batch_index
        assert!(db.get_nonce_message(1, 1, &dealer).unwrap().is_none());

        // Wrong dealer
        let other_dealer = Address::new([2u8; 32]);
        assert!(db.get_nonce_message(1, 0, &other_dealer).unwrap().is_none());
    }

    #[test]
    fn test_nonce_messages_different_batches() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let message1 = create_test_nonce_message();
        let message2 = create_test_nonce_message();

        // Store in batch 0 and batch 1 of same epoch
        db.store_nonce_message(1, 0, &dealer, &message1).unwrap();
        db.store_nonce_message(1, 1, &dealer, &message2).unwrap();

        // Each batch returns only its own messages
        let batch0 = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(batch0.len(), 1);
        assert_eq!(
            bcs::to_bytes(&batch0[0].1).unwrap(),
            bcs::to_bytes(&message1).unwrap()
        );

        let batch1 = db.list_nonce_messages(1, 1).unwrap();
        assert_eq!(batch1.len(), 1);
        assert_eq!(
            bcs::to_bytes(&batch1[0].1).unwrap(),
            bcs::to_bytes(&message2).unwrap()
        );
    }

    #[test]
    fn test_delete_dealer_message() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let message = create_test_message();

        db.store_dealer_message(1, &dealer1, &message).unwrap();
        db.store_dealer_message(1, &dealer2, &message).unwrap();
        assert_eq!(db.list_all_dealer_messages(1).unwrap().len(), 2);

        // Delete one
        db.delete_dealer_message(1, &dealer1).unwrap();
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_none());
        assert!(db.get_dealer_message(1, &dealer2).unwrap().is_some());
        assert_eq!(db.list_all_dealer_messages(1).unwrap().len(), 1);

        // Delete non-existent is a no-op
        db.delete_dealer_message(1, &dealer1).unwrap();
        db.delete_dealer_message(99, &dealer2).unwrap();
    }

    #[test]
    fn test_delete_rotation_messages() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let mut messages: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        db.store_rotation_messages(1, &dealer1, &messages).unwrap();
        db.store_rotation_messages(1, &dealer2, &messages).unwrap();
        assert_eq!(db.list_all_rotation_messages(1).unwrap().len(), 2);

        // Delete one
        db.delete_rotation_messages(1, &dealer1).unwrap();
        assert!(db.get_rotation_messages(1, &dealer1).unwrap().is_none());
        assert!(db.get_rotation_messages(1, &dealer2).unwrap().is_some());
        assert_eq!(db.list_all_rotation_messages(1).unwrap().len(), 1);

        // Delete non-existent is a no-op
        db.delete_rotation_messages(1, &dealer1).unwrap();
    }

    #[test]
    fn test_delete_nonce_message() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let message = create_test_nonce_message();

        db.store_nonce_message(1, 0, &dealer1, &message).unwrap();
        db.store_nonce_message(1, 0, &dealer2, &message).unwrap();
        assert_eq!(db.list_nonce_messages(1, 0).unwrap().len(), 2);

        // Delete one
        db.delete_nonce_message(1, 0, &dealer1).unwrap();
        let remaining = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, dealer2);

        // Delete non-existent is a no-op
        db.delete_nonce_message(1, 0, &dealer1).unwrap();
        db.delete_nonce_message(1, 1, &dealer2).unwrap();
    }

    #[test]
    fn test_nonce_messages_overwrite() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let message1 = create_test_nonce_message();
        let message2 = create_test_nonce_message();

        // Store and overwrite same key
        db.store_nonce_message(1, 0, &dealer, &message1).unwrap();
        db.store_nonce_message(1, 0, &dealer, &message2).unwrap();

        // Should have exactly one entry (overwritten)
        let result = db.list_nonce_messages(1, 0).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(
            bcs::to_bytes(&result[0].1).unwrap(),
            bcs::to_bytes(&message2).unwrap()
        );
    }

    #[test]
    fn test_store_does_not_prune() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let dealer_msg = create_test_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());
        let nonce_msg = create_test_nonce_message();
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());

        // Store at the "stuck" source epoch.
        db.store_dealer_message(71, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(71, &dealer, &rotation_msgs)
            .unwrap();
        db.store_nonce_message(71, 0, &dealer, &nonce_msg).unwrap();
        db.store_encryption_key(71, &enc_key).unwrap();

        // Chain advanced 16 epochs while hashi was stuck. Validator stores at the
        // new target epoch.
        db.store_dealer_message(87, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(87, &dealer, &rotation_msgs)
            .unwrap();
        db.store_nonce_message(87, 0, &dealer, &nonce_msg).unwrap();
        db.store_encryption_key(87, &enc_key).unwrap();

        // The (epoch=71, *) entries must still be present.
        assert!(
            db.get_dealer_message(71, &dealer).unwrap().is_some(),
            "dealer message at source epoch must survive a write at a much later epoch"
        );
        assert!(
            db.get_rotation_messages(71, &dealer).unwrap().is_some(),
            "rotation messages at source epoch must survive a write at a much later epoch"
        );
        assert!(
            db.get_nonce_message(71, 0, &dealer).unwrap().is_some(),
            "nonce message at source epoch must survive a write at a much later epoch"
        );
        assert!(
            db.get_encryption_key(71).unwrap().is_some(),
            "encryption key at source epoch must survive a write at a much later epoch"
        );
    }

    #[test]
    fn test_prune_messages_below_basic() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let dealer_msg = create_test_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());
        let nonce_msg = create_test_nonce_message();
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());

        for epoch in 1..=10 {
            db.store_dealer_message(epoch, &dealer, &dealer_msg)
                .unwrap();
            db.store_rotation_messages(epoch, &dealer, &rotation_msgs)
                .unwrap();
            db.store_nonce_message(epoch, 0, &dealer, &nonce_msg)
                .unwrap();
            db.store_encryption_key(epoch, &enc_key).unwrap();
        }

        db.prune_messages_below(8).unwrap();

        for epoch in 1..8 {
            assert!(
                db.get_dealer_message(epoch, &dealer).unwrap().is_none(),
                "dealer message at epoch {epoch} should be pruned"
            );
            assert!(
                db.get_rotation_messages(epoch, &dealer).unwrap().is_none(),
                "rotation messages at epoch {epoch} should be pruned"
            );
            assert!(
                db.get_nonce_message(epoch, 0, &dealer).unwrap().is_none(),
                "nonce message at epoch {epoch} should be pruned"
            );
            assert!(
                db.get_encryption_key(epoch).unwrap().is_none(),
                "encryption key at epoch {epoch} should be pruned"
            );
        }
        for epoch in 8..=10 {
            assert!(
                db.get_dealer_message(epoch, &dealer).unwrap().is_some(),
                "dealer message at epoch {epoch} should be kept"
            );
            assert!(
                db.get_rotation_messages(epoch, &dealer).unwrap().is_some(),
                "rotation messages at epoch {epoch} should be kept"
            );
            assert!(
                db.get_nonce_message(epoch, 0, &dealer).unwrap().is_some(),
                "nonce message at epoch {epoch} should be kept"
            );
            assert!(
                db.get_encryption_key(epoch).unwrap().is_some(),
                "encryption key at epoch {epoch} should be kept"
            );
        }
    }

    #[test]
    fn test_prune_messages_below_zero_is_no_op() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let message = create_test_message();
        for epoch in 5..=10 {
            db.store_dealer_message(epoch, &dealer, &message).unwrap();
        }

        db.prune_messages_below(0).unwrap();

        for epoch in 5..=10 {
            assert!(db.get_dealer_message(epoch, &dealer).unwrap().is_some());
        }
    }

    #[test]
    fn test_prune_messages_below_empty_db() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();
        // Should be a no-op, not an error.
        db.prune_messages_below(100).unwrap();
    }

    #[test]
    fn test_epoch_store_writes_at_explicit_epoch_not_self_epoch() {
        use crate::storage::EpochPublicMessagesStore;
        use crate::storage::PublicMessagesStore;
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(tmpdir.path()).unwrap());

        let mut store = EpochPublicMessagesStore::new(db.clone(), 87);

        let dealer = Address::new([1u8; 32]);
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        store
            .store_rotation_messages(71, &dealer, &rotation_msgs)
            .unwrap();

        assert!(
            store.get_rotation_messages(71, &dealer).unwrap().is_some(),
            "rotation messages written with explicit epoch=71 must be readable at epoch=71"
        );

        assert!(
            store.get_rotation_messages(87, &dealer).unwrap().is_none(),
            "rotation messages must not leak to the store's self.epoch=87"
        );
    }

    #[test]
    fn test_snapshot_to_path() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();

        let dealer1 = Address::new([1u8; 32]);
        let dealer2 = Address::new([2u8; 32]);
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let dealer_msg = create_test_message();
        let nonce_msg = create_test_nonce_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        db.store_encryption_key(10, &enc_key).unwrap();
        db.store_dealer_message(10, &dealer1, &dealer_msg).unwrap();
        db.store_rotation_messages(10, &dealer2, &rotation_msgs)
            .unwrap();
        db.store_nonce_message(10, 0, &dealer1, &nonce_msg).unwrap();

        let dest_parent = tempfile::Builder::new().tempdir().unwrap();
        let dest_path = dest_parent.path().join("snapshot");
        db.snapshot_to_path(&dest_path).unwrap();

        // Drop the source so we know we're reading from the destination
        drop(db);

        let restored = Database::open(&dest_path).unwrap();

        // Verify encryption key
        assert_eq!(restored.get_encryption_key(10).unwrap().unwrap(), enc_key);

        // Verify dealer message
        let restored_dealer = restored.get_dealer_message(10, &dealer1).unwrap().unwrap();
        assert_eq!(
            bcs::to_bytes(&restored_dealer).unwrap(),
            bcs::to_bytes(&dealer_msg).unwrap()
        );

        // Verify rotation messages
        let restored_rotation = restored.list_all_rotation_messages(10).unwrap();
        assert_eq!(restored_rotation.len(), 1);
        assert_eq!(restored_rotation[0].0, dealer2);

        // Verify nonce messages
        let restored_nonces = restored.list_nonce_messages(10, 0).unwrap();
        assert_eq!(restored_nonces.len(), 1);
        assert_eq!(restored_nonces[0].0, dealer1);
    }

    #[test]
    fn test_snapshot_to_path_empty_db() {
        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();

        let dest_parent = tempfile::Builder::new().tempdir().unwrap();
        let dest_path = dest_parent.path().join("snapshot");
        db.snapshot_to_path(&dest_path).unwrap();
        drop(db);

        let restored = Database::open(&dest_path).unwrap();
        assert!(restored.latest_encryption_key_epoch().unwrap().is_none());
        assert!(restored.list_all_dealer_messages(0).unwrap().is_empty());
    }

    #[test]
    fn test_snapshot_to_path_rejects_existing_destination() {
        // Refusing to merge into an existing dir is the snapshot API's
        // contract — silently merging would produce a hybrid DB that's not a
        // true point-in-time snapshot.
        let src_dir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(src_dir.path()).unwrap();

        let dest_dir = tempfile::Builder::new().tempdir().unwrap();
        let err = db.snapshot_to_path(dest_dir.path()).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("already exists"),
            "expected already-exists error, got: {chain}"
        );
    }
}
