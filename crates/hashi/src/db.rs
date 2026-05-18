// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto::traits::ToFromBytes;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fjall::Keyspace;
use fjall::KeyspaceCreateOptions;
use fjall::Result;
use sui_sdk_types::Address;

use hashi_types::committee::BLS12381PublicKey;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::committee::EncryptionPublicKey;

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

    // Column Family used to store BLS signing (protocol) keys.
    //
    // key: big endian u64 for the epoch the key is used for
    // value: BCS-encoded `Bls12381PrivateKey`
    signing_keys: Keyspace,

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
const SIGNING_KEYS_CF_NAME: &str = "signing_keys";
const DEALER_MESSAGES_CF_NAME: &str = "dealer_messages";
const ROTATION_MESSAGES_CF_NAME: &str = "rotation_messages";
const NONCE_MESSAGES_CF_NAME: &str = "nonce_messages";

const RETENTION_EXTRA_EPOCHS: u64 = 7;

/// Keyspaces included in snapshot backups. Add new backup/restore keyspaces here.
#[derive(Clone, Copy)]
enum BackupKeyspace {
    EncryptionKeys,
    SigningKeys,
    DealerMessages,
    RotationMessages,
}

const BACKUP_KEYSPACES: [BackupKeyspace; 4] = [
    BackupKeyspace::EncryptionKeys,
    BackupKeyspace::SigningKeys,
    BackupKeyspace::DealerMessages,
    BackupKeyspace::RotationMessages,
];

impl BackupKeyspace {
    fn name(self) -> &'static str {
        match self {
            Self::EncryptionKeys => ENCRYPTION_KEYS_CF_NAME,
            Self::SigningKeys => SIGNING_KEYS_CF_NAME,
            Self::DealerMessages => DEALER_MESSAGES_CF_NAME,
            Self::RotationMessages => ROTATION_MESSAGES_CF_NAME,
        }
    }

    fn keyspace(self, db: &Database) -> &Keyspace {
        match self {
            Self::EncryptionKeys => &db.encryption_keys,
            Self::SigningKeys => &db.signing_keys,
            Self::DealerMessages => &db.dealer_messages,
            Self::RotationMessages => &db.rotation_messages,
        }
    }
}

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
        let signing_keys = db.keyspace(SIGNING_KEYS_CF_NAME, KeyspaceCreateOptions::default)?;
        let dealer_messages =
            db.keyspace(DEALER_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        let rotation_messages =
            db.keyspace(ROTATION_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        let nonce_messages = db.keyspace(NONCE_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)?;
        Ok(Self {
            db,
            encryption_keys,
            signing_keys,
            dealer_messages,
            rotation_messages,
            nonce_messages,
        })
    }

    pub(crate) fn backup_keyspaces(&self) -> [(&'static str, &Keyspace); 4] {
        BACKUP_KEYSPACES.map(|keyspace| (keyspace.name(), keyspace.keyspace(self)))
    }

    pub(crate) fn backup_keyspace_names() -> [&'static str; 4] {
        BACKUP_KEYSPACES.map(BackupKeyspace::name)
    }

    pub(crate) fn snapshot(&self) -> fjall::Snapshot {
        self.db.snapshot()
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

    pub fn find_encryption_key_matching(
        &self,
        target: &EncryptionPublicKey,
    ) -> Result<Option<EncryptionPrivateKey>> {
        let target_bytes = target.as_element().to_byte_array();
        for guard in self.encryption_keys.iter() {
            let value = guard.value()?;
            let byte_array: [u8; 32] = (&*value).try_into().map_err(|_| {
                fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid point",
                ))
            })?;
            let scalar = match RistrettoScalar::from_byte_array(&byte_array) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let candidate = EncryptionPrivateKey::from(scalar);
            let candidate_pub = EncryptionPublicKey::from_private_key(&candidate);
            if candidate_pub.as_element().to_byte_array() == target_bytes {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
    }

    pub fn store_signing_key(&self, epoch: u64, signing_key: &Bls12381PrivateKey) -> Result<()> {
        let key = epoch.to_be_bytes();
        if !self.signing_keys.contains_key(key)? {
            let value = bcs::to_bytes(signing_key).unwrap();
            self.signing_keys.insert(key, value)?;
        }
        Ok(())
    }

    pub fn get_signing_key(&self, epoch: u64) -> Result<Option<Bls12381PrivateKey>> {
        let key = epoch.to_be_bytes();
        let bytes = match self.signing_keys.get(key) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };
        let signing_key: Bls12381PrivateKey = bcs::from_bytes(&bytes).map_err(|_| {
            fjall::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid BLS signing key encoding",
            ))
        })?;
        Ok(Some(signing_key))
    }

    pub fn latest_signing_key_epoch(&self) -> Result<Option<u64>> {
        let mut latest: Option<u64> = None;
        for guard in self.signing_keys.iter() {
            let key = guard.key()?;
            if let Ok(bytes) = <[u8; 8]>::try_from(key.as_ref()) {
                let epoch = u64::from_be_bytes(bytes);
                latest = Some(latest.map_or(epoch, |l: u64| l.max(epoch)));
            }
        }
        Ok(latest)
    }

    pub fn find_signing_key_matching(
        &self,
        target: &BLS12381PublicKey,
    ) -> Result<Option<Bls12381PrivateKey>> {
        let target_bytes = target.as_ref();
        for guard in self.signing_keys.iter() {
            let value = guard.value()?;
            let candidate: Bls12381PrivateKey = match bcs::from_bytes(&value) {
                Ok(k) => k,
                Err(_) => continue,
            };
            if candidate.public_key().as_ref() == target_bytes {
                return Ok(Some(candidate));
            }
        }
        Ok(None)
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

    /// Prune all MPC keyspaces.
    pub(crate) fn prune_messages_below(
        &self,
        cutoff_epoch: u64,
        pruning_references: &PruningReferences,
    ) -> Result<()> {
        let retention_cutoff = cutoff_epoch.saturating_sub(RETENTION_EXTRA_EPOCHS);
        prune_keyspace_with(&self.encryption_keys, retention_cutoff, |_epoch, value| {
            let Ok(key) = bcs::from_bytes::<EncryptionPrivateKey>(value) else {
                return false;
            };
            let pub_bytes = EncryptionPublicKey::from_private_key(&key)
                .as_element()
                .to_byte_array()
                .to_vec();
            pruning_references.encryption_keys.contains(&pub_bytes)
        })?;
        prune_keyspace_with(&self.signing_keys, retention_cutoff, |_epoch, value| {
            let Ok(key) = bcs::from_bytes::<Bls12381PrivateKey>(value) else {
                return false;
            };
            pruning_references
                .signing_keys
                .contains(key.public_key().as_bytes())
        })?;
        let is_referenced_epoch =
            |epoch: u64, _value: &[u8]| pruning_references.committee_epochs.contains(&epoch);
        prune_keyspace_with(&self.dealer_messages, retention_cutoff, is_referenced_epoch)?;
        prune_keyspace_with(
            &self.rotation_messages,
            retention_cutoff,
            is_referenced_epoch,
        )?;
        prune_keyspace(&self.nonce_messages, cutoff_epoch)?;
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct PruningReferences {
    encryption_keys: std::collections::HashSet<Vec<u8>>,
    signing_keys: std::collections::HashSet<Vec<u8>>,
    committee_epochs: std::collections::HashSet<u64>,
}

impl PruningReferences {
    pub(crate) fn add_member_pubkeys(
        &mut self,
        encryption_public_key: &EncryptionPublicKey,
        signing_public_key: &BLS12381PublicKey,
    ) {
        self.encryption_keys
            .insert(encryption_public_key.as_element().to_byte_array().to_vec());
        self.signing_keys
            .insert(signing_public_key.as_bytes().to_vec());
    }

    pub(crate) fn add_committee_epoch(&mut self, epoch: u64) {
        self.committee_epochs.insert(epoch);
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

/// Delete entries from `keyspace` whose leading big-endian u64 epoch is
/// `< cutoff_epoch`, unless `is_referenced(epoch, value)` returns `true`.
fn prune_keyspace_with<F>(keyspace: &Keyspace, cutoff_epoch: u64, is_referenced: F) -> Result<()>
where
    F: Fn(u64, &[u8]) -> bool,
{
    let keys_to_delete: Vec<_> = keyspace
        .iter()
        .filter_map(|guard| {
            let (key, value) = guard.into_inner().ok()?;
            let epoch_bytes: [u8; 8] = key.as_ref().get(..8)?.try_into().ok()?;
            let epoch = u64::from_be_bytes(epoch_bytes);
            if epoch >= cutoff_epoch {
                return None;
            }
            (!is_referenced(epoch, &value)).then(|| key.to_vec())
        })
        .collect();
    for key in keys_to_delete {
        keyspace.remove(key)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::mpc::EncryptionGroupElement;
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::threshold_schnorr::avss;
    use fastcrypto_tbls::threshold_schnorr::batch_avss;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use sui_sdk_types::Address;

    use super::Database;
    use super::PruningReferences;
    use super::RETENTION_EXTRA_EPOCHS;

    pub(crate) fn create_test_nodes(count: u16) -> Nodes<EncryptionGroupElement> {
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

    pub(crate) fn create_test_message() -> avss::Message {
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

    pub(crate) fn create_test_nonce_message() -> batch_avss::Message {
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
    fn test_find_encryption_key_matching() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let key_a = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key_b = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key_c = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(10, &key_a).unwrap();
        db.store_encryption_key(11, &key_b).unwrap();
        db.store_encryption_key(12, &key_c).unwrap();

        // Looking up by each pub key returns the matching private key.
        for key in [&key_a, &key_b, &key_c] {
            let pub_key = EncryptionPublicKey::from_private_key(key);
            let found = db.find_encryption_key_matching(&pub_key).unwrap().unwrap();
            assert_eq!(&found, key);
        }

        // An unrelated pub key has no match.
        let unrelated = EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(
            &mut rand::thread_rng(),
        ));
        assert!(
            db.find_encryption_key_matching(&unrelated)
                .unwrap()
                .is_none(),
            "no DB key should match an unrelated pub key"
        );
    }

    #[test]
    fn test_signing_key_store_and_get() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let private_key = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        db.store_signing_key(100, &private_key).unwrap();

        let from_db = db.get_signing_key(100).unwrap().unwrap();
        assert_eq!(
            private_key.public_key().as_ref(),
            from_db.public_key().as_ref(),
            "round-tripped signing key should derive the same public key"
        );

        assert!(db.get_signing_key(101).unwrap().is_none());
    }

    #[test]
    fn test_signing_key_idempotent_store() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let key_a = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let key_b = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let pub_a = key_a.public_key().as_ref().to_vec();

        db.store_signing_key(7, &key_a).unwrap();
        // Second store at the same epoch is a no-op (idempotent for restart safety).
        db.store_signing_key(7, &key_b).unwrap();

        let from_db = db.get_signing_key(7).unwrap().unwrap();
        assert_eq!(
            from_db.public_key().as_ref(),
            pub_a,
            "store should be a no-op when an entry already exists at this epoch"
        );
    }

    #[test]
    fn test_find_signing_key_matching() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let key_a = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let key_b = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let key_c = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        db.store_signing_key(10, &key_a).unwrap();
        db.store_signing_key(11, &key_b).unwrap();
        db.store_signing_key(12, &key_c).unwrap();

        for key in [&key_a, &key_b, &key_c] {
            let pub_key = key.public_key();
            let found = db.find_signing_key_matching(&pub_key).unwrap().unwrap();
            assert_eq!(found.public_key().as_ref(), pub_key.as_ref());
        }

        let unrelated = Bls12381PrivateKey::generate(&mut rand::thread_rng()).public_key();
        assert!(
            db.find_signing_key_matching(&unrelated).unwrap().is_none(),
            "no DB key should match an unrelated pub key"
        );
    }

    #[test]
    fn test_latest_signing_key_epoch() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        assert!(db.latest_signing_key_epoch().unwrap().is_none());

        db.store_signing_key(5, &Bls12381PrivateKey::generate(&mut rand::thread_rng()))
            .unwrap();
        assert_eq!(db.latest_signing_key_epoch().unwrap(), Some(5));

        db.store_signing_key(8, &Bls12381PrivateKey::generate(&mut rand::thread_rng()))
            .unwrap();
        db.store_signing_key(3, &Bls12381PrivateKey::generate(&mut rand::thread_rng()))
            .unwrap();
        assert_eq!(db.latest_signing_key_epoch().unwrap(), Some(8));
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
        let sig_key = Bls12381PrivateKey::generate(&mut rand::thread_rng());

        // Cutoff far enough above the retention window that key keyspaces
        // also see prunes (i.e., `cutoff - RETENTION_EXTRA_EPOCHS > 1`).
        let cutoff = RETENTION_EXTRA_EPOCHS + 8;
        let last_epoch = cutoff + 5;
        let key_retain_floor = cutoff - RETENTION_EXTRA_EPOCHS;

        for epoch in 1..=last_epoch {
            db.store_dealer_message(epoch, &dealer, &dealer_msg)
                .unwrap();
            db.store_rotation_messages(epoch, &dealer, &rotation_msgs)
                .unwrap();
            db.store_nonce_message(epoch, 0, &dealer, &nonce_msg)
                .unwrap();
            db.store_encryption_key(epoch, &enc_key).unwrap();
            db.store_signing_key(epoch, &sig_key).unwrap();
        }

        db.prune_messages_below(cutoff, &PruningReferences::default())
            .unwrap();

        let message_retain_floor = key_retain_floor;

        for epoch in 1..message_retain_floor {
            assert!(
                db.get_dealer_message(epoch, &dealer).unwrap().is_none(),
                "dealer message at epoch {epoch} should be pruned (< cutoff - {RETENTION_EXTRA_EPOCHS}, no committee reference)"
            );
            assert!(
                db.get_rotation_messages(epoch, &dealer).unwrap().is_none(),
                "rotation messages at epoch {epoch} should be pruned (< cutoff - {RETENTION_EXTRA_EPOCHS}, no committee reference)"
            );
        }
        for epoch in message_retain_floor..cutoff {
            assert!(
                db.get_dealer_message(epoch, &dealer).unwrap().is_some(),
                "dealer message at epoch {epoch} should be retained (>= cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
            assert!(
                db.get_rotation_messages(epoch, &dealer).unwrap().is_some(),
                "rotation messages at epoch {epoch} should be retained (>= cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
        }
        for epoch in 1..cutoff {
            assert!(
                db.get_nonce_message(epoch, 0, &dealer).unwrap().is_none(),
                "nonce message at epoch {epoch} should be pruned (flat cutoff)"
            );
        }
        for epoch in 1..key_retain_floor {
            assert!(
                db.get_encryption_key(epoch).unwrap().is_none(),
                "encryption key at epoch {epoch} should be pruned (< cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
            assert!(
                db.get_signing_key(epoch).unwrap().is_none(),
                "signing key at epoch {epoch} should be pruned (< cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
        }
        for epoch in key_retain_floor..cutoff {
            assert!(
                db.get_encryption_key(epoch).unwrap().is_some(),
                "encryption key at epoch {epoch} should be retained (>= cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
            assert!(
                db.get_signing_key(epoch).unwrap().is_some(),
                "signing key at epoch {epoch} should be retained (>= cutoff - {RETENTION_EXTRA_EPOCHS})"
            );
        }
        for epoch in cutoff..=last_epoch {
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
            assert!(
                db.get_signing_key(epoch).unwrap().is_some(),
                "signing key at epoch {epoch} should be kept"
            );
        }
    }

    #[test]
    fn test_prune_messages_below_zero_is_no_op() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let message = create_test_message();
        let enc_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let sig_key = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        for epoch in 5..=10 {
            db.store_dealer_message(epoch, &dealer, &message).unwrap();
            db.store_encryption_key(epoch, &enc_key).unwrap();
            db.store_signing_key(epoch, &sig_key).unwrap();
        }

        // Cutoff = 0 saturates the key-retention subtraction; nothing should
        // be pruned in any keyspace.
        db.prune_messages_below(0, &PruningReferences::default())
            .unwrap();

        for epoch in 5..=10 {
            assert!(db.get_dealer_message(epoch, &dealer).unwrap().is_some());
            assert!(db.get_encryption_key(epoch).unwrap().is_some());
            assert!(db.get_signing_key(epoch).unwrap().is_some());
        }
    }

    #[test]
    fn test_prune_messages_below_empty_db() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();
        // Should be a no-op, not an error.
        db.prune_messages_below(100, &PruningReferences::default())
            .unwrap();
    }

    fn referenced_pubkeys_from(
        keys: &[(&EncryptionPrivateKey, &Bls12381PrivateKey)],
    ) -> PruningReferences {
        let mut result = PruningReferences::default();
        for (enc, sig) in keys {
            result.add_member_pubkeys(
                &EncryptionPublicKey::from_private_key(enc),
                &sig.public_key(),
            );
        }
        result
    }

    #[test]
    fn test_prune_messages_below_handles_non_contiguous_committees() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        // Committees 5 and 33 are well below the flat cutoff
        // (`51 - RETENTION_EXTRA_EPOCHS = 44`); only the committee-
        // reference protection should retain them.
        struct ValidatorKeys {
            encryption: EncryptionPrivateKey,
            signing: Bls12381PrivateKey,
        }
        let make_keys = || ValidatorKeys {
            encryption: EncryptionPrivateKey::new(&mut rand::thread_rng()),
            signing: Bls12381PrivateKey::generate(&mut rand::thread_rng()),
        };
        let keys_for_committee_5 = make_keys();
        let keys_for_committee_33 = make_keys();
        let keys_for_committee_51 = make_keys();

        for (epoch, keys) in [
            (5u64, &keys_for_committee_5),
            (33, &keys_for_committee_33),
            (51, &keys_for_committee_51),
        ] {
            db.store_encryption_key(epoch, &keys.encryption).unwrap();
            db.store_signing_key(epoch, &keys.signing).unwrap();
        }

        let referenced = referenced_pubkeys_from(&[
            (
                &keys_for_committee_5.encryption,
                &keys_for_committee_5.signing,
            ),
            (
                &keys_for_committee_33.encryption,
                &keys_for_committee_33.signing,
            ),
            (
                &keys_for_committee_51.encryption,
                &keys_for_committee_51.signing,
            ),
        ]);

        // Prune at cutoff 51. Flat key-retention cutoff is 44. The keys for
        // committees 5 and 33 are below that — without committee-aware
        // protection they would be deleted, even though their pubkeys are
        // still referenced by committees still held on-chain.
        db.prune_messages_below(51, &referenced).unwrap();

        for committee_epoch in [5u64, 33, 51] {
            assert!(
                db.get_encryption_key(committee_epoch).unwrap().is_some(),
                "encryption key for committee[{committee_epoch}] must be retained \
                 (committee record still references its pubkey)"
            );
            assert!(
                db.get_signing_key(committee_epoch).unwrap().is_some(),
                "signing key for committee[{committee_epoch}] must be retained \
                 (committee record still references its pubkey)"
            );
        }
    }

    #[test]
    fn test_prune_messages_below_deletes_unreferenced_keys_below_cutoff() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        // Store a keypair tagged at storage epoch 10, but build a protected
        // pubkey set that references a different pubkey — so the stored
        // keypair is not protected by reference.
        let stored_encryption = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let stored_signing = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        db.store_encryption_key(10, &stored_encryption).unwrap();
        db.store_signing_key(10, &stored_signing).unwrap();

        let committee_member_encryption = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let committee_member_signing = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let referenced =
            referenced_pubkeys_from(&[(&committee_member_encryption, &committee_member_signing)]);

        // Cutoff 20 → flat key cutoff 13; stored keys at epoch 10 are below
        // and not referenced, so should be deleted.
        db.prune_messages_below(20, &referenced).unwrap();

        assert!(
            db.get_encryption_key(10).unwrap().is_none(),
            "unreferenced encryption key at storage epoch 10 should be pruned"
        );
        assert!(
            db.get_signing_key(10).unwrap().is_none(),
            "unreferenced signing key at storage epoch 10 should be pruned"
        );
    }

    #[test]
    fn test_prune_messages_below_retains_in_flight_key_within_cutoff_window() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        // Simulates the state right after `prepare_and_register_keys(N+1)`
        // has stored next-epoch keys but `start_reconfig(N+1)` has not
        // captured them. Storage epoch (N+1) is above the flat cutoff
        // (N - RETENTION_EXTRA_EPOCHS) but no committee references it.
        let target_epoch = 20u64;
        let in_flight_epoch = target_epoch + 1;
        let in_flight_encryption = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let in_flight_signing = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        db.store_encryption_key(in_flight_epoch, &in_flight_encryption)
            .unwrap();
        db.store_signing_key(in_flight_epoch, &in_flight_signing)
            .unwrap();

        // No committee references the in-flight key.
        db.prune_messages_below(target_epoch, &PruningReferences::default())
            .unwrap();

        assert!(
            db.get_encryption_key(in_flight_epoch).unwrap().is_some(),
            "in-flight encryption key (stored before start_reconfig captures it) must be retained by the flat cutoff"
        );
        assert!(
            db.get_signing_key(in_flight_epoch).unwrap().is_some(),
            "in-flight signing key (stored before start_reconfig captures it) must be retained by the flat cutoff"
        );
    }

    #[test]
    fn test_prune_messages_below_committee_epoch_retains_dealer_and_rotation_messages_below_buffer()
    {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let dealer_msg = create_test_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        // Storage epoch 5 sits well below the flat retention floor at
        // cutoff=20 (floor = 20 - 7 = 13). Only committee-epoch protection
        // can rescue it. Storage epoch 3 stays unreferenced.
        db.store_dealer_message(5, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(5, &dealer, &rotation_msgs)
            .unwrap();
        db.store_dealer_message(3, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(3, &dealer, &rotation_msgs)
            .unwrap();

        // Models the abort_reconfig + multi-epoch jump scenario where
        // committee[5] is the previous-finalized bridge to committee[20].
        let mut referenced = PruningReferences::default();
        referenced.add_committee_epoch(5);

        db.prune_messages_below(20, &referenced).unwrap();

        assert!(
            db.get_dealer_message(5, &dealer).unwrap().is_some(),
            "dealer message at storage_epoch=5 must be retained (committee_epochs={{5}})"
        );
        assert!(
            db.get_rotation_messages(5, &dealer).unwrap().is_some(),
            "rotation messages at storage_epoch=5 must be retained (committee_epochs={{5}})"
        );
        assert!(
            db.get_dealer_message(3, &dealer).unwrap().is_none(),
            "dealer message at storage_epoch=3 must be pruned (not referenced, below buffer)"
        );
        assert!(
            db.get_rotation_messages(3, &dealer).unwrap().is_none(),
            "rotation messages at storage_epoch=3 must be pruned (not referenced, below buffer)"
        );
    }

    #[test]
    fn test_prune_messages_below_buffer_retains_recent_dealer_and_rotation_messages() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let dealer_msg = create_test_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        // Storage epochs 8 and 14 are within the 7-epoch buffer at cutoff=15
        // (floor = 15 - 7 = 8). Empty references — only the buffer protects.
        for epoch in [5u64, 8, 14] {
            db.store_dealer_message(epoch, &dealer, &dealer_msg)
                .unwrap();
            db.store_rotation_messages(epoch, &dealer, &rotation_msgs)
                .unwrap();
        }

        db.prune_messages_below(15, &PruningReferences::default())
            .unwrap();

        assert!(
            db.get_dealer_message(5, &dealer).unwrap().is_none(),
            "dealer message at storage_epoch=5 must be pruned (below buffer floor 8)"
        );
        assert!(
            db.get_rotation_messages(5, &dealer).unwrap().is_none(),
            "rotation messages at storage_epoch=5 must be pruned (below buffer floor 8)"
        );
        for epoch in [8u64, 14] {
            assert!(
                db.get_dealer_message(epoch, &dealer).unwrap().is_some(),
                "dealer message at storage_epoch={epoch} must be retained (buffer)"
            );
            assert!(
                db.get_rotation_messages(epoch, &dealer).unwrap().is_some(),
                "rotation messages at storage_epoch={epoch} must be retained (buffer)"
            );
        }
    }

    #[test]
    fn test_prune_messages_below_still_prunes_other_keyspaces_with_references() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path()).unwrap();

        let dealer = Address::new([1u8; 32]);
        let dealer_msg = create_test_message();
        let mut rotation_msgs: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        rotation_msgs.insert(NonZeroU16::new(1).unwrap(), create_test_message());
        let nonce_msg = create_test_nonce_message();

        // Write at storage epoch 5 (well below any plausible cutoff).
        db.store_dealer_message(5, &dealer, &dealer_msg).unwrap();
        db.store_rotation_messages(5, &dealer, &rotation_msgs)
            .unwrap();
        db.store_nonce_message(5, 0, &dealer, &nonce_msg).unwrap();

        // A non-empty protected pubkey set — irrelevant to
        // dealer/rotation/nonce keyspaces, just exercises the path where
        // committee-aware retention is in play yet must not bleed over into
        // these keyspaces.
        let enc = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let sig = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        let referenced = referenced_pubkeys_from(&[(&enc, &sig)]);

        db.prune_messages_below(20, &referenced).unwrap();

        assert!(
            db.get_dealer_message(5, &dealer).unwrap().is_none(),
            "dealer message at storage epoch 5 should be pruned (committee-awareness does not protect this keyspace)"
        );
        assert!(
            db.get_rotation_messages(5, &dealer).unwrap().is_none(),
            "rotation messages at storage epoch 5 should be pruned"
        );
        assert!(
            db.get_nonce_message(5, 0, &dealer).unwrap().is_none(),
            "nonce message at storage epoch 5 should be pruned"
        );
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
}
