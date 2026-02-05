use std::path::Path;

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::avss;
use fjall::Keyspace;
use fjall::KeyspaceCreateOptions;
use fjall::Result;
use sui_sdk_types::Address;

use hashi_types::committee::EncryptionPrivateKey;

use crate::mpc::types::RotationMessages;

pub struct Database {
    #[allow(unused)]
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
}

const ENCRYPTION_KEYS_CF_NAME: &str = "encryption_keys";
const DEALER_MESSAGES_CF_NAME: &str = "dealer_messages";
const ROTATION_MESSAGES_CF_NAME: &str = "rotation_messages";

impl Database {
    pub fn open(path: &Path) -> Self {
        let db = fjall::Database::builder(path).open().unwrap();
        let encryption_keys = db
            .keyspace(ENCRYPTION_KEYS_CF_NAME, KeyspaceCreateOptions::default)
            .unwrap();
        let dealer_messages = db
            .keyspace(DEALER_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)
            .unwrap();
        let rotation_messages = db
            .keyspace(ROTATION_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)
            .unwrap();
        Self {
            db,
            encryption_keys,
            dealer_messages,
            rotation_messages,
        }
    }

    /// Store encryption key for the given epoch.
    ///
    /// No-op if a key already exists for this epoch (idempotent for restart safety).
    /// Also cleans up old encryption keys (keeps only current and previous epoch).
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
        self.cleanup_old_encryption_keys(epoch)?;
        Ok(())
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

    /// Clear encryption keys older than `current_epoch - 1` to limit exposure if the node is
    /// compromised.
    fn cleanup_old_encryption_keys(&self, current_epoch: u64) -> Result<()> {
        let cutoff = current_epoch.saturating_sub(1);
        let keys_to_delete: Vec<_> = self
            .encryption_keys
            .iter()
            .filter_map(|guard| {
                let key = guard.key().ok()?;
                let epoch_bytes: [u8; 8] = key.as_ref().try_into().ok()?;
                let epoch = u64::from_be_bytes(epoch_bytes);
                if epoch < cutoff { Some(epoch) } else { None }
            })
            .collect();
        for epoch in keys_to_delete {
            self.encryption_keys.remove(epoch.to_be_bytes())?;
        }
        Ok(())
    }

    pub fn store_dealer_message(
        &self,
        epoch: u64,
        dealer: &Address,
        message: &avss::Message,
    ) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        let value = bcs::to_bytes(message).unwrap();
        self.dealer_messages.insert(key, value)?;
        clean_up_old_epochs(&self.dealer_messages, epoch)
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
        let prefix = epoch.to_be_bytes();
        let mut results = Vec::new();
        for guard in self.dealer_messages.prefix(prefix) {
            let (key, value) = guard.into_inner()?;
            // Key format: [epoch (8 bytes) | address (32 bytes)]
            let address_bytes: [u8; 32] = key[8..].try_into().map_err(|_| {
                fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid key length",
                ))
            })?;
            let address = Address::new(address_bytes);
            let message: avss::Message = bcs::from_bytes(&value).map_err(|_| {
                fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid message",
                ))
            })?;
            results.push((address, message));
        }
        Ok(results)
    }

    pub fn store_rotation_messages(
        &self,
        epoch: u64,
        dealer: &Address,
        messages: &RotationMessages,
    ) -> Result<()> {
        let key = [epoch.to_be_bytes().as_slice(), dealer.as_bytes()].concat();
        let value = bcs::to_bytes(messages).unwrap();
        self.rotation_messages.insert(key, value)?;
        clean_up_old_epochs(&self.rotation_messages, epoch)
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
        let prefix = epoch.to_be_bytes();
        let mut results = Vec::new();
        for guard in self.rotation_messages.prefix(prefix) {
            let (key, value) = guard.into_inner()?;
            // Key format: [epoch (8 bytes) | address (32 bytes)]
            let address_bytes: [u8; 32] = key[8..].try_into().map_err(|_| {
                fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid key length",
                ))
            })?;
            let address = Address::new(address_bytes);
            let messages: RotationMessages = bcs::from_bytes(&value).map_err(|_| {
                fjall::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid rotation messages",
                ))
            })?;
            results.push((address, messages));
        }
        Ok(results)
    }
}

/// Delete entries from keyspace where key starts with epoch (big-endian u64) < cutoff.
/// Cutoff is `current_epoch - 1`, keeping current and previous epoch.
fn clean_up_old_epochs(keyspace: &Keyspace, current_epoch: u64) -> Result<()> {
    let cutoff = current_epoch.saturating_sub(1);
    let keys_to_delete: Vec<_> = keyspace
        .iter()
        .filter_map(|guard| {
            let key = guard.key().ok()?;
            let epoch_bytes: [u8; 8] = key.as_ref().get(..8)?.try_into().ok()?;
            let epoch = u64::from_be_bytes(epoch_bytes);
            if epoch < cutoff {
                Some(key.to_vec())
            } else {
                None
            }
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
            1, // max_faulty
            b"test-session".to_vec(),
        )
        .unwrap();
        dealer.create_message(&mut rand::thread_rng())
    }

    #[test]
    fn test_encryption_key() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

        let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());

        db.store_encryption_key(100, &private_key).unwrap();
        let key_from_db = db.get_encryption_key(100).unwrap().unwrap();

        assert_eq!(private_key, key_from_db);

        assert!(db.get_encryption_key(101).unwrap().is_none());
        drop(db);

        // Test persistence across reopen
        let db = Database::open(tmpdir.path());
        assert_eq!(private_key, db.get_encryption_key(100).unwrap().unwrap());
        assert!(db.get_encryption_key(101).unwrap().is_none());

        // Test that storing twice is idempotent
        let another_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        db.store_encryption_key(100, &another_key).unwrap();
        assert_eq!(private_key, db.get_encryption_key(100).unwrap().unwrap());
    }

    #[test]
    fn test_automatic_cleanup_on_store() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

        let key1 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key2 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key3 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key4 = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let key5 = EncryptionPrivateKey::new(&mut rand::thread_rng());

        // Store epoch 1 - cleanup(1) is no-op (epoch < 2)
        db.store_encryption_key(1, &key1).unwrap();
        assert!(db.get_encryption_key(1).unwrap().is_some());

        // Store epoch 2 - cleanup(2) cutoff=1, deletes nothing
        db.store_encryption_key(2, &key2).unwrap();
        assert!(db.get_encryption_key(1).unwrap().is_some());
        assert!(db.get_encryption_key(2).unwrap().is_some());

        // Store epoch 3 - cleanup(3) cutoff=2, deletes epoch 1
        db.store_encryption_key(3, &key3).unwrap();
        assert!(db.get_encryption_key(1).unwrap().is_none()); // deleted
        assert!(db.get_encryption_key(2).unwrap().is_some());
        assert!(db.get_encryption_key(3).unwrap().is_some());

        // Store epoch 4 - cleanup(4) cutoff=3, deletes epoch 2
        db.store_encryption_key(4, &key4).unwrap();
        assert!(db.get_encryption_key(2).unwrap().is_none()); // deleted
        assert!(db.get_encryption_key(3).unwrap().is_some());
        assert!(db.get_encryption_key(4).unwrap().is_some());

        // Store epoch 5 - cleanup(5) cutoff=4, deletes epoch 3
        db.store_encryption_key(5, &key5).unwrap();
        assert!(db.get_encryption_key(3).unwrap().is_none()); // deleted
        assert_eq!(key4, db.get_encryption_key(4).unwrap().unwrap());
        assert_eq!(key5, db.get_encryption_key(5).unwrap().unwrap());
    }

    #[test]
    fn test_dealer_messages() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

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
        let db = Database::open(tmpdir.path());
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_some());
        assert!(db.get_dealer_message(2, &dealer1).unwrap().is_some());
    }

    #[test]
    fn test_dealer_messages_auto_cleanup() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

        let dealer = Address::new([1u8; 32]);
        let message = create_test_message();

        // Store in epoch 5 - cleanup happens for epochs < 4, but nothing exists yet
        db.store_dealer_message(5, &dealer, &message).unwrap();
        assert!(db.get_dealer_message(5, &dealer).unwrap().is_some());

        // Store in epoch 6 - cleanup happens for epochs < 5, so epoch 5 remains
        db.store_dealer_message(6, &dealer, &message).unwrap();
        assert!(db.get_dealer_message(5, &dealer).unwrap().is_some());
        assert!(db.get_dealer_message(6, &dealer).unwrap().is_some());

        // Store in epoch 7 - cleanup happens for epochs < 6, so epoch 5 is deleted
        db.store_dealer_message(7, &dealer, &message).unwrap();
        assert!(
            db.get_dealer_message(5, &dealer).unwrap().is_none(),
            "epoch 5 should be cleaned up"
        );
        assert!(
            db.get_dealer_message(6, &dealer).unwrap().is_some(),
            "epoch 6 should remain"
        );
        assert!(
            db.get_dealer_message(7, &dealer).unwrap().is_some(),
            "epoch 7 should remain"
        );
    }

    #[test]
    fn test_list_all_dealer_messages() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

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
        let db = Database::open(tmpdir.path());

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
        let db = Database::open(tmpdir.path());
        let all = db.list_all_rotation_messages(1).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_rotation_messages_auto_cleanup() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

        let dealer = Address::new([1u8; 32]);
        let mut messages: BTreeMap<NonZeroU16, avss::Message> = BTreeMap::new();
        messages.insert(NonZeroU16::new(1).unwrap(), create_test_message());

        // Store in epoch 5 - cleanup happens for epochs < 4, but nothing exists yet
        db.store_rotation_messages(5, &dealer, &messages).unwrap();
        assert_eq!(db.list_all_rotation_messages(5).unwrap().len(), 1);

        // Store in epoch 6 - cleanup happens for epochs < 5, so epoch 5 remains
        db.store_rotation_messages(6, &dealer, &messages).unwrap();
        assert_eq!(db.list_all_rotation_messages(5).unwrap().len(), 1);
        assert_eq!(db.list_all_rotation_messages(6).unwrap().len(), 1);

        // Store in epoch 7 - cleanup happens for epochs < 6, so epoch 5 is deleted
        db.store_rotation_messages(7, &dealer, &messages).unwrap();
        assert!(
            db.list_all_rotation_messages(5).unwrap().is_empty(),
            "epoch 5 should be cleaned up"
        );
        assert_eq!(
            db.list_all_rotation_messages(6).unwrap().len(),
            1,
            "epoch 6 should remain"
        );
        assert_eq!(
            db.list_all_rotation_messages(7).unwrap().len(),
            1,
            "epoch 7 should remain"
        );
    }

    #[test]
    fn test_list_all_rotation_messages() {
        use std::collections::BTreeMap;
        use std::num::NonZeroU16;

        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

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
}
