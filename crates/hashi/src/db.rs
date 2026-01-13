use std::path::Path;

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::avss;
use fjall::Keyspace;
use fjall::KeyspaceCreateOptions;
use fjall::Result;
use sui_sdk_types::Address;

use hashi_types::committee::EncryptionPrivateKey;

pub struct Database {
    #[allow(unused)]
    db: fjall::Database,
    // keyspaces

    // Column Family used to store encryption keys.
    //
    // key: big endian u64 for the epoch the key is used for
    // value: 32-byte RistrettoScalar
    encryption_keys: Keyspace,

    // Column Family used to store dealer messages for DKG and key rotation.
    //
    // key: (big endian u64 epoch) + (32-byte validator address)
    // value: avss::Message
    dealer_messages: Keyspace,
}

const ENCRYPTION_KEYS_CF_NAME: &str = "encryption_keys";
const DEALER_MESSAGES_CF_NAME: &str = "dealer_messages";

impl Database {
    pub fn open(path: &Path) -> Self {
        let db = fjall::Database::builder(path).open().unwrap();

        let encryption_keys = db
            .keyspace(ENCRYPTION_KEYS_CF_NAME, KeyspaceCreateOptions::default)
            .unwrap();
        let dealer_messages = db
            .keyspace(DEALER_MESSAGES_CF_NAME, KeyspaceCreateOptions::default)
            .unwrap();

        Self {
            db,
            encryption_keys,
            dealer_messages,
        }
    }

    pub fn store_encryption_key(
        &self,
        epoch: Option<u64>,
        encryption_key: &EncryptionPrivateKey,
    ) -> Result<()> {
        let key = epoch.unwrap_or(u64::MAX).to_be_bytes();
        let value = bcs::to_bytes(encryption_key).unwrap();

        self.encryption_keys.insert(key, value)
    }

    pub fn get_encryption_key(&self, epoch: Option<u64>) -> Result<Option<EncryptionPrivateKey>> {
        let key = epoch.unwrap_or(u64::MAX).to_be_bytes();
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

    pub fn clear_dealer_messages(&self, epoch: u64) -> Result<()> {
        let prefix = epoch.to_be_bytes();
        for guard in self.dealer_messages.prefix(prefix) {
            let key = guard.key()?;
            self.dealer_messages.remove(key)?;
        }
        Ok(())
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
}

#[cfg(test)]
mod tests {
    use crate::dkg::EncryptionGroupElement;
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
        dealer.create_message(&mut rand::thread_rng()).unwrap()
    }

    #[test]
    fn test_encryption_key() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let db = Database::open(tmpdir.path());

        let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());

        db.store_encryption_key(None, &private_key).unwrap();
        let key_from_db = db.get_encryption_key(None).unwrap().unwrap();

        assert_eq!(private_key, key_from_db);

        db.store_encryption_key(Some(100), &private_key).unwrap();
        let key_from_db = db.get_encryption_key(Some(100)).unwrap().unwrap();

        assert_eq!(private_key, key_from_db);

        assert!(db.get_encryption_key(Some(101)).unwrap().is_none());
        drop(db);

        let db = Database::open(tmpdir.path());
        assert_eq!(private_key, db.get_encryption_key(None).unwrap().unwrap());
        assert_eq!(
            private_key,
            db.get_encryption_key(Some(100)).unwrap().unwrap()
        );
        assert!(db.get_encryption_key(Some(101)).unwrap().is_none());
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

        // Clear epoch 1 - should only clear epoch 1
        db.clear_dealer_messages(1).unwrap();
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_none());
        assert!(db.get_dealer_message(1, &dealer2).unwrap().is_none());
        assert!(db.get_dealer_message(2, &dealer1).unwrap().is_some());

        // Verify persistence across reopen
        drop(db);
        let db = Database::open(tmpdir.path());
        assert!(db.get_dealer_message(1, &dealer1).unwrap().is_none());
        assert!(db.get_dealer_message(2, &dealer1).unwrap().is_some());
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

        // Clear epoch 1 and verify list is empty
        db.clear_dealer_messages(1).unwrap();
        let result = db.list_all_dealer_messages(1).unwrap();
        assert!(result.is_empty());

        // Epoch 2 should still have its message
        let result = db.list_all_dealer_messages(2).unwrap();
        assert_eq!(result.len(), 1);
    }
}
