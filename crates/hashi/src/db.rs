use std::path::Path;

use fastcrypto::groups::ristretto255::RistrettoScalar;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::threshold_schnorr::avss;
use fjall::Keyspace;
use fjall::KeyspaceCreateOptions;
use fjall::Result;
use sui_sdk_types::Address;

use crate::committee::EncryptionPrivateKey;

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
}

#[cfg(test)]
mod tests {
    use crate::committee::EncryptionPrivateKey;

    use super::Database;

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
}
