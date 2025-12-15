use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use fastcrypto_tbls::ecies_v1::PrivateKey;
use fastcrypto_tbls::threshold_schnorr::avss;
use sui_sdk_types::Address;

use super::PublicMessagesStore;
use super::SecretsStore;
use crate::dkg::EncryptionGroupElement;

const MESSAGE_FILE_EXTENSION: &str = "bin";

fn clear_dir(dir: &Path) -> Result<()> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// File-based storage for DKG dealer messages.
///
/// ## Directory Layout
///
/// ```text
/// {dir}/
/// ├── 0x0000000000000000000000000000000000000000000000000000000000000001.bin
/// ├── 0x0000000000000000000000000000000000000000000000000000000000000002.bin
/// └── ...
/// ```
///
/// Each file is named `{dealer_address}.bin` where `dealer_address` is the
/// hex-encoded Sui address of the dealer. Files contain BCS-serialized
/// `avss::Message` data (~100KB per message).
///
/// The directory is created on construction if it doesn't exist.
/// Calling `clear()` removes all files and recreates the empty directory.
pub struct FilePublicMessagesStore {
    dir: PathBuf,
}

impl FilePublicMessagesStore {
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn message_path(&self, dealer: &Address) -> PathBuf {
        self.dir
            .join(format!("{}.{}", dealer, MESSAGE_FILE_EXTENSION))
    }
}

impl PublicMessagesStore for FilePublicMessagesStore {
    fn store_dealer_message(&mut self, dealer: &Address, message: &avss::Message) -> Result<()> {
        let bytes = bcs::to_bytes(message)?;
        std::fs::write(self.message_path(dealer), bytes)?;
        Ok(())
    }

    fn list_all(&self) -> Result<Vec<(Address, avss::Message)>> {
        let mut results = Vec::new();
        if !self.dir.exists() {
            return Ok(results);
        }
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|ext| ext == MESSAGE_FILE_EXTENSION)
            {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .ok_or_else(|| anyhow::anyhow!("invalid filename"))?;
                let dealer: Address = stem.parse()?;
                let bytes = std::fs::read(&path)?;
                let message: avss::Message = bcs::from_bytes(&bytes)?;
                results.push((dealer, message));
            }
        }
        Ok(results)
    }

    fn clear(&mut self) -> Result<()> {
        clear_dir(&self.dir)
    }
}

/// File-based storage for DKG secrets (encryption keys).
///
/// ## Directory Layout
///
/// ```text
/// {dir}/
/// └── encryption_key.bin
/// ```
///
/// The encryption key file contains a BCS-serialized
/// `PrivateKey<EncryptionGroupElement>`. Only one key is stored per directory.
///
/// The directory is created on construction if it doesn't exist.
/// `store_encryption_key()` fails if the key file already exists (no overwrite).
/// Calling `clear()` removes all files and recreates the empty directory.
pub struct FileSecretsStore {
    dir: PathBuf,
}

impl FileSecretsStore {
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn key_path(&self) -> PathBuf {
        self.dir.join("encryption_key.bin")
    }
}

impl SecretsStore for FileSecretsStore {
    fn store_encryption_key(&mut self, key: &PrivateKey<EncryptionGroupElement>) -> Result<()> {
        let path = self.key_path();
        if path.exists() {
            anyhow::bail!("encryption key already exists");
        }
        let bytes = bcs::to_bytes(key)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    fn get_encryption_key(&self) -> Result<Option<PrivateKey<EncryptionGroupElement>>> {
        let path = self.key_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path)?;
        Ok(Some(bcs::from_bytes(&bytes)?))
    }

    fn clear(&mut self) -> Result<()> {
        clear_dir(&self.dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastcrypto_tbls::ecies_v1::PrivateKey;
    use fastcrypto_tbls::ecies_v1::PublicKey;
    use fastcrypto_tbls::nodes::Node;
    use fastcrypto_tbls::nodes::Nodes;
    use fastcrypto_tbls::threshold_schnorr::avss::Dealer;
    use tempfile::tempdir;

    fn create_test_message() -> avss::Message {
        let mut rng = rand::thread_rng();
        let pk1 = PublicKey::from_private_key(&PrivateKey::<EncryptionGroupElement>::new(&mut rng));
        let pk2 = PublicKey::from_private_key(&PrivateKey::<EncryptionGroupElement>::new(&mut rng));
        let nodes = Nodes::new(vec![
            Node {
                id: 0,
                pk: pk1,
                weight: 1,
            },
            Node {
                id: 1,
                pk: pk2,
                weight: 1,
            },
        ])
        .unwrap();
        let dealer = Dealer::new(None, nodes, 1, 0, b"test_session".to_vec()).unwrap();
        dealer.create_message(&mut rng).unwrap()
    }

    fn find_message(store: &FilePublicMessagesStore, dealer: &Address) -> Option<avss::Message> {
        store
            .list_all()
            .unwrap()
            .into_iter()
            .find(|(d, _)| d == dealer)
            .map(|(_, m)| m)
    }

    #[test]
    fn test_public_messages_store_and_get() {
        let dir = tempdir().unwrap();
        let mut store = FilePublicMessagesStore::new(dir.path().join("messages")).unwrap();
        let dealer = Address::ZERO;
        let message = create_test_message();

        assert!(find_message(&store, &dealer).is_none());

        store.store_dealer_message(&dealer, &message).unwrap();

        let retrieved = find_message(&store, &dealer).unwrap();
        assert_eq!(
            bcs::to_bytes(&retrieved).unwrap(),
            bcs::to_bytes(&message).unwrap()
        );
    }

    #[test]
    fn test_public_messages_overwrite() {
        let dir = tempdir().unwrap();
        let mut store = FilePublicMessagesStore::new(dir.path().join("messages")).unwrap();
        let dealer = Address::ZERO;

        let message1 = create_test_message();
        let message2 = create_test_message();

        store.store_dealer_message(&dealer, &message1).unwrap();
        store.store_dealer_message(&dealer, &message2).unwrap();

        let retrieved = find_message(&store, &dealer).unwrap();
        assert_eq!(
            bcs::to_bytes(&retrieved).unwrap(),
            bcs::to_bytes(&message2).unwrap()
        );
    }

    #[test]
    fn test_public_messages_clear() {
        let dir = tempdir().unwrap();
        let mut store = FilePublicMessagesStore::new(dir.path().join("messages")).unwrap();
        let dealer = Address::ZERO;
        let message = create_test_message();

        store.store_dealer_message(&dealer, &message).unwrap();
        store.clear().unwrap();

        assert!(find_message(&store, &dealer).is_none());
    }

    #[test]
    fn test_public_messages_list_all() {
        let dir = tempdir().unwrap();
        let mut store = FilePublicMessagesStore::new(dir.path().join("messages")).unwrap();

        // Empty store
        assert!(store.list_all().unwrap().is_empty());

        // Add two messages
        let dealer1 = Address::ZERO;
        let dealer2 = Address::new([1; 32]);
        let message1 = create_test_message();
        let message2 = create_test_message();

        store.store_dealer_message(&dealer1, &message1).unwrap();
        store.store_dealer_message(&dealer2, &message2).unwrap();

        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 2);

        let dealers: std::collections::HashSet<_> = all.iter().map(|(d, _)| *d).collect();
        assert!(dealers.contains(&dealer1));
        assert!(dealers.contains(&dealer2));
    }

    #[test]
    fn test_secrets_store_and_get() {
        let dir = tempdir().unwrap();
        let mut store = FileSecretsStore::new(dir.path().join("secrets")).unwrap();
        let key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());

        assert!(store.get_encryption_key().unwrap().is_none());

        store.store_encryption_key(&key).unwrap();

        let retrieved = store.get_encryption_key().unwrap().unwrap();
        assert_eq!(retrieved, key);
    }

    #[test]
    fn test_secrets_store_fails_if_exists() {
        let dir = tempdir().unwrap();
        let mut store = FileSecretsStore::new(dir.path().join("secrets")).unwrap();
        let key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());

        store.store_encryption_key(&key).unwrap();
        assert!(store.store_encryption_key(&key).is_err());
    }

    #[test]
    fn test_secrets_clear() {
        let dir = tempdir().unwrap();
        let mut store = FileSecretsStore::new(dir.path().join("secrets")).unwrap();
        let key = PrivateKey::<EncryptionGroupElement>::new(&mut rand::thread_rng());

        store.store_encryption_key(&key).unwrap();
        store.clear().unwrap();

        assert!(store.get_encryption_key().unwrap().is_none());
    }
}
