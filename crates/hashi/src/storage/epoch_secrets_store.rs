use std::sync::Arc;

use anyhow::Result;
use hashi_types::committee::EncryptionPrivateKey;

use crate::db::Database;
use crate::storage::SecretsStore;

pub struct EpochSecretsStore {
    db: Arc<Database>,
    epoch: u64,
}

impl EpochSecretsStore {
    pub fn new(db: Arc<Database>, epoch: u64) -> Self {
        Self { db, epoch }
    }
}

impl SecretsStore for EpochSecretsStore {
    fn store_encryption_key(&mut self, key: &EncryptionPrivateKey) -> Result<()> {
        self.db
            .store_encryption_key(Some(self.epoch), key)
            .map_err(|e| anyhow::anyhow!("failed to store encryption key: {e}"))
    }

    fn get_encryption_key(&self) -> Result<Option<EncryptionPrivateKey>> {
        self.db
            .get_encryption_key(Some(self.epoch))
            .map_err(|e| anyhow::anyhow!("failed to get encryption key: {e}"))
    }

    fn clear(&mut self) -> Result<()> {
        self.db
            .clear_encryption_key(self.epoch)
            .map_err(|e| anyhow::anyhow!("failed to clear encryption key: {e}"))
    }
}
