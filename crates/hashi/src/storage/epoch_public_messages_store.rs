use std::sync::Arc;

use fastcrypto_tbls::threshold_schnorr::avss;
use sui_sdk_types::Address;

use crate::db::Database;
use crate::storage::PublicMessagesStore;

pub struct EpochPublicMessagesStore {
    db: Arc<Database>,
    epoch: u64,
}

impl EpochPublicMessagesStore {
    pub fn new(db: Arc<Database>, epoch: u64) -> Self {
        Self { db, epoch }
    }
}

impl PublicMessagesStore for EpochPublicMessagesStore {
    fn store_dealer_message(
        &mut self,
        dealer: &Address,
        message: &avss::Message,
    ) -> anyhow::Result<()> {
        self.db
            .store_dealer_message(self.epoch, dealer, message)
            .map_err(|e| anyhow::anyhow!("failed to store dealer message: {e}"))
    }

    fn get_dealer_message(&self, dealer: &Address) -> anyhow::Result<Option<avss::Message>> {
        self.db
            .get_dealer_message(self.epoch, dealer)
            .map_err(|e| anyhow::anyhow!("failed to get dealer message: {e}"))
    }

    fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, avss::Message)>> {
        self.db
            .list_all_dealer_messages(self.epoch)
            .map_err(|e| anyhow::anyhow!("failed to list dealer messages: {e}"))
    }

    fn clear(&mut self) -> anyhow::Result<()> {
        self.db
            .clear_dealer_messages(self.epoch)
            .map_err(|e| anyhow::anyhow!("failed to clear dealer messages: {e}"))
    }
}
