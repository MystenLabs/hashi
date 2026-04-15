// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use sui_sdk_types::Address;

use crate::db::Database;
use crate::mpc::types::Messages;
use crate::mpc::types::RotationMessages;
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
        epoch: u64,
        dealer: &Address,
        message: &avss::Message,
    ) -> anyhow::Result<()> {
        self.db
            .store_dealer_message(epoch, dealer, message)
            .map_err(|e| anyhow::anyhow!("failed to store dealer message: {e}"))
    }

    fn get_dealer_message(
        &self,
        epoch: u64,
        dealer: &Address,
    ) -> anyhow::Result<Option<avss::Message>> {
        self.db
            .get_dealer_message(epoch, dealer)
            .map_err(|e| anyhow::anyhow!("failed to get dealer message: {e}"))
    }

    fn list_all_dealer_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
        self.db
            .list_all_dealer_messages(self.epoch)
            .map(|msgs| {
                msgs.into_iter()
                    .map(|(addr, msg)| (addr, Messages::Dkg(msg)))
                    .collect()
            })
            .map_err(|e| anyhow::anyhow!("failed to list dealer messages: {e}"))
    }

    fn store_rotation_messages(
        &mut self,
        epoch: u64,
        dealer: &Address,
        messages: &RotationMessages,
    ) -> anyhow::Result<()> {
        self.db
            .store_rotation_messages(epoch, dealer, messages)
            .map_err(|e| anyhow::anyhow!("failed to store rotation messages: {e}"))
    }

    fn get_rotation_messages(
        &self,
        epoch: u64,
        dealer: &Address,
    ) -> anyhow::Result<Option<RotationMessages>> {
        self.db
            .get_rotation_messages(epoch, dealer)
            .map_err(|e| anyhow::anyhow!("failed to get rotation messages: {e}"))
    }

    fn list_all_rotation_messages(&self) -> anyhow::Result<Vec<(Address, Messages)>> {
        self.db
            .list_all_rotation_messages(self.epoch)
            .map(|msgs| {
                msgs.into_iter()
                    .map(|(addr, msg)| (addr, Messages::Rotation(msg)))
                    .collect()
            })
            .map_err(|e| anyhow::anyhow!("failed to list rotation messages: {e}"))
    }

    fn store_nonce_message(
        &mut self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
        message: &batch_avss::Message,
    ) -> anyhow::Result<()> {
        self.db
            .store_nonce_message(epoch, batch_index, dealer, message)
            .map_err(|e| anyhow::anyhow!("failed to store nonce message: {e}"))
    }

    fn get_nonce_message(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> anyhow::Result<Option<batch_avss::Message>> {
        self.db
            .get_nonce_message(epoch, batch_index, dealer)
            .map_err(|e| anyhow::anyhow!("failed to get nonce message: {e}"))
    }

    fn list_nonce_messages(
        &self,
        batch_index: u32,
    ) -> anyhow::Result<Vec<(Address, batch_avss::Message)>> {
        self.db
            .list_nonce_messages(self.epoch, batch_index)
            .map_err(|e| anyhow::anyhow!("failed to list nonce messages: {e}"))
    }
}
