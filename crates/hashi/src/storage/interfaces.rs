// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use fastcrypto_tbls::threshold_schnorr::avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss;
use fastcrypto_tbls::threshold_schnorr::batch_avss_avid;
use sui_sdk_types::Address;

pub use crate::mpc::types::AvidRoundState;
use crate::mpc::types::HeldAvidEchoes;
pub use crate::mpc::types::Messages;
pub use crate::mpc::types::RotationMessages;

pub trait PublicMessagesStore: Send + Sync {
    /// Store a dealer's DKG message at the given epoch.
    /// If a message already exists for this dealer, it will be overwritten.
    fn store_dealer_message(
        &mut self,
        epoch: u64,
        dealer: &Address,
        message: &avss::Message,
    ) -> Result<()>;

    /// Retrieve a dealer's DKG message for the given epoch.
    /// Returns None if no message exists for this dealer.
    fn get_dealer_message(&self, epoch: u64, dealer: &Address) -> Result<Option<avss::Message>>;

    /// List all stored dealer messages for the current epoch.
    fn list_all_dealer_messages(&self) -> Result<Vec<(Address, Messages)>>;

    /// Store a dealer's rotation messages at the given epoch.
    /// If messages already exist for this dealer, they will be overwritten.
    fn store_rotation_messages(
        &mut self,
        epoch: u64,
        dealer: &Address,
        messages: &RotationMessages,
    ) -> Result<()>;

    /// Retrieve a dealer's rotation messages for the given epoch.
    /// Returns None if no messages exist for this dealer.
    fn get_rotation_messages(
        &self,
        epoch: u64,
        dealer: &Address,
    ) -> Result<Option<RotationMessages>>;

    /// List all stored rotation messages for the current epoch.
    fn list_all_rotation_messages(&self) -> Result<Vec<(Address, Messages)>>;

    /// Store a dealer's nonce message at the given epoch.
    /// If a message already exists for this dealer and batch, it will be overwritten.
    fn store_nonce_message(
        &mut self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
        message: &batch_avss::Message,
    ) -> Result<()>;

    /// Retrieve a dealer's nonce message for the given epoch and batch.
    ///
    ///  Returns None if no message exists for this dealer.
    fn get_nonce_message(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> Result<Option<batch_avss::Message>>;

    /// List all nonce messages for the current epoch and given batch.
    fn list_nonce_messages(&self, batch_index: u32) -> Result<Vec<(Address, batch_avss::Message)>>;

    /// Store a dealer's AVID round state at the given epoch and batch.
    /// If state already exists for this dealer and batch, it will be overwritten.
    fn store_avid_round_state(
        &mut self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
        state: &AvidRoundState,
    ) -> Result<()>;

    /// Retrieve a dealer's AVID round state for the given epoch and batch.
    /// Returns None if no state exists for this dealer.
    fn get_avid_round_state(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> Result<Option<AvidRoundState>>;

    /// List all AVID round states for the current epoch and given batch.
    fn list_avid_round_states(&self, batch_index: u32) -> Result<Vec<(Address, AvidRoundState)>>;

    /// Store this node's held AVID vote and echoes for the given epoch, batch, and dealer,
    /// overwriting any existing entry.
    fn store_avid_held_echoes(
        &mut self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
        held: &HeldAvidEchoes,
    ) -> Result<()>;

    /// Retrieve this node's held AVID vote and echoes for the given epoch, batch, and dealer.
    fn get_avid_held_echoes(
        &self,
        epoch: u64,
        batch_index: u32,
        dealer: &Address,
    ) -> Result<Option<HeldAvidEchoes>>;

    /// Store this node's own AVID dealer builder for the given epoch and batch, overwriting any
    /// existing one.
    fn store_avid_dealer_builder(
        &mut self,
        epoch: u64,
        batch_index: u32,
        builder: &batch_avss_avid::AvssMessageBuilder,
    ) -> Result<()>;

    /// Retrieve this node's own AVID dealer builder for the given epoch and batch.
    fn get_avid_dealer_builder(
        &self,
        epoch: u64,
        batch_index: u32,
    ) -> Result<Option<batch_avss_avid::AvssMessageBuilder>>;
}
