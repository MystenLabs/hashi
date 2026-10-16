// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The deposit flow's events and the deposit's id.

use crate::domain::BtcConfirmation;
use std::fmt;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::move_types::DepositConfirmed;
use serde::Deserialize;

use crate::keys::HashiBTCKeys;

/// Stable identifier for a monitored deposit: its Bitcoin outpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DepositId(OutPoint);

impl DepositId {
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self(OutPoint { txid, vout })
    }

    pub fn txid(self) -> Txid {
        self.0.txid
    }

    pub fn vout(self) -> u32 {
        self.0.vout
    }
}

impl fmt::Display for DepositId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorDepositEvent {
    pub event_type: DepositEventType,
    pub timestamp_secs: UnixSeconds,
    pub deposit_id: DepositId,
    /// Satoshis in the deposit output. Sui gives the claimed amount, Bitcoin
    /// the paid amount.
    pub amount: u64,
    /// Script the deposit output pays. Sui gives the bridge address of the
    /// claimed derivation path, Bitcoin the paid script.
    pub script_pubkey: ScriptBuf,
}

impl MonitorDepositEvent {
    /// E2 from Hashi's `DepositConfirmed`. Its Move payload has no
    /// timestamp, so the containing checkpoint's time is used. The claim's
    /// derivation path becomes the bridge script the state machine compares
    /// with the paid output.
    pub fn from_sui(
        event: DepositConfirmed,
        checkpoint_timestamp_secs: UnixSeconds,
        keys: &HashiBTCKeys,
    ) -> Self {
        Self {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: checkpoint_timestamp_secs,
            deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
            amount: event.utxo.amount,
            script_pubkey: keys.script_pubkey(event.utxo.derivation_path.as_ref()),
        }
    }

    /// E1 from Bitcoin's confirmation: the output at `deposit_id`'s vout, or
    /// `None` if the transaction has no output there.
    pub fn from_btc(confirmation: &BtcConfirmation, deposit_id: DepositId) -> Option<Self> {
        let output = confirmation.outputs.get(deposit_id.vout() as usize)?;
        Some(Self {
            event_type: DepositEventType::E1BtcConfirmed,
            timestamp_secs: confirmation.confirmed_time,
            deposit_id,
            amount: output.value.to_sat(),
            script_pubkey: output.script_pubkey.clone(),
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum DepositEventType {
    /// deposit confirmed event on btc
    E1BtcConfirmed,
    /// `DepositConfirmed` on Sui. Its timestamp is the containing checkpoint's
    /// timestamp, supplied with the transaction by Sui gRPC.
    E2HashiDeposited,
}
