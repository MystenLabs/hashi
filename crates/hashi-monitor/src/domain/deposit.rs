// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The deposit flow's events, the deposit's id, the user's request, and
//! the deposit a request yields.

use crate::domain::BtcConfirmation;
use std::fmt;

use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::DepositConfirmed;
use hashi_types::move_types::DepositRequested;
use sui_sdk_types::Address;

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

impl From<DepositId> for OutPoint {
    fn from(deposit_id: DepositId) -> Self {
        deposit_id.0
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DepositEventType {
    /// deposit confirmed event on btc
    E1BtcConfirmed,
    /// `DepositConfirmed` on Sui. Its timestamp is the containing checkpoint's
    /// timestamp, supplied with the transaction by Sui gRPC.
    E2HashiDeposited,
}

/// The monitor's view of `DepositRequested` on Sui: the user's claim that a
/// Bitcoin output pays the bridge. The public `deposit` entry emits it, so
/// the committee cannot suppress it. Its timestamp is the request's own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuiDepositRequestedEvent {
    /// The Sui `DepositRequest` object. Each request for a UTXO has its own.
    pub request_id: Address,
    pub timestamp_secs: UnixSeconds,
    pub deposit_id: DepositId,
    /// Satoshis the user claims. The pool takes Bitcoin's amount; this one
    /// only explains a request Hashi never confirms.
    pub amount: u64,
    /// The bridge script of the claimed derivation path. The monitor cannot
    /// recognize a bridge output without the path, so a wrong path hides
    /// the UTXO.
    pub script_pubkey: ScriptBuf,
}

impl SuiDepositRequestedEvent {
    /// Keep the claim and derive its bridge script. The requester and the
    /// digest are not used.
    pub fn from_sui(event: DepositRequested, keys: &HashiBTCKeys) -> Self {
        Self {
            request_id: event.request_id,
            timestamp_secs: unix_millis_to_seconds(event.timestamp_ms),
            deposit_id: DepositId::new(event.utxo_id.txid.into(), event.utxo_id.vout),
            amount: event.amount,
            script_pubkey: keys.script_pubkey(event.derivation_path.as_ref()),
        }
    }
}

/// A deposit Bitcoin confirmed at a bridge address. The UTXO pool records it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmedDeposit {
    pub deposit_id: DepositId,
    /// Satoshis Bitcoin paid.
    pub amount: u64,
    /// The bridge script the output pays. It matched the claimed path.
    pub script_pubkey: ScriptBuf,
    /// The time of the block that holds the transaction. The recovery
    /// leaf's clock starts there, so the UTXO's age counts from it.
    pub block_time: UnixSeconds,
}

impl ConfirmedDeposit {
    /// The deposit `request` claims, from Bitcoin's `confirmation` of its
    /// transaction. `None` when the transaction has no output at the claimed
    /// vout, or that output pays another script. The amount is Bitcoin's.
    pub fn from_confirmation(
        request: &SuiDepositRequestedEvent,
        confirmation: &BtcConfirmation,
    ) -> Option<Self> {
        let output = confirmation
            .outputs
            .get(request.deposit_id.vout() as usize)?;
        if output.script_pubkey != request.script_pubkey {
            return None;
        }
        Some(Self {
            deposit_id: request.deposit_id,
            amount: output.value.to_sat(),
            script_pubkey: output.script_pubkey.clone(),
            block_time: confirmation.block_time,
        })
    }
}
