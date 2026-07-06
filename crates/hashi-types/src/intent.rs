// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Domain-separation intents for everything signed by Hashi member BLS keys.
//!
//! The signing preimage is `bcs(epoch) || intent || bcs(message)`. Every
//! message type signed under the committee's keys carries a unique intent
//! byte, so a certificate produced for one message type can never verify as
//! another — regardless of whether two types happen to share a BCS layout.
//!
//! This registry mirrors `packages/hashi/sources/core/intent.move`; the two
//! MUST stay in sync. Allocation ranges:
//! - `0..=63`: core protocol (committee lifecycle, MPC ceremonies)
//! - `64..=127`: Bitcoin
//! - `128..`: reserved for future chains

/// A message signed by Hashi member BLS keys. `INTENT` is bound into the
/// signing preimage, giving each message type its own signature domain.
pub trait IntentMessage: serde::Serialize {
    const INTENT: u8;
}

impl<T: IntentMessage> IntentMessage for &T {
    const INTENT: u8 = T::INTENT;
}

// ==== Core protocol (0..=63) ====

/// Proof of possession of a member BLS key (epoch, address, public key).
pub const PROOF_OF_POSSESSION: u8 = 0;
/// Committee handoff: the outgoing committee attests the next committee.
pub const COMMITTEE_TRANSITION: u8 = 1;
/// Reconfiguration completion: the next committee holds the MPC key(s).
pub const RECONFIG_COMPLETION: u8 = 2;
/// AVID/TOB dealer-messages hash certificates (MPC ceremonies).
pub const DEALER_MESSAGES_HASH: u8 = 3;

// ==== Bitcoin (64..=127) ====

/// Deposit confirmation over (request_id, utxo).
pub const DEPOSIT_CONFIRMATION: u8 = 64;
/// Withdrawal request approval.
pub const WITHDRAWAL_REQUEST_APPROVAL: u8 = 65;
/// Withdrawal transaction commitment (inputs/outputs/txid).
pub const WITHDRAWAL_COMMITMENT: u8 = 66;
/// Incremental per-input MPC signature submission.
pub const MPC_INPUT_SIGNATURES: u8 = 67;
/// Fully-signed withdrawal (MPC + guardian signatures).
pub const WITHDRAWAL_SIGNED: u8 = 68;
/// Withdrawal confirmed on Bitcoin.
pub const WITHDRAWAL_CONFIRMATION: u8 = 69;
/// Request for the guardian to co-sign a withdrawal.
pub const GUARDIAN_WITHDRAWAL_REQUEST: u8 = 70;
