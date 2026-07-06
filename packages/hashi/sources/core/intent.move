// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Domain-separation intents for everything signed by Hashi member BLS keys.
///
/// The signing preimage is `bcs(epoch) || intent || bcs(message)`. Every
/// message type signed under the committee's keys carries a unique intent
/// byte, so a certificate produced for one message type can never verify as
/// another — regardless of whether two types happen to share a BCS layout.
///
/// This registry mirrors `crates/hashi-types/src/intent.rs`; the two MUST
/// stay in sync. Allocation ranges:
/// - `0..=63`: core protocol (committee lifecycle, MPC ceremonies)
/// - `64..=127`: Bitcoin
/// - `128..`: reserved for future chains
module hashi::intent;

// ==== Core protocol (0..=63) ====

/// Proof of possession of a member BLS key (epoch, address, public key).
const PROOF_OF_POSSESSION: u8 = 0;
/// Committee handoff: the outgoing committee attests the next committee.
const COMMITTEE_TRANSITION: u8 = 1;
/// Reconfiguration completion: the next committee holds the MPC key(s).
const RECONFIG_COMPLETION: u8 = 2;
/// AVID/TOB dealer-messages hash certificates (MPC ceremonies). Verified
/// off-chain only; the intent is reserved here so the registry is complete.
const DEALER_MESSAGES_HASH: u8 = 3;

// ==== Bitcoin (64..=127) ====

/// Deposit confirmation over (request_id, utxo).
const DEPOSIT_CONFIRMATION: u8 = 64;
/// Withdrawal request approval.
const WITHDRAWAL_REQUEST_APPROVAL: u8 = 65;
/// Withdrawal transaction commitment (inputs/outputs/txid).
const WITHDRAWAL_COMMITMENT: u8 = 66;
/// Incremental per-input MPC signature submission.
const MPC_INPUT_SIGNATURES: u8 = 67;
/// Fully-signed withdrawal (MPC + guardian signatures).
const WITHDRAWAL_SIGNED: u8 = 68;
/// Withdrawal confirmed on Bitcoin.
const WITHDRAWAL_CONFIRMATION: u8 = 69;
/// Request for the guardian to co-sign a withdrawal. Verified off-chain
/// only; reserved here so the registry is complete.
const GUARDIAN_WITHDRAWAL_REQUEST: u8 = 70;

public(package) fun proof_of_possession(): u8 { PROOF_OF_POSSESSION }

public(package) fun committee_transition(): u8 { COMMITTEE_TRANSITION }

public(package) fun reconfig_completion(): u8 { RECONFIG_COMPLETION }

public(package) fun dealer_messages_hash(): u8 { DEALER_MESSAGES_HASH }

public(package) fun deposit_confirmation(): u8 { DEPOSIT_CONFIRMATION }

public(package) fun withdrawal_request_approval(): u8 { WITHDRAWAL_REQUEST_APPROVAL }

public(package) fun withdrawal_commitment(): u8 { WITHDRAWAL_COMMITMENT }

public(package) fun mpc_input_signatures(): u8 { MPC_INPUT_SIGNATURES }

public(package) fun withdrawal_signed(): u8 { WITHDRAWAL_SIGNED }

public(package) fun withdrawal_confirmation(): u8 { WITHDRAWAL_CONFIRMATION }

public(package) fun guardian_withdrawal_request(): u8 { GUARDIAN_WITHDRAWAL_REQUEST }
