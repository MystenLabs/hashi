// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Domain-separation intents for everything signed by Hashi member BLS keys.
///
/// The signing preimage is `intent (u16 LE) || bcs(epoch) || bcs(message)`.
/// Every message type signed under the committee's keys carries a unique
/// intent value, so a certificate produced for one message type can never
/// verify as another — regardless of whether two types happen to share a BCS
/// layout.
///
/// This registry mirrors `crates/hashi-types/src/intent.rs`; the two MUST stay
/// in sync. Allocation blocks, one per domain, with room to grow within each:
/// - `0x0000..=0x00FF`: core protocol (committee lifecycle, MPC ceremonies)
/// - `0x0100..=0x01FF`: Bitcoin
/// - `0x0200..`: reserved for future chains, one block each
module hashi::intent;

// ~~~~~~~ Constants ~~~~~~~

// ==== Core protocol (0x0000..=0x00FF) ====

/// Proof of possession of a member BLS key (epoch, address, public key).
const PROOF_OF_POSSESSION: u16 = 0x0000;
/// Committee handoff: the outgoing committee attests the next committee.
const COMMITTEE_TRANSITION: u16 = 0x0001;
/// Reconfiguration completion: the next committee holds the MPC key(s).
const RECONFIG_COMPLETION: u16 = 0x0002;
/// AVID/TOB dealer-messages hash certificates (MPC ceremonies). Verified
/// off-chain only; the intent is reserved here so the registry is complete.
const DEALER_MESSAGES_HASH: u16 = 0x0003;

// ==== Bitcoin (0x0100..=0x01FF) ====

/// Deposit confirmation over (request_id, utxo).
const DEPOSIT_CONFIRMATION: u16 = 0x0100;
/// Withdrawal request approval.
const WITHDRAWAL_REQUEST_APPROVAL: u16 = 0x0101;
/// Withdrawal transaction commitment (inputs/outputs/txid).
const WITHDRAWAL_COMMITMENT: u16 = 0x0102;
/// Incremental per-input MPC signature submission.
const MPC_INPUT_SIGNATURES: u16 = 0x0103;
/// Fully-signed withdrawal (MPC + guardian signatures).
const WITHDRAWAL_SIGNED: u16 = 0x0104;
/// Withdrawal confirmed on Bitcoin.
const WITHDRAWAL_CONFIRMATION: u16 = 0x0105;
/// Request for the guardian to co-sign a withdrawal. Verified off-chain
/// only; reserved here so the registry is complete.
const GUARDIAN_WITHDRAWAL_REQUEST: u16 = 0x0106;

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun proof_of_possession(): u16 { PROOF_OF_POSSESSION }

public(package) fun committee_transition(): u16 { COMMITTEE_TRANSITION }

public(package) fun reconfig_completion(): u16 { RECONFIG_COMPLETION }

public(package) fun dealer_messages_hash(): u16 { DEALER_MESSAGES_HASH }

public(package) fun deposit_confirmation(): u16 { DEPOSIT_CONFIRMATION }

public(package) fun withdrawal_request_approval(): u16 { WITHDRAWAL_REQUEST_APPROVAL }

public(package) fun withdrawal_commitment(): u16 { WITHDRAWAL_COMMITMENT }

public(package) fun mpc_input_signatures(): u16 { MPC_INPUT_SIGNATURES }

public(package) fun withdrawal_signed(): u16 { WITHDRAWAL_SIGNED }

public(package) fun withdrawal_confirmation(): u16 { WITHDRAWAL_CONFIRMATION }

public(package) fun guardian_withdrawal_request(): u16 { GUARDIAN_WITHDRAWAL_REQUEST }
