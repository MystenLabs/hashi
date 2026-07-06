// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Domain-separation intents for everything signed by Hashi member BLS keys.
//!
//! The signing preimage is `intent (u16 LE) || bcs(epoch) || bcs(message)`.
//! Every message type signed under the committee's keys carries a unique
//! intent value, so a certificate produced for one message type can never
//! verify as another — regardless of whether two types happen to share a BCS
//! layout.
//!
//! [`Intent`] is a `#[repr(u16)]` enum with explicit discriminants: the
//! compiler rejects two variants sharing a value, and each message type names
//! a variant (not a raw number), so a typo'd or reused intent fails to compile.
//! The wire value is the discriminant, taken via `as u16` — never serde's enum
//! encoding (which is the variant index, not the discriminant).
//!
//! This registry mirrors `packages/hashi/sources/core/intent.move`; the two
//! MUST stay in sync — `intent_values_are_stable` below pins the on-wire
//! values so the Rust side cannot drift silently, and the e2e suite is the
//! true cross-language check. Allocation blocks, one per domain, with room to
//! grow within each:
//! - `0x0000..=0x00FF`: core protocol (committee lifecycle, MPC ceremonies)
//! - `0x0100..=0x01FF`: Bitcoin
//! - `0x0200..`: reserved for future chains, one block each

/// Signing-domain registry. Each variant's discriminant is the on-wire intent
/// value; explicit values let the compiler catch collisions.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    // ==== Core protocol (0x0000..=0x00FF) ====
    /// Proof of possession of a member BLS key (epoch, address, public key).
    ProofOfPossession = 0x0000,
    /// Committee handoff: the outgoing committee attests the next committee.
    CommitteeTransition = 0x0001,
    /// Reconfiguration completion: the next committee holds the MPC key(s).
    ReconfigCompletion = 0x0002,
    /// AVID/TOB dealer-messages hash certificates (MPC ceremonies).
    DealerMessagesHash = 0x0003,

    // ==== Bitcoin (0x0100..=0x01FF) ====
    /// Deposit confirmation over (request_id, utxo).
    DepositConfirmation = 0x0100,
    /// Withdrawal request approval.
    WithdrawalRequestApproval = 0x0101,
    /// Withdrawal transaction commitment (inputs/outputs/txid).
    WithdrawalCommitment = 0x0102,
    /// Incremental per-input MPC signature submission.
    MpcInputSignatures = 0x0103,
    /// Fully-signed withdrawal (MPC + guardian signatures).
    WithdrawalSigned = 0x0104,
    /// Withdrawal confirmed on Bitcoin.
    WithdrawalConfirmation = 0x0105,
    /// Request for the guardian to co-sign a withdrawal.
    GuardianWithdrawalRequest = 0x0106,

    /// Test-only signing domain for raw byte messages. Never used in
    /// production and absent from non-test builds.
    #[cfg(test)]
    Test = 0xFFFF,
}

impl Intent {
    /// The on-wire intent value (the discriminant, not the serde variant index).
    #[inline]
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

/// A message signed by Hashi member BLS keys. `INTENT` is bound into the
/// signing preimage, giving each message type its own signature domain.
pub trait IntentMessage: serde::Serialize {
    const INTENT: Intent;
}

impl<T: IntentMessage> IntentMessage for &T {
    const INTENT: Intent = T::INTENT;
}

#[cfg(test)]
mod tests {
    use super::Intent;

    /// The intent discriminants are the on-wire signing domain and MUST match
    /// `packages/hashi/sources/core/intent.move` exactly. Renumbering here (or
    /// there) breaks every committee signature across the language boundary.
    #[test]
    fn intent_values_are_stable() {
        assert_eq!(Intent::ProofOfPossession as u16, 0x0000);
        assert_eq!(Intent::CommitteeTransition as u16, 0x0001);
        assert_eq!(Intent::ReconfigCompletion as u16, 0x0002);
        assert_eq!(Intent::DealerMessagesHash as u16, 0x0003);
        assert_eq!(Intent::DepositConfirmation as u16, 0x0100);
        assert_eq!(Intent::WithdrawalRequestApproval as u16, 0x0101);
        assert_eq!(Intent::WithdrawalCommitment as u16, 0x0102);
        assert_eq!(Intent::MpcInputSignatures as u16, 0x0103);
        assert_eq!(Intent::WithdrawalSigned as u16, 0x0104);
        assert_eq!(Intent::WithdrawalConfirmation as u16, 0x0105);
        assert_eq!(Intent::GuardianWithdrawalRequest as u16, 0x0106);
    }
}
