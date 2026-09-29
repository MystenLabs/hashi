// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::committee::Committee;
use crate::committee::EncryptionGroupElement;
use crate::committee::EncryptionPublicKey;
use crate::committee::SignedMessage;
use crate::intent::IntentMessage;
use fastcrypto::groups::HashToGroupElement;
use serde::Serialize;
use std::sync::LazyLock;
use sui_crypto::SignatureError;
use sui_sdk_types::Address;
use sui_sdk_types::bcs::FromBcs;
use sui_sdk_types::bcs::ToBcs;

/// Guardian's operational committee with the node fallback substituted for malformed
/// member encryption keys. BLS keys are still parsed strictly.
///
/// # Representation warning
///
/// Its serialized representation may differ from the original Move committee:
/// replacing a malformed encryption key changes the bytes. Never use this view
/// to reconstruct signed payloads or original on-chain records. Verify and log
/// those using the original Move value instead.
///
/// The inner committee is private, with no `Deref`, serialization implementation,
/// or conversion back to `Committee` or Move. This prevents an accidental
/// deserialize/fallback/serialize round trip. Activation hashing deliberately
/// commits to the installed runtime state, including any fallback keys.
///
/// A runtime view cannot be converted back into an ordinary or wire committee:
/// ```compile_fail
/// use hashi_types::{committee::Committee, guardian::RuntimeCommittee};
/// fn into_committee(runtime: RuntimeCommittee) -> Committee {
///     runtime.into()
/// }
/// ```
/// ```compile_fail
/// use hashi_types::{guardian::RuntimeCommittee, move_types};
/// fn into_move(runtime: &RuntimeCommittee) -> move_types::Committee {
///     runtime.into()
/// }
/// ```
/// Nor can it be serialized as if it were the original committee:
/// ```compile_fail
/// use hashi_types::guardian::RuntimeCommittee;
/// fn serialize(runtime: &RuntimeCommittee) {
///     bcs::to_bytes(runtime).unwrap();
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeCommittee(Committee);

impl From<Committee> for RuntimeCommittee {
    fn from(committee: Committee) -> Self {
        Self(committee)
    }
}

impl RuntimeCommittee {
    /// Build a runtime view. Preserve the original Move value for signatures and
    /// logs; only this local view substitutes malformed encryption keys.
    pub fn from_move_with_encryption_key_fallback(
        mut committee: crate::move_types::Committee,
    ) -> anyhow::Result<Self> {
        for member in &mut committee.members {
            if EncryptionPublicKey::from_bcs(&member.encryption_public_key).is_err() {
                member.encryption_public_key = fallback_encryption_public_key()
                    .to_bcs()
                    .expect("encryption key serialization should not fail");
            }
        }
        Committee::try_from(committee).map(Self)
    }

    pub fn epoch(&self) -> u64 {
        self.0.epoch()
    }

    pub fn total_weight(&self) -> u64 {
        self.0.total_weight()
    }

    pub fn verify_signature_and_weight<T: IntentMessage>(
        &self,
        hashi_id: Address,
        message: &SignedMessage<T>,
        required_weight: u64,
    ) -> Result<(), SignatureError> {
        self.0
            .verify_signature_and_weight(hashi_id, message, required_weight)
    }

    /// Dedicated encoding for activation-state hashing, not a wire committee.
    pub(super) fn activation_digest_repr(&self) -> ActivationCommitteeRepr {
        ActivationCommitteeRepr((&self.0).into())
    }
}

/// Keeps the existing activation digest encoding while denying callers a Move
/// committee reconstructed from a runtime view.
#[derive(Serialize)]
#[serde(transparent)]
pub(super) struct ActivationCommitteeRepr(crate::move_types::Committee);

// Match the existing node fallback in hashi::mpc::mpc_except_signing. Guardian
// needs the same effective state, but cannot depend on the node crate here.
fn fallback_encryption_public_key() -> EncryptionPublicKey {
    static FALLBACK: LazyLock<EncryptionPublicKey> = LazyLock::new(|| {
        EncryptionPublicKey::from(EncryptionGroupElement::hash_to_group_element(b"hashi"))
    });
    FALLBACK.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::committee::Bls12381PrivateKey;
    use crate::committee::CommitteeMember;
    use crate::committee::EncryptionPrivateKey;

    fn raw_committee() -> crate::move_types::Committee {
        let mut rng = rand::thread_rng();
        let member = CommitteeMember::new(
            Address::new([1; 32]),
            Bls12381PrivateKey::generate(&mut rng).public_key(),
            EncryptionPrivateKey::new(&mut rng).public_key(),
            10,
        );
        (&Committee::new(vec![member], 7, 0, 3333)).into()
    }

    #[test]
    fn fallback_is_runtime_only_and_preserves_activation_encoding() {
        let mut raw = raw_committee();
        raw.members[0].encryption_public_key = vec![0xff; 32];
        assert!(Committee::try_from(raw.clone()).is_err());

        let runtime =
            RuntimeCommittee::from_move_with_encryption_key_fallback(raw.clone()).unwrap();
        assert_eq!(runtime.epoch(), raw.epoch);
        assert_eq!(runtime.total_weight(), raw.total_weight);
        assert_eq!(
            runtime.0.members()[0].encryption_public_key(),
            &fallback_encryption_public_key()
        );

        // Activation pins installed state, not the original signed bytes.
        let original_bytes = bcs::to_bytes(&raw).unwrap();
        raw.members[0].encryption_public_key = fallback_encryption_public_key().to_bcs().unwrap();
        let activation_bytes = bcs::to_bytes(&runtime.activation_digest_repr()).unwrap();
        assert_eq!(activation_bytes, bcs::to_bytes(&raw).unwrap());
        assert_ne!(activation_bytes, original_bytes);
    }

    #[test]
    fn fallback_does_not_accept_a_malformed_bls_key() {
        let mut raw = raw_committee();
        raw.members[0].public_key = vec![0xff; 96];
        raw.members[0].encryption_public_key = vec![0xff; 32];
        assert!(RuntimeCommittee::from_move_with_encryption_key_fallback(raw).is_err());
    }
}
