// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A committee member's proof that it holds its registered TLS key, sent on
//! every guardian RPC. TLS ends at the guardian proxy's load balancer, so the
//! proxy checks this signature instead of a client certificate.

use serde::Deserialize;
use serde::Serialize;
use sui_sdk_types::Address;

use crate::guardian::UnixMillis;
use crate::intent::Intent;

/// gRPC binary metadata key carrying a BCS-encoded [`MemberAuth`].
pub const MEMBER_AUTH_METADATA_KEY: &str = "x-hashi-member-auth-bin";

/// How far a token's timestamp may be from the verifier's clock, either way:
/// the skew the guardian already allows on withdrawal timestamps.
pub const MEMBER_AUTH_MAX_SKEW_MS: UnixMillis = 5 * 60 * 1000;

#[derive(Serialize)]
struct MemberAuthMessage<'a> {
    method: &'a str,
    timestamp_ms: UnixMillis,
}

/// A member's TLS-key signature over one request's gRPC method and send time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberAuth {
    pub tls_public_key: [u8; 32],
    timestamp_ms: UnixMillis,
    signature: Vec<u8>,
}

impl MemberAuth {
    pub fn sign(
        tls_private_key: &ed25519_dalek::SigningKey,
        hashi_id: Address,
        method: &str,
        timestamp_ms: UnixMillis,
    ) -> Self {
        use ed25519_dalek::Signer;

        let signature = tls_private_key.sign(&preimage(hashi_id, method, timestamp_ms));
        Self {
            tls_public_key: tls_private_key.verifying_key().to_bytes(),
            timestamp_ms,
            signature: signature.to_bytes().to_vec(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).unwrap()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bcs::Error> {
        bcs::from_bytes(bytes)
    }

    pub fn is_fresh(&self, now_ms: UnixMillis) -> bool {
        now_ms.abs_diff(self.timestamp_ms) <= MEMBER_AUTH_MAX_SKEW_MS
    }

    /// Strict verification rejects small-order keys, which the permissive
    /// (ZIP-215) check on TLS key registration lets onto the chain.
    pub fn verify_signature(&self, hashi_id: Address, method: &str) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&self.tls_public_key) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&self.signature) else {
            return false;
        };
        key.verify_strict(&preimage(hashi_id, method, self.timestamp_ms), &signature)
            .is_ok()
    }
}

fn preimage(hashi_id: Address, method: &str, timestamp_ms: UnixMillis) -> Vec<u8> {
    let message = MemberAuthMessage {
        method,
        timestamp_ms,
    };
    bcs::to_bytes(&(Intent::GuardianProxyAuth.as_u16(), hashi_id, &message)).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    const METHOD: &str = "/sui.hashi.v1alpha.GuardianService/StandardWithdrawal";

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn signed_token_round_trips_and_verifies() {
        let hashi_id = Address::new([0xAB; 32]);
        let auth = MemberAuth::sign(&signing_key(0x42), hashi_id, METHOD, 1_000);

        let decoded = MemberAuth::from_bytes(&auth.to_bytes()).unwrap();
        assert_eq!(decoded, auth);
        assert_eq!(
            decoded.tls_public_key,
            signing_key(0x42).verifying_key().to_bytes()
        );
        assert!(decoded.verify_signature(hashi_id, METHOD));
    }

    #[test]
    fn signature_binds_deployment_method_time_and_key() {
        let hashi_id = Address::new([0xAB; 32]);
        let auth = MemberAuth::sign(&signing_key(0x42), hashi_id, METHOD, 1_000);

        assert!(!auth.verify_signature(Address::new([0xAC; 32]), METHOD));
        assert!(!auth.verify_signature(
            hashi_id,
            "/sui.hashi.v1alpha.GuardianService/UpdateCommitteeChain"
        ));

        let mut retimed = auth.clone();
        retimed.timestamp_ms += 1;
        assert!(!retimed.verify_signature(hashi_id, METHOD));

        let mut rekeyed = auth.clone();
        rekeyed.tls_public_key = signing_key(0x43).verifying_key().to_bytes();
        assert!(!rekeyed.verify_signature(hashi_id, METHOD));

        let mut truncated = auth;
        truncated.signature.pop();
        assert!(!truncated.verify_signature(hashi_id, METHOD));
    }

    #[test]
    fn freshness_allows_the_skew_either_way() {
        let sent = 10 * MEMBER_AUTH_MAX_SKEW_MS;
        let auth = MemberAuth::sign(&signing_key(0x42), Address::ZERO, METHOD, sent);

        assert!(auth.is_fresh(sent));
        assert!(auth.is_fresh(sent + MEMBER_AUTH_MAX_SKEW_MS));
        assert!(auth.is_fresh(sent - MEMBER_AUTH_MAX_SKEW_MS));
        assert!(!auth.is_fresh(sent + MEMBER_AUTH_MAX_SKEW_MS + 1));
        assert!(!auth.is_fresh(sent - MEMBER_AUTH_MAX_SKEW_MS - 1));
    }

    #[test]
    fn rejects_a_forgery_under_a_small_order_key() {
        // The identity point as the key and R, with s = 0, verifies for any
        // message under ZIP-215.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&identity);
        let hashi_id = Address::new([0xAB; 32]);

        let permissive = ed25519_consensus::VerificationKey::try_from(identity).unwrap();
        assert!(
            permissive
                .verify(
                    &ed25519_consensus::Signature::from(signature),
                    &preimage(hashi_id, METHOD, 1_000)
                )
                .is_ok()
        );

        let forged = MemberAuth {
            tls_public_key: identity,
            timestamp_ms: 1_000,
            signature: signature.to_vec(),
        };
        assert!(!forged.verify_signature(hashi_id, METHOD));
    }

    #[test]
    fn preimage_is_intent_then_hashi_id_then_method_then_timestamp() {
        let bytes = preimage(Address::new([0xAB; 32]), "/m", 7);

        let mut expected = vec![0x07, 0x00];
        expected.extend([0xAB; 32]);
        expected.extend([2, b'/', b'm']);
        expected.extend(7u64.to_le_bytes());
        assert_eq!(bytes, expected);
    }
}
