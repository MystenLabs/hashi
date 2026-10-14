// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Detects presignature (nonce) reuse from what leaves hashi's nodes, without
//! trusting any record the nodes keep.
//!
//! A node signs input `i` of withdrawal `W` with the nonce
//! `R = P + (md + pd)·G` (hashi `mpc::types::signing_nonce_bytes`), where `P`
//! and `pd` are fixed by the presignature and `md = H(W.randomness, i, sighash)`
//! is computable from public data. `Q = R - md·G` therefore identifies the
//! presignature: two signing sessions with the same `Q` used one presignature
//! for two messages, which discloses key material. The detector only sees reuse
//! under one presignature index (`pd` covers the index), which is the reuse the
//! on-chain allocator and the node's slot pool exist to prevent.

use std::collections::HashMap;

use fastcrypto::groups::GroupElement;
use fastcrypto::serde_helpers::ToFromByteArray;
use fastcrypto_tbls::random_oracle::RandomOracle;
use fastcrypto_tbls::threshold_schnorr::G;
use fastcrypto_tbls::threshold_schnorr::S;
use hashi::constants::MESSAGE_DELTA_LABEL;
use hashi::constants::SIGNING_DELTA_DOMAIN;
use sui_sdk_types::Address;

/// One input of one withdrawal, signed in one hashi epoch. Reallocation after
/// an epoch change re-signs the same input with a new presignature and new
/// randomness, so the epoch is part of the session's identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Session {
    pub signing_id: Address,
    pub epoch: u64,
}

#[derive(Clone, Debug)]
pub struct SigningContext {
    pub session: Session,
    pub withdrawal: Address,
    pub input_index: u32,
    pub sighash: [u8; 32],
    pub message_delta: S,
}

impl SigningContext {
    pub fn new(
        withdrawal: Address,
        input_index: u32,
        epoch: u64,
        randomness: &[u8; 32],
        sighash: [u8; 32],
    ) -> Self {
        Self {
            session: Session {
                signing_id: signing_id(&withdrawal, input_index),
                epoch,
            },
            withdrawal,
            input_index,
            sighash,
            message_delta: message_delta(randomness, input_index, &sighash),
        }
    }
}

/// Mirrors hashi `withdrawals::withdrawal_input_signing_id`.
pub fn signing_id(withdrawal: &Address, input_index: u32) -> Address {
    use fastcrypto::hash::Blake2b256;
    use fastcrypto::hash::HashFunction;
    let bytes = bcs::to_bytes(&(withdrawal, input_index)).expect("serialization should succeed");
    Address::new(Blake2b256::digest(&bytes).digest)
}

/// Mirrors hashi `mpc::types::message_delta`; pinned to hashi's golden vectors
/// in the tests below.
pub fn message_delta(randomness: &[u8; 32], input_index: u32, message: &[u8]) -> S {
    RandomOracle::new(SIGNING_DELTA_DOMAIN)
        .extend(MESSAGE_DELTA_LABEL)
        .evaluate_to_group_element(&(randomness, input_index, message))
}

/// A signing nonce as seen on the wire (the full point a node serves with its
/// partial signature) or in a BIP340 signature (x coordinate only).
#[derive(Clone, Copy, Debug)]
pub enum Nonce {
    Point(G),
    XOnly([u8; 32]),
}

impl Nonce {
    /// A nonce as nodes serve it: fastcrypto's 33-byte point encoding, which is
    /// arkworks' compressed form rather than SEC1.
    pub fn from_compressed(bytes: &[u8]) -> anyhow::Result<Self> {
        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce is {} bytes, expected 33", bytes.len()))?;
        Ok(Self::Point(G::from_byte_array(&bytes)?))
    }

    /// The nonce of a 64-byte BIP340 signature.
    pub fn from_signature(signature: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            signature.len() == 64,
            "signature is {} bytes, expected 64",
            signature.len()
        );
        Ok(Self::XOnly(signature[..32].try_into().unwrap()))
    }

    /// The BIP340 x coordinate.
    pub fn x_only(&self) -> [u8; 32] {
        match self {
            Self::Point(point) => point
                .x_as_be_bytes()
                .expect("a signing nonce is never the point at infinity"),
            Self::XOnly(x) => *x,
        }
    }

    /// The points this nonce may stand for. An x coordinate lifts to two
    /// points, and BIP340 does not say which one the signer's `R` was.
    fn points(&self) -> Vec<G> {
        match self {
            Self::Point(point) => vec![*point],
            Self::XOnly(x) => G::with_even_y_from_x_be_bytes(x)
                .map(|even| vec![even, -even])
                .unwrap_or_default(),
        }
    }
}

/// An invariant the ledger found broken, with what is needed to triage it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A node served a different nonce or partial signature for a session it
    /// had already served.
    PartialChanged { node: String, session: Session },
    /// Two sources disagree on a session's nonce.
    NonceDisagreement {
        session: Session,
        first_source: String,
        source: String,
    },
    /// One presignature signed two different messages.
    PresignatureReused { first: Session, second: Session },
    /// The guardian signed two different messages with one nonce.
    GuardianNonceReused { nonce_x: [u8; 32] },
}

#[derive(Default)]
pub struct NonceLedger {
    served: HashMap<(String, Session), (Vec<u8>, Vec<u8>)>,
    session_nonces: HashMap<Session, ([u8; 32], String)>,
    presignatures: HashMap<[u8; 33], (Session, [u8; 32])>,
    guardian_nonces: HashMap<[u8; 32], [u8; 32]>,
}

impl NonceLedger {
    /// Records the nonce and partial signature `node` served for `context`.
    pub fn record_partial(
        &mut self,
        node: &str,
        context: &SigningContext,
        nonce: &[u8],
        partial: &[u8],
    ) -> anyhow::Result<Vec<Violation>> {
        let mut violations = Vec::new();
        let key = (node.to_owned(), context.session);
        let served = (nonce.to_vec(), partial.to_vec());
        match self.served.get(&key) {
            Some(previous) if *previous != served => violations.push(Violation::PartialChanged {
                node: node.to_owned(),
                session: context.session,
            }),
            Some(_) => {}
            None => {
                self.served.insert(key, served);
            }
        }
        let nonce = Nonce::from_compressed(nonce)?;
        violations.extend(self.record_nonce(node, context, nonce));
        Ok(violations)
    }

    /// Records a nonce observed for `context` from any source: a node's
    /// response, or a signature on Sui or Bitcoin.
    pub fn record_nonce(
        &mut self,
        source: &str,
        context: &SigningContext,
        nonce: Nonce,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        let nonce_x = nonce.x_only();
        match self.session_nonces.get(&context.session) {
            Some((first, first_source)) if *first != nonce_x => {
                violations.push(Violation::NonceDisagreement {
                    session: context.session,
                    first_source: first_source.clone(),
                    source: source.to_owned(),
                })
            }
            Some(_) => {}
            None => {
                self.session_nonces
                    .insert(context.session, (nonce_x, source.to_owned()));
            }
        }

        let delta = G::generator() * context.message_delta;
        for point in nonce.points() {
            let presignature = (point - delta).to_byte_array();
            match self.presignatures.get(&presignature) {
                Some((first, sighash))
                    if *first != context.session || *sighash != context.sighash =>
                {
                    violations.push(Violation::PresignatureReused {
                        first: *first,
                        second: context.session,
                    })
                }
                Some(_) => {}
                None => {
                    self.presignatures
                        .insert(presignature, (context.session, context.sighash));
                }
            }
        }
        violations
    }

    /// Records a guardian signature over `sighash`. The guardian draws a fresh
    /// nonce per signature, so one nonce over two messages is a reuse.
    pub fn record_guardian_signature(
        &mut self,
        sighash: [u8; 32],
        signature: &[u8],
    ) -> anyhow::Result<Option<Violation>> {
        let nonce_x = Nonce::from_signature(signature)?.x_only();
        Ok(match self.guardian_nonces.get(&nonce_x) {
            Some(first) if *first != sighash => Some(Violation::GuardianNonceReused { nonce_x }),
            Some(_) => None,
            None => {
                self.guardian_nonces.insert(nonce_x, sighash);
                None
            }
        })
    }

    /// The nonce x coordinate first observed for this session, if any.
    pub fn session_nonce(&self, session: &Session) -> Option<[u8; 32]> {
        self.session_nonces.get(session).map(|(x, _)| *x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hashi `mpc::signing` tests pin `message_delta` to these values.
    #[test]
    fn message_delta_matches_hashi_golden_vectors() {
        let randomness: [[u8; 32]; 2] = [std::array::from_fn(|i| i as u8), [0xff; 32]];
        let deltas: Vec<String> = [
            (&randomness[0], 0),
            (&randomness[0], 1),
            (&randomness[1], 0),
        ]
        .iter()
        .map(|(r, i)| hex::encode(message_delta(r, *i, b"golden").to_byte_array()))
        .collect();
        assert_eq!(
            deltas,
            [
                "39448aee8778c3764651274144dfd7457bb01dd11f1771fc0b55bc76e2d3323d",
                "3d530db4d4c04a84d5dde298588c2afb930488f343d34af9bb311726028e72a2",
                "4adf4bc48b673eff49843d7b0246e6eeb48ebf925fe5ff50ec13a1f2b85846e7",
            ]
        );
    }

    struct Presignature {
        point: G,
        delta: S,
    }

    impl Presignature {
        fn new(seed: u64) -> Self {
            Self {
                point: G::generator() * S::from(u128::from(seed + 1000)),
                delta: S::from(u128::from(seed + 7)),
            }
        }

        /// The nonce a node would serve when signing `context` with this presignature.
        fn nonce(&self, context: &SigningContext) -> G {
            self.point + G::generator() * (context.message_delta + self.delta)
        }
    }

    fn context(withdrawal: u8, input_index: u32, epoch: u64, sighash: u8) -> SigningContext {
        SigningContext::new(
            Address::new([withdrawal; 32]),
            input_index,
            epoch,
            &[withdrawal; 32],
            [sighash; 32],
        )
    }

    fn compressed(point: G) -> Vec<u8> {
        point.to_byte_array().to_vec()
    }

    #[test]
    fn consistent_observations_pass() {
        let mut ledger = NonceLedger::default();
        let (a, b) = (context(1, 0, 1, 1), context(1, 1, 1, 2));
        let (pa, pb) = (Presignature::new(1), Presignature::new(2));
        for node in ["hashi1", "hashi2"] {
            for _ in 0..2 {
                for (ctx, presig) in [(&a, &pa), (&b, &pb)] {
                    let nonce = compressed(presig.nonce(ctx));
                    assert!(
                        ledger
                            .record_partial(node, ctx, &nonce, b"partial")
                            .unwrap()
                            .is_empty()
                    );
                }
            }
        }
        // The aggregate signature on chain carries only the x coordinate.
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&pa.nonce(&a).x_as_be_bytes().unwrap());
        let nonce = Nonce::from_signature(&signature).unwrap();
        assert!(ledger.record_nonce("bitcoin", &a, nonce).is_empty());
        // Reallocation re-signs the input in a new epoch with a new presignature.
        let realloc = context(1, 0, 2, 1);
        let nonce = compressed(Presignature::new(3).nonce(&realloc));
        assert!(
            ledger
                .record_partial("hashi1", &realloc, &nonce, b"partial")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn detects_a_changed_partial() {
        let mut ledger = NonceLedger::default();
        let ctx = context(1, 0, 1, 1);
        let nonce = compressed(Presignature::new(1).nonce(&ctx));
        ledger
            .record_partial("hashi1", &ctx, &nonce, b"before")
            .unwrap();
        let violations = ledger
            .record_partial("hashi1", &ctx, &nonce, b"after")
            .unwrap();
        assert_eq!(
            violations,
            [Violation::PartialChanged {
                node: "hashi1".into(),
                session: ctx.session,
            }]
        );
    }

    #[test]
    fn detects_one_presignature_over_two_messages() {
        let mut ledger = NonceLedger::default();
        let presig = Presignature::new(1);
        let (a, b) = (context(1, 0, 1, 1), context(2, 3, 1, 9));
        ledger
            .record_partial("hashi1", &a, &compressed(presig.nonce(&a)), b"a")
            .unwrap();
        let violations = ledger
            .record_partial("hashi2", &b, &compressed(presig.nonce(&b)), b"b")
            .unwrap();
        assert!(violations.contains(&Violation::PresignatureReused {
            first: a.session,
            second: b.session,
        }));
    }

    #[test]
    fn detects_reuse_seen_only_in_bip340_signatures() {
        let mut ledger = NonceLedger::default();
        let presig = Presignature::new(1);
        let (a, b) = (context(1, 0, 1, 1), context(2, 0, 1, 2));
        for ctx in [&a, &b] {
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&presig.nonce(ctx).x_as_be_bytes().unwrap());
            let nonce = Nonce::from_signature(&signature).unwrap();
            let violations = ledger.record_nonce("sui", ctx, nonce);
            if ctx.session == b.session {
                assert!(violations.contains(&Violation::PresignatureReused {
                    first: a.session,
                    second: b.session,
                }));
            }
        }
    }

    #[test]
    fn detects_nodes_disagreeing_on_a_nonce() {
        let mut ledger = NonceLedger::default();
        let ctx = context(1, 0, 1, 1);
        let first = compressed(Presignature::new(1).nonce(&ctx));
        let second = compressed(Presignature::new(2).nonce(&ctx));
        ledger.record_partial("hashi1", &ctx, &first, b"x").unwrap();
        let violations = ledger
            .record_partial("hashi2", &ctx, &second, b"x")
            .unwrap();
        assert!(violations.contains(&Violation::NonceDisagreement {
            session: ctx.session,
            first_source: "hashi1".into(),
            source: "hashi2".into(),
        }));
    }

    #[test]
    fn detects_guardian_nonce_reuse() {
        let mut ledger = NonceLedger::default();
        let signature = [7u8; 64];
        assert_eq!(
            ledger
                .record_guardian_signature([1; 32], &signature)
                .unwrap(),
            None
        );
        assert_eq!(
            ledger
                .record_guardian_signature([1; 32], &signature)
                .unwrap(),
            None
        );
        assert_eq!(
            ledger
                .record_guardian_signature([2; 32], &signature)
                .unwrap(),
            Some(Violation::GuardianNonceReused { nonce_x: [7; 32] })
        );
    }
}
