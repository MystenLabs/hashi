// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::bitcoin::BTC_LIB;
use crate::guardian::errors::GuardianError::InvalidInputs;
use crate::guardian::errors::GuardianResult;
use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
use k256::CompressedPoint;
use k256::ProjectivePoint;
use k256::Scalar;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::group::GroupEncoding;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;
use tracing::info;

pub type ShareID = NonZeroU16; // Share IDs are assigned from 1, e.g., 1, 2, 3 and so on.

#[derive(Copy, Clone)]
pub struct Share {
    pub id: ShareID,
    pub value: Scalar,
}

/// Minimum reconstruction threshold (`t > 1`).
pub const MIN_THRESHOLD: usize = 2;
/// Maximum total number of shares (`n <= u16::MAX`)
pub const MAX_NUM_SHARES: usize = u16::MAX as usize;

/// Validated `(n, t)` secret-sharing parameters.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct SecretSharingParams {
    num_shares: usize,
    threshold: usize,
}

impl SecretSharingParams {
    pub fn new(num_shares: usize, threshold: usize) -> GuardianResult<Self> {
        if threshold < MIN_THRESHOLD {
            return Err(InvalidInputs(format!(
                "threshold {threshold} below minimum {MIN_THRESHOLD}"
            )));
        }
        if num_shares < threshold {
            return Err(InvalidInputs(format!(
                "num_shares {num_shares} below threshold {threshold}"
            )));
        }
        if num_shares > MAX_NUM_SHARES {
            return Err(InvalidInputs(format!(
                "{num_shares} must be at most u16::MAX"
            )));
        }
        Ok(Self {
            num_shares,
            threshold,
        })
    }

    pub fn num_shares(&self) -> usize {
        self.num_shares
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }
}

pub type DigestBytes = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitment {
    pub id: ShareID,
    pub digest: DigestBytes,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitments(
    #[serde(with = "crate::guardian::serde::hex_map_values")] BTreeMap<ShareID, DigestBytes>,
);

/// Public description of the current BTC key's secret-sharing scheme.
/// `sharing_seq` versions the instance: setup writes 0, each rotation bumps it by 1.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SecretSharingInstance {
    commitments: ShareCommitments,
    params: SecretSharingParams,
    sharing_seq: u64,
}

impl SecretSharingInstance {
    pub fn new(
        commitments: ShareCommitments,
        num_shares: usize,
        threshold: usize,
        sharing_seq: u64,
    ) -> GuardianResult<Self> {
        let params = SecretSharingParams::new(num_shares, threshold)?;
        if commitments.len() != params.num_shares() {
            return Err(InvalidInputs(format!(
                "expected {} commitments, got {}",
                params.num_shares(),
                commitments.len()
            )));
        }
        let commitment_ids: Vec<u16> = commitments.iter().map(|c| c.id.get()).collect();
        let expected_ids: Vec<u16> = (1..=params.num_shares() as u16).collect();
        if commitment_ids != expected_ids {
            return Err(InvalidInputs(format!(
                "commitment ids are not exactly 1..={}: got {commitment_ids:?}",
                params.num_shares()
            )));
        }
        Ok(Self {
            commitments,
            params,
            sharing_seq,
        })
    }

    pub fn commitments(&self) -> &ShareCommitments {
        &self.commitments
    }

    pub fn num_shares(&self) -> usize {
        self.params.num_shares()
    }

    pub fn threshold(&self) -> usize {
        self.params.threshold()
    }

    pub fn sharing_seq(&self) -> u64 {
        self.sharing_seq
    }
}

impl fmt::Display for SecretSharingInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = bcs::to_bytes(&self.commitments).expect("serialization should work");
        let commitments_hash = Blake2b::<U32>::digest(bytes);
        let commitments_hash_hex = hex::encode(commitments_hash);
        write!(
            f,
            "SecretSharingInstance(seq={},n={},t={},commitments_hash={})",
            self.sharing_seq,
            self.num_shares(),
            self.threshold(),
            commitments_hash_hex
        )
    }
}

impl ShareCommitments {
    pub fn new(commitments: Vec<ShareCommitment>) -> GuardianResult<Self> {
        let mut map = BTreeMap::new();
        for commitment in commitments {
            if map.insert(commitment.id, commitment.digest).is_some() {
                return Err(InvalidInputs("duplicate share id".into()));
            }
        }
        Ok(Self(map))
    }

    pub fn from_shares(shares: &[Share]) -> GuardianResult<Self> {
        Self::new(shares.iter().map(commit_share).collect())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn contains(&self, commitment: &ShareCommitment) -> bool {
        self.0
            .get(&commitment.id)
            .is_some_and(|digest| digest == &commitment.digest)
    }

    /// Verify `share`'s commitment is in this set.
    pub fn verify_share(&self, share: &Share) -> GuardianResult<()> {
        self.contains(&commit_share(share))
            .then_some(())
            .ok_or_else(|| InvalidInputs("No matching share found".into()))
    }

    pub fn iter(&self) -> impl Iterator<Item = ShareCommitment> + '_ {
        self.0.iter().map(|(id, digest)| ShareCommitment {
            id: *id,
            digest: digest.clone(),
        })
    }
}

impl IntoIterator for ShareCommitments {
    type Item = ShareCommitment;
    type IntoIter = std::vec::IntoIter<ShareCommitment>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
            .map(|(id, digest)| ShareCommitment { id, digest })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

pub fn to_scalar(id: ShareID) -> Scalar {
    Scalar::from(id.get() as u32)
}

/// Split a k256 SecretKey into `params.num_shares()` shares using Shamir's
/// secret-sharing with reconstruction threshold `params.threshold()`.
pub fn split_secret<R: CryptoRng + RngCore>(
    sk: &k256::SecretKey,
    params: &SecretSharingParams,
    rng: &mut R,
) -> Vec<Share> {
    let secret = *sk.to_nonzero_scalar().as_ref();
    let mut coefficients = vec![secret];
    for _ in 0..(params.threshold() - 1) {
        coefficients.push(Scalar::random(&mut *rng))
    }

    (1..=params.num_shares())
        .map(|i| NonZeroU16::new(i as u16).expect("validated num_shares fits in u16"))
        .map(|i| Share {
            id: i,
            value: eval_poly(i, &coefficients),
        })
        .collect()
}

// Coefficients: [c0, c1, c2, c3]
// Returns: c0 + c1 * x + c2 * x^2 + c3 * x^3
pub fn eval_poly(pos: ShareID, coefficients: &[Scalar]) -> Scalar {
    let x = to_scalar(pos);
    let mut out = Scalar::ZERO;
    let mut xpow = Scalar::ONE;
    for c in coefficients {
        out = out.add(&c.mul(&xpow));
        xpow = xpow.mul(&x);
    }
    out
}

/// Combine secret shares into the reconstructed `k256::SecretKey` with
/// threshold `t`. Errors on duplicate share IDs or fewer than `t` shares.
/// Callers that need a `bitcoin::secp256k1::Keypair` should pass the result
/// through `k256_sk_to_btc_keypair`.
pub fn combine_shares(shares: &[Share], t: usize) -> GuardianResult<k256::SecretKey> {
    // Validation: ensure no duplicates
    let mut seen_ids = std::collections::HashSet::new();
    for share in shares {
        if !seen_ids.insert(share.id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
    }
    if seen_ids.len() < t {
        return Err(InvalidInputs(format!(
            "Received only {} out of {} shares",
            seen_ids.len(),
            t
        )));
    }

    let ids = shares.iter().map(|s| to_scalar(s.id)).collect::<Vec<_>>();
    let mut result = Scalar::ZERO;
    for share in shares {
        let cur_share_id = to_scalar(share.id);
        let numerator: Scalar = ids
            .iter()
            .filter(|&id| cur_share_id != *id)
            .map(|id| id.negate())
            .product();
        let denominator: Scalar = ids
            .iter()
            .filter(|&id| cur_share_id != *id)
            .map(|id| cur_share_id.sub(id))
            .product();

        // Lagrange basis polynomial evaluated at x=0
        // L_i(0) = product_{j != i} (-x_j) / (x_i - x_j)
        let lagrange_basis = numerator.mul(
            &denominator
                .invert()
                .expect("Denominator is never zero because share IDs are unique"),
        );
        result = result.add(&share.value.mul(&lagrange_basis));
    }

    info!("Bitcoin key created with fingerprint {:x}", exp_g(&result));

    Ok(k256::SecretKey::from_slice(&result.to_bytes())
        .expect("k256 scalar bytes are a valid k256 secret key"))
}

/// Convert a `k256::SecretKey` to a `bitcoin::secp256k1::Keypair`. Both libs
/// use big-endian 32-byte scalars so the byte round-trip is value-preserving.
/// We juggle between the two libraries because secp256k1 does not expose the
/// arithmetic tools needed for secret-sharing.
pub fn k256_sk_to_btc_keypair(sk: &k256::SecretKey) -> bitcoin::secp256k1::Keypair {
    let btc_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk.to_bytes())
        .expect("k256 secret key bytes are a valid secp256k1 secret key");
    bitcoin::secp256k1::Keypair::from_secret_key(&BTC_LIB, &btc_sk)
}

/// The x-only BTC public key for a `k256::SecretKey` — the guardian's BTC master
/// pubkey. Bridges through the secp256k1 keypair, like [`k256_sk_to_btc_keypair`].
pub fn k256_sk_to_btc_xonly_pubkey(sk: &k256::SecretKey) -> crate::bitcoin::BitcoinPubkey {
    k256_sk_to_btc_keypair(sk).x_only_public_key().0
}

/// Create a commitment (hash) for a share
pub fn commit_share(share: &Share) -> ShareCommitment {
    let commitment = ProjectivePoint::GENERATOR * share.value;
    ShareCommitment {
        id: share.id,
        digest: commitment.to_bytes().to_vec(),
    }
}

pub fn fingerprint(sk: &k256::SecretKey) -> CompressedPoint {
    exp_g(&Scalar::from(sk.as_scalar_primitive()))
}

pub fn exp_g(scalar: &Scalar) -> CompressedPoint {
    (ProjectivePoint::GENERATOR * scalar).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;

    // Verify secret reconstruction with varying number of shares (0 to n).
    // For each `num_shares`:
    // - Below threshold: combine errors (refuses to interpolate)
    // - Threshold or above: returns the original secret
    fn check_reconstruction_with_varying_share_count(n: usize, t: usize) {
        let original_k256_sk = SecretKey::random(&mut rand::thread_rng());
        let original_bytes = original_k256_sk.to_bytes();
        let shares = split_secret(
            &original_k256_sk,
            &SecretSharingParams::new(n, t).unwrap(),
            &mut rand::thread_rng(),
        );

        for num_shares in 0..=n {
            let result = combine_shares(&shares[0..num_shares], t);

            if num_shares < t {
                assert!(
                    result.is_err(),
                    "n={n} t={t} num_shares={num_shares}: subthreshold combine should error"
                );
            } else {
                let reconstructed = result.unwrap();
                assert_eq!(
                    original_bytes,
                    reconstructed.to_bytes(),
                    "n={n} t={t} num_shares={num_shares}: should reconstruct original",
                );
            }
        }
    }

    // Verify that certain other subsets of `t` shares reconstructs the original.
    fn check_varying_subsets(n: usize, t: usize) {
        let original_sk = SecretKey::random(&mut rand::thread_rng());
        let original_bytes = original_sk.to_bytes();
        let shares = split_secret(
            &original_sk,
            &SecretSharingParams::new(n, t).unwrap(),
            &mut rand::thread_rng(),
        );

        for start_idx in 0..=(n - t) {
            let subset = &shares[start_idx..(start_idx + t)];
            let reconstructed = combine_shares(subset, t).unwrap();
            assert_eq!(
                original_bytes,
                reconstructed.to_bytes(),
                "n={n} t={t} start_idx={start_idx}: subset should reconstruct original",
            );
        }
    }

    fn check_combine_shares_rejects_duplicate_ids(n: usize, t: usize) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let shares = split_secret(
            &sk,
            &SecretSharingParams::new(n, t).unwrap(),
            &mut rand::thread_rng(),
        );

        // First t-1 distinct shares plus a duplicate of shares[0].
        let mut duplicate_shares: Vec<_> = shares.iter().take(t - 1).copied().collect();
        duplicate_shares.push(shares[0]);

        let err = combine_shares(&duplicate_shares, t)
            .expect_err("combine_shares should reject duplicate share IDs");
        assert!(
            err.to_string().contains("Duplicate share ID"),
            "n={n} t={t}: expected duplicate-id error, got {err}"
        );
    }

    fn test_commitments(ids: &[u16]) -> ShareCommitments {
        ShareCommitments::new(
            ids.iter()
                .map(|&id| ShareCommitment {
                    id: NonZeroU16::new(id).unwrap(),
                    digest: vec![id as u8],
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn share_commitments_json_encodes_digests_as_hex() {
        let commitments = test_commitments(&[1, 2]);
        let json = serde_json::to_value(&commitments).unwrap();

        assert_eq!(json["1"], "01");
        assert_eq!(json["2"], "02");
        assert_eq!(
            serde_json::from_value::<ShareCommitments>(json).unwrap(),
            commitments
        );
    }

    // Parameterized test cases: covers minimum (n=t=2), small, default, and large.
    #[test]
    fn reconstruction_with_varying_share_count_2_2() {
        check_reconstruction_with_varying_share_count(2, 2);
    }
    #[test]
    fn reconstruction_with_varying_share_count_3_2() {
        check_reconstruction_with_varying_share_count(3, 2);
    }
    #[test]
    fn reconstruction_with_varying_share_count_5_3() {
        check_reconstruction_with_varying_share_count(5, 3);
    }
    #[test]
    fn reconstruction_with_varying_share_count_10_7() {
        check_reconstruction_with_varying_share_count(10, 7);
    }

    #[test]
    fn varying_subsets_2_2() {
        check_varying_subsets(2, 2);
    }
    #[test]
    fn varying_subsets_3_2() {
        check_varying_subsets(3, 2);
    }
    #[test]
    fn varying_subsets_5_3() {
        check_varying_subsets(5, 3);
    }
    #[test]
    fn varying_subsets_10_7() {
        check_varying_subsets(10, 7);
    }

    #[test]
    fn combine_shares_rejects_duplicate_ids_2_2() {
        check_combine_shares_rejects_duplicate_ids(2, 2);
    }
    #[test]
    fn combine_shares_rejects_duplicate_ids_3_2() {
        check_combine_shares_rejects_duplicate_ids(3, 2);
    }
    #[test]
    fn combine_shares_rejects_duplicate_ids_5_3() {
        check_combine_shares_rejects_duplicate_ids(5, 3);
    }
    #[test]
    fn combine_shares_rejects_duplicate_ids_10_7() {
        check_combine_shares_rejects_duplicate_ids(10, 7);
    }

    #[test]
    fn secret_sharing_params_validation_cases() {
        // Valid pairs.
        for &(n, t) in &[(2, 2), (3, 2), (5, 3), (10, 7), (MAX_NUM_SHARES, 100)] {
            SecretSharingParams::new(n, t)
                .unwrap_or_else(|e| panic!("(n={n}, t={t}) should be valid: {e}"));
        }
        // Threshold below minimum.
        for t in 0..MIN_THRESHOLD {
            assert!(
                SecretSharingParams::new(5, t).is_err(),
                "t={t} (< MIN_THRESHOLD={MIN_THRESHOLD}) should be rejected"
            );
        }
        // num_shares < threshold.
        assert!(SecretSharingParams::new(2, 3).is_err());
        assert!(SecretSharingParams::new(5, 7).is_err());
        // num_shares > MAX_NUM_SHARES.
        assert!(SecretSharingParams::new(MAX_NUM_SHARES + 1, 3).is_err());
    }

    #[test]
    fn secret_sharing_instance_accepts_exact_commitment_ids() {
        SecretSharingInstance::new(test_commitments(&[1, 2, 3]), 3, 2, 0)
            .expect("commitment ids exactly 1..=n should be accepted");
    }

    #[test]
    fn secret_sharing_instance_rejects_non_contiguous_commitment_ids() {
        let err = SecretSharingInstance::new(test_commitments(&[1, 2, 4]), 3, 2, 0)
            .expect_err("commitment ids must be exactly 1..=n");
        assert!(format!("{err}").contains("commitment ids"), "{err}");
    }

    #[test]
    fn secret_sharing_instance_display_is_concise() {
        let instance = SecretSharingInstance::new(test_commitments(&[1, 2, 3]), 3, 2, 7)
            .expect("valid instance");
        let display = instance.to_string();

        assert!(display.contains("seq=7"), "{display}");
        assert!(display.contains("n=3"), "{display}");
        assert!(display.contains("t=2"), "{display}");
        assert!(display.contains("commitments_hash="), "{display}");
    }

    // Test eval function with specific coefficients
    #[test]
    fn test_eval_polynomial() {
        // Test with simple polynomial: f(x) = 1 + 2x + 3x^2
        let coefficients = vec![Scalar::ONE, Scalar::from(2u32), Scalar::from(3u32)];

        // f(1) = 1 + 2(1) + 3(1)^2 = 6
        let result1 = eval_poly(NonZeroU16::new(1).unwrap(), &coefficients);
        assert_eq!(result1, Scalar::from(6u32));

        // f(2) = 1 + 2(2) + 3(4) = 17
        let result2 = eval_poly(NonZeroU16::new(2).unwrap(), &coefficients);
        assert_eq!(result2, Scalar::from(17u32));
    }
}
