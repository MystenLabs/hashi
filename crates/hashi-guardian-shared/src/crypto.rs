use crate::bitcoin_utils::BTC_LIB;
use crate::GuardianError::InvalidInputs;
use crate::GuardianResult;
use crate::GuardianSigned;
use crate::SigningIntent;
use ed25519_consensus::SigningKey;
use ed25519_consensus::VerificationKey;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kem::X25519HkdfSha256;
use hpke::Deserializable;
use hpke::Kem;
use hpke::Serializable;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use k256::CompressedPoint;
use k256::FieldBytes;
use k256::ProjectivePoint;
use k256::Scalar;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::num::NonZeroU16;
use tracing::info;
// ---------------------------------
//      Crypto Structs & Types
// ---------------------------------

pub type EncSecKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type EncPubKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub type EncPubKeyBytes = Vec<u8>; // Use as an alternative to EncPubKey where Serialize is needed
pub struct GuardianEncKeyPair {
    sk: EncSecKey,
    pk: EncPubKey,
}
pub type EncapsulatedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

pub type ShareID = NonZeroU16; // Share IDs are assigned from 1, e.g., 1, 2, 3 and so on.

#[derive(Copy, Clone)]
pub struct Share {
    pub id: ShareID,
    pub value: Scalar,
}

// Secret sharing constants: threshold and total number of key provisioners
// TODO: How to rotate committee / change the below config?
pub const THRESHOLD: usize = 3;
pub const NUM_OF_SHARES: usize = 5;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct EncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitment {
    pub id: ShareID,
    pub digest: DigestBytes,
}

pub type DigestBytes = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ciphertext {
    pub encapsulated_key: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl GuardianEncKeyPair {
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(rng);
        Self { sk, pk }
    }

    pub fn secret_key(&self) -> &EncSecKey {
        &self.sk
    }

    pub fn public_key(&self) -> &EncPubKey {
        &self.pk
    }
}

pub fn to_scalar(id: ShareID) -> Scalar {
    Scalar::from(id.get() as u32)
}

// ---------------------------------
//    Encryption/Decryption utils
// ---------------------------------

/// Encrypts plaintext. Returns InvalidInputs if plaintext / aad is extraordinarily long (~2^36).
pub fn encrypt<R: CryptoRng + RngCore>(
    bytes: &[u8],
    pk: &EncPubKey,
    aad: Option<&[u8; 32]>,
    rng: &mut R,
) -> GuardianResult<Ciphertext> {
    let (encapsulated_key, aes_ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            pk,
            &[],
            bytes,
            aad.unwrap_or(&[0; 32]),
            rng,
        )
        .map_err(|e| InvalidInputs(format!("Encryption failed: {}", e)))?;
    Ok(Ciphertext {
        encapsulated_key: encapsulated_key.to_bytes().to_vec(),
        aes_ciphertext,
    })
}

/// Decrypts ciphertext. Returns InvalidInputs if aad is invalid.
pub fn decrypt(
    ciphertext: &Ciphertext,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Vec<u8>> {
    let encapsulated_key = EncapsulatedKey::from_bytes(&ciphertext.encapsulated_key)
        .map_err(|e| InvalidInputs(format!("Failed to deserialize encapsulated key: {}", e)))?;
    hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        sk,
        &encapsulated_key,
        &[],
        &ciphertext.aes_ciphertext,
        aad.unwrap_or(&[0; 32]),
    )
    .map_err(|e| InvalidInputs(format!("Decryption failed: {}", e)))
}

// ---------------------------------
//    Secret Sharing utilities
// ---------------------------------

/// Split a k256 SecretKey into shares using Shamir's secret sharing
pub fn split_secret<R: CryptoRng + RngCore>(sk: &k256::SecretKey, rng: &mut R) -> Vec<Share> {
    let secret = *sk.to_nonzero_scalar().as_ref();
    let mut coefficients = vec![secret];
    for _ in 0..(THRESHOLD - 1) {
        coefficients.push(Scalar::random(&mut *rng))
    }

    // Evaluate
    (1..=NUM_OF_SHARES)
        .map(|i| NonZeroU16::new(i as u16).expect("Not zeroes!"))
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

/// Combine secret shares to a secp256k1 secret key
/// Throws an error if duplicate share IDs exist or <t shares are input
pub fn combine_shares(shares: &[Share]) -> GuardianResult<bitcoin::secp256k1::Keypair> {
    // Validation: ensure no duplicates
    let mut seen_ids = std::collections::HashSet::new();
    for share in shares {
        if !seen_ids.insert(share.id) {
            return Err(InvalidInputs("Duplicate share ID".into()));
        }
    }
    if seen_ids.len() < THRESHOLD {
        return Err(InvalidInputs(format!(
            "Received only {} out of {} shares",
            seen_ids.len(),
            THRESHOLD
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

    // Note: Library switching works because k256's to_bytes and secp256k1's from_slice both
    //       use big-endian representation. We are juggling between two libraries because secp256k1
    //       does not expose the arithmetic tools needed to implement secret-sharing.
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&result.to_bytes())
        .expect("casting secret key into secp256k1 failed");
    Ok(bitcoin::secp256k1::Keypair::from_secret_key(&BTC_LIB, &sk))
}

/// Create a commitment (hash) for a share
pub fn commit_share(share: &Share) -> ShareCommitment {
    let commitment = ProjectivePoint::GENERATOR * share.value;
    ShareCommitment {
        id: share.id,
        digest: commitment.to_bytes().to_vec(),
    }
}

/// Encrypt a share with optional AAD
pub fn encrypt_share<R: CryptoRng + RngCore>(
    share: &Share,
    pk: &EncPubKey,
    aad: Option<&[u8; 32]>,
    rng: &mut R,
) -> EncryptedShare {
    EncryptedShare {
        id: share.id,
        ciphertext: encrypt(&share.value.to_bytes(), pk, aad, rng)
            .expect("neither plaintext nor aad are long"),
    }
}

/// Decrypt an encrypted share with optional AAD
pub fn decrypt_share(
    encrypted_share: &EncryptedShare,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Share> {
    let serialized_share = decrypt(&encrypted_share.ciphertext, sk, aad)?;
    let result: Option<Scalar> =
        Scalar::from_repr(*FieldBytes::from_slice(&serialized_share)).into();
    match result {
        Some(x) => Ok(Share {
            id: encrypted_share.id,
            value: x,
        }),
        None => Err(InvalidInputs("Failed to deserialize share".into())),
    }
}

// ---------------------------------
//    Signing utilities
// ---------------------------------

/// Methods for `Signed<T>` wrapper - signing and verification
impl<T: Serialize + SigningIntent> GuardianSigned<T> {
    /// Create a new signed payload (used by enclave)
    /// Includes intent byte for domain separation to prevent cross-type signature attacks
    pub fn new(data: T, signing_key: &SigningKey, timestamp_ms: u64) -> Self {
        let tuple = (T::INTENT, &data, timestamp_ms);
        let signing_payload = bcs::to_bytes(&tuple).expect("serialization should not fail");
        let signature = signing_key.sign(&signing_payload);
        Self {
            data,
            timestamp_ms,
            signature,
        }
    }

    /// Verify signature and extract payload
    /// Checks intent byte to ensure signature is for the correct type
    pub fn verify(self, pub_key: &VerificationKey) -> GuardianResult<T> {
        let tuple = (T::INTENT, &self.data, self.timestamp_ms);
        let msg_bytes = bcs::to_bytes(&tuple).expect("serialization should not fail");
        pub_key
            .verify(&self.signature, &msg_bytes)
            .map_err(|_| InvalidInputs("signature invalid".into()))?;
        Ok(self.data)
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

    #[test]
    fn test_encrypt_and_decrypt() {
        let bytes = b"Let's encrypt some stuff!";
        let keypair = GuardianEncKeyPair::random(&mut rand::thread_rng());
        let aad = Some(&[0; 32]);
        let ciphertext =
            encrypt(bytes, keypair.public_key(), aad, &mut rand::thread_rng()).unwrap();
        assert!(decrypt(&ciphertext, keypair.secret_key(), aad).is_ok_and(|x| x == bytes));

        let wrong_aad = Some(&[10; 32]);
        assert!(decrypt(&ciphertext, keypair.secret_key(), wrong_aad)
            .is_err_and(|x| matches!(x, InvalidInputs(_))));
    }

    // Verify secret reconstruction with varying number of shares (0 to limit)
    // Tests that:
    // - With insufficient shares (< threshold): either error or wrong reconstruction
    // - Threshold shares can reconstruct the original secret
    // - Correct conversion to bitcoin::secp256k1::SecretKey
    // - Full round-trip produces equivalent keys
    #[test]
    fn test_varying_share_count() {
        // Start with a k256::SecretKey
        let original_k256_sk = SecretKey::random(&mut rand::thread_rng());
        let original_bytes = original_k256_sk.to_bytes();

        // Split the secret into shares
        let shares = split_secret(&original_k256_sk, &mut rand::thread_rng());

        // Test reconstruction with varying numbers of shares from 0 to LIMIT
        for num_shares in 0..=NUM_OF_SHARES {
            let shares_subset = &shares[0..num_shares];
            let result = combine_shares(shares_subset);

            if num_shares < THRESHOLD {
                // With insufficient shares, either:
                // 1. The combine operation fails (returns error), OR
                // 2. The combine operation succeeds but produces wrong secret
                match result {
                    Err(_) => {
                        // Good: operation failed as expected
                    }
                    Ok(reconstructed) => {
                        // Operation succeeded but should produce wrong secret
                        let reconstructed_bytes = reconstructed.secret_bytes();
                        assert_ne!(
                            original_bytes.as_slice(),
                            &reconstructed_bytes,
                            "With {} shares (less than threshold {}), should not reconstruct correct secret",
                            num_shares,
                            THRESHOLD
                        );
                    }
                }
            } else {
                // With threshold or more shares, reconstruction should succeed and match original
                let reconstructed_secp_sk = result.unwrap();
                let reconstructed_bytes = reconstructed_secp_sk.secret_bytes();

                // Verify the reconstructed secret matches the original
                assert_eq!(
                    original_bytes.as_slice(),
                    &reconstructed_bytes,
                    "Reconstructed secret should match original (using {} shares)",
                    num_shares
                );
            }
        }
    }

    // Verify any subset of THRESHOLD shares works
    #[test]
    fn test_varying_subsets() {
        let original_sk = SecretKey::random(&mut rand::thread_rng());
        let original_bytes = original_sk.to_bytes();

        // Generate all shares
        let shares = split_secret(&original_sk, &mut rand::thread_rng());

        // Test different combinations of THRESHOLD shares
        // Try shares [0,1,2], [1,2,3], [2,3,4], etc.
        for start_idx in 0..=(NUM_OF_SHARES - THRESHOLD) {
            let subset = &shares[start_idx..(start_idx + THRESHOLD)];
            let reconstructed = combine_shares(subset).unwrap();

            assert_eq!(
                original_bytes.as_slice(),
                &reconstructed.secret_bytes(),
                "Any subset of {} shares should reconstruct the original secret (testing subset starting at index {})",
                THRESHOLD,
                start_idx
            );
        }
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

    // Test that combine_shares rejects shares with duplicate identifiers
    #[test]
    fn test_combine_shares_rejects_duplicate_ids() {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let shares = split_secret(&sk, &mut rand::thread_rng());

        // Create a list with duplicate share IDs: [shares[0], shares[1], shares[0]]
        let duplicate_shares = vec![shares[0], shares[1], shares[0]];

        let result = combine_shares(&duplicate_shares);
        assert!(
            result.is_err(),
            "combine_shares should reject shares with duplicate IDs"
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Duplicate share ID"));
    }
}
