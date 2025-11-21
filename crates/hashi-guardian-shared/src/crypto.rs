use crate::errors::{GuardianError, GuardianResult};
use crate::{Ciphertext, EncryptedShare, ShareCommitment};
use fastcrypto::hash::{Blake2b256, HashFunction};
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, HpkeError, Kem, Serializable};
use k256::elliptic_curve::PrimeField;
use k256::{Scalar, SecretKey};
use vsss_rs::{shamir, DefaultShare, IdentifierPrimeField, ReadableShareSet, Share};

// ---------------------------------
//      Crypto Types
// ---------------------------------

pub type EncSecKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type EncPubKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub struct EncKeyPair {
    sk: EncSecKey,
    pk: EncPubKey,
}
pub type EncapsulatedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

pub type K256ShareBase = IdentifierPrimeField<Scalar>;
pub type ShareID = K256ShareBase;
pub type ShareValue = K256ShareBase;
pub type MyShare = DefaultShare<ShareID, ShareValue>;

// Secret sharing constants: threshold and total number of key provisioners
pub const THRESHOLD: usize = 3;
pub const LIMIT: usize = 5;

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl EncKeyPair {
    pub fn secret(&self) -> &EncSecKey {
        &self.sk
    }
    pub fn public(&self) -> &EncPubKey {
        &self.pk
    }
}

impl From<(EncSecKey, EncPubKey)> for EncKeyPair {
    fn from((enc_sk, enc_pk): (EncSecKey, EncPubKey)) -> Self {
        EncKeyPair {
            sk: enc_sk,
            pk: enc_pk,
        }
    }
}

impl From<Vec<EncPubKey>> for crate::SetupNewKeyRequest {
    fn from(keys: Vec<EncPubKey>) -> Self {
        crate::SetupNewKeyRequest {
            key_provisioner_public_keys: keys.iter().map(|k| k.to_bytes().to_vec()).collect(),
        }
    }
}

impl TryFrom<crate::SetupNewKeyRequest> for Vec<EncPubKey> {
    type Error = HpkeError;
    fn try_from(value: crate::SetupNewKeyRequest) -> Result<Self, Self::Error> {
        value
            .key_provisioner_public_keys
            .into_iter()
            .map(|k| EncPubKey::from_bytes(&k))
            .collect()
    }
}

// ---------------------------------
//    Encryption/Decryption utils
// ---------------------------------

pub fn encrypt(bytes: &[u8], pk: &EncPubKey, aad: Option<&[u8; 32]>) -> GuardianResult<Ciphertext> {
    let mut rng = rand::thread_rng();
    let (encapsulated_key, aes_ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            &pk,
            &[],
            &bytes,
            aad.or(Option::Some(&[0; 32])).expect("REASON"),
            &mut rng,
        )
        .map_err(|e| GuardianError::GenericError(format!("Failed to encrypt: {}", e)))?;

    Ok((encapsulated_key, aes_ciphertext).into())
}

pub fn decrypt(
    ciphertext: &Ciphertext,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Vec<u8>> {
    let (encapsulated_key, aes_ciphertext) = ciphertext.try_into().map_err(|e: HpkeError| {
        GuardianError::GenericError(format!("Failed to deserialize ciphertext: {}", e))
    })?;

    let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        sk,
        &encapsulated_key,
        &[],
        &aes_ciphertext,
        aad.or(Option::Some(&[0; 32])).expect("REASON"),
    )
    .map_err(|e| GuardianError::GenericError(format!("Failed to decrypt: {}", e)))?;

    Ok(decrypted)
}

// ---------------------------------
//    Secret Sharing utilities
// ---------------------------------

/// Split a k256 SecretKey into shares using Shamir's secret sharing
pub fn k256_secret_key_to_shares(sk: SecretKey) -> GuardianResult<Vec<MyShare>> {
    let nzs = sk.to_nonzero_scalar();
    let shared_secret = IdentifierPrimeField(*nzs.as_ref());
    let shares =
        shamir::split_secret::<MyShare>(THRESHOLD, LIMIT, &shared_secret, &mut rand::thread_rng())
            .map_err(|e| GuardianError::GenericError(format!("Failed to split secret: {}", e)))?;
    Ok(shares)
}

/// Create a commitment (hash) for a share
pub fn commit_share(share: &MyShare) -> GuardianResult<ShareCommitment> {
    let share_id = share.identifier;
    let share_value = share.value;
    let bytes = bincode::serialize(&share_value).map_err(|e| {
        GuardianError::GenericError(format!("Failed to serialize share value: {}", e))
    })?;
    Ok((share_id, Blake2b256::digest(&bytes)).into())
}

/// Encrypt a share for a given public key with optional AAD
pub fn encrypt_share(
    share: &MyShare,
    pk: &EncPubKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<EncryptedShare> {
    let share_id = share.identifier;
    let share_value = share.value;
    let bytes = bincode::serialize(&share_value).map_err(|e| {
        GuardianError::GenericError(format!("Failed to serialize share value: {}", e))
    })?;
    let ciphertext = encrypt(&bytes, pk, aad)?;
    Ok((share_id, ciphertext).into())
}

/// Decrypt an encrypted share with optional AAD
pub fn decrypt_share(
    encrypted_share: &EncryptedShare,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<MyShare> {
    let share_id = *encrypted_share.id();
    let serialized_share = decrypt(encrypted_share.ciphertext(), sk, aad)?;
    let share_value: ShareValue = bincode::deserialize(&serialized_share).map_err(|e| {
        GuardianError::GenericError(format!("Failed to deserialize share value: {}", e))
    })?;
    Ok(MyShare::with_identifier_and_value(share_id, share_value))
}

/// Combine shares back into a bitcoin secp256k1 SecretKey
pub fn k256shares_to_secp_secret_key(
    shares: &[MyShare],
) -> GuardianResult<bitcoin::secp256k1::SecretKey> {
    let result = shares
        .combine()
        .map_err(|e| GuardianError::GenericError(format!("Failed to combine share: {}", e)))?;

    // Note: Library switching works because k256's to_bytes and secp256k1's from_slice both
    //       use the same representation to store bytes (big-endian). We need this because the
    //       secret-sharing lib expects RustCrypto traits that secp256k1 does not implement.
    //       And performing btc operations is easier with secp256k1.
    let sk = result.0.to_repr();
    let secp_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk).map_err(|e| {
        GuardianError::GenericError(format!("Failed to cast combined secret key: {}", e))
    })?;
    Ok(secp_sk)
}

#[cfg(test)]
mod encryption_tests {
    // https://github.com/rozbb/rust-hpke/tree/main
    // Note: using hpke
    use super::{decrypt, encrypt};
    use hpke::aead::AesGcm256;
    use hpke::kdf::HkdfSha384;
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn test_hpke() {
        let plaintext = b"Hello, world!";
        let aad = b"aad";

        let mut rng = StdRng::from_entropy();
        let keys = X25519HkdfSha256::gen_keypair(&mut rng);

        let (encapped_key, ciphertext) =
            hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
                &hpke::OpModeS::Base,
                &keys.1,
                &[],
                plaintext,
                aad,
                &mut rng,
            )
            .unwrap();
        let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
            &hpke::OpModeR::Base,
            &keys.0,
            &encapped_key,
            &[],
            &ciphertext,
            aad,
        )
        .unwrap();
        println!("decrypted: {:?}", decrypted);
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_and_decrypt() {
        let bytes = b"Let's encrypt some stuff!";
        let mut rng = rand::thread_rng();
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let ciphertext = encrypt(bytes, &pk, None).unwrap();
        let decrypted_plaintext = decrypt(&ciphertext, &sk, None).unwrap();
        assert_eq!(bytes, &decrypted_plaintext[..]);
    }
}

#[cfg(test)]
mod secret_sharing_tests {
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use k256::elliptic_curve::PrimeField;
    use vsss_rs::{shamir, IdentifierPrimeField, ReadableShareSet};

    #[test]
    fn basic_secret_sharing() {
        let mut osrng = rand_core::OsRng::default();
        let sk = SecretKey::random(&mut osrng);
        let nzs = sk.to_nonzero_scalar();
        let shared_secret = IdentifierPrimeField(*nzs.as_ref());
        let res = shamir::split_secret::<MyShare>(2, 3, &shared_secret, &mut osrng);
        assert!(res.is_ok());
        let shares = res.unwrap();
        println!("{:?}", shares);
        let res = shares.combine();
        assert!(res.is_ok());
        let scalar = res.unwrap();
        let sk_dup = SecretKey::from_bytes(&scalar.0.to_repr()).unwrap();
        assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn test_libs_signing_compat() {
        let msg = [7u8; 32];
        let mut osrng = rand_core::OsRng::default();
        let sk1 = k256::SecretKey::random(&mut osrng);
        let sk1_bytes = sk1.to_bytes();

        let secp = Secp256k1::new();
        let sk2 = bitcoin::secp256k1::SecretKey::from_slice(&sk1_bytes).unwrap();

        // secp signing
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk2);
        let bytes = [2u8; 32];
        let msg_dup = Message::from_digest(msg);
        let signature = secp.sign_schnorr_with_aux_rand(&msg_dup, &keypair, &bytes);
        let xonly_pubkey = bitcoin::XOnlyPublicKey::from_keypair(&keypair).0;
        secp.verify_schnorr(&signature, &msg_dup, &xonly_pubkey)
            .unwrap();

        // k256 Schnorr signing
        let k256_schnorr_key = k256::schnorr::SigningKey::from_bytes(&sk1_bytes).unwrap();
        let k256_schnorr_sig = k256_schnorr_key.sign_raw(&msg, &bytes).unwrap();
        assert_eq!(signature.serialize(), k256_schnorr_sig.to_bytes());

        // Verify with k256 Schnorr
        let k256_schnorr_vkey = k256_schnorr_key.verifying_key();
        k256_schnorr_vkey
            .verify_raw(&msg, &k256_schnorr_sig)
            .unwrap();
    }

    // Verify that k256_secret_key_to_shares generates the correct number of shares
    #[test]
    fn test_k256_secret_key_to_shares_generates_correct_number() {
        let mut osrng = rand_core::OsRng::default();
        let sk = SecretKey::random(&mut osrng);

        let shares = k256_secret_key_to_shares(sk).unwrap();

        // Should generate LIMIT (5) shares
        assert_eq!(
            shares.len(),
            LIMIT,
            "Should generate exactly {} shares",
            LIMIT
        );

        // Verify all shares have unique identifiers
        let mut identifiers = std::collections::HashSet::new();
        for share in &shares {
            assert!(
                identifiers.insert(share.identifier),
                "Share identifiers should be unique"
            );
        }
    }

    // Verify secret reconstruction with varying number of shares (0 to limit)
    // Tests that:
    // - With insufficient shares (< threshold): either error or wrong reconstruction
    // - Threshold shares can reconstruct the original secret
    // - Correct conversion to bitcoin::secp256k1::SecretKey
    // - Full round-trip produces equivalent keys
    #[test]
    fn test_roundtrip_reconstruction_varying_shares() {
        let mut osrng = rand_core::OsRng::default();

        // Start with a k256::SecretKey
        let original_k256_sk = SecretKey::random(&mut osrng);
        let original_bytes = original_k256_sk.to_bytes();

        // Split the secret into shares
        let shares = k256_secret_key_to_shares(original_k256_sk).unwrap();

        // Test reconstruction with varying numbers of shares from 0 to LIMIT
        for num_shares in 0..=LIMIT {
            let shares_subset = &shares[0..num_shares];
            let result = k256shares_to_secp_secret_key(shares_subset);

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
    fn test_any_threshold_subset_reconstructs_secret() {
        let mut osrng = rand_core::OsRng::default();
        let original_sk = SecretKey::random(&mut osrng);
        let original_bytes = original_sk.to_bytes();

        // Generate all shares
        let shares = k256_secret_key_to_shares(original_sk).unwrap();

        // Test different combinations of THRESHOLD shares
        // Try shares [0,1,2], [1,2,3], [2,3,4], etc.
        for start_idx in 0..=(LIMIT - THRESHOLD) {
            let subset = &shares[start_idx..(start_idx + THRESHOLD)];
            let reconstructed = k256shares_to_secp_secret_key(subset).unwrap();

            assert_eq!(
                original_bytes.as_slice(),
                &reconstructed.secret_bytes(),
                "Any subset of {} shares should reconstruct the original secret (testing subset starting at index {})",
                THRESHOLD,
                start_idx
            );
        }
    }
}
