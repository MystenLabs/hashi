use crate::GuardianError::InternalError;
use crate::GuardianResult;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kem::X25519HkdfSha256;
use hpke::Deserializable;
use hpke::HpkeError;
use hpke::Kem;
use hpke::Serializable;
use k256::Scalar;
use serde::Deserialize;
use serde::Serialize;
use vsss_rs::shamir;
use vsss_rs::DefaultShare;
use vsss_rs::IdentifierPrimeField;
use vsss_rs::ReadableShareSet;
use vsss_rs::Share;

// ---------------------------------
//      Crypto Structs & Types
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitment {
    pub id: ShareID,
    pub digest: DigestBytes,
}

pub type DigestBytes = [u8; 32];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Ciphertext {
    pub encapsulated_key: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl EncKeyPair {
    pub fn random() -> Self {
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rand::thread_rng());
        Self { sk, pk }
    }

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

impl From<(EncapsulatedKey, Vec<u8>)> for Ciphertext {
    fn from((encapsulated_key, aes_ciphertext): (EncapsulatedKey, Vec<u8>)) -> Self {
        Ciphertext {
            encapsulated_key: encapsulated_key.to_bytes().to_vec(),
            aes_ciphertext,
        }
    }
}

impl<'a> TryFrom<&'a Ciphertext> for (EncapsulatedKey, &'a [u8]) {
    type Error = HpkeError;
    fn try_from(value: &'a Ciphertext) -> Result<Self, Self::Error> {
        Ok((
            EncapsulatedKey::from_bytes(&value.encapsulated_key)?,
            &value.aes_ciphertext,
        ))
    }
}

impl ShareCommitment {
    pub fn id(&self) -> &ShareID {
        &self.id
    }

    pub fn digest(&self) -> &DigestBytes {
        &self.digest
    }
}

impl From<(ShareID, DigestBytes)> for ShareCommitment {
    fn from((id, digest): (ShareID, DigestBytes)) -> ShareCommitment {
        ShareCommitment { id, digest }
    }
}

impl EncryptedShare {
    pub fn id(&self) -> &ShareID {
        &self.id
    }

    pub fn ciphertext(&self) -> &Ciphertext {
        &self.ciphertext
    }
}

impl From<(ShareID, Ciphertext)> for EncryptedShare {
    fn from((id, ciphertext): (ShareID, Ciphertext)) -> EncryptedShare {
        EncryptedShare { id, ciphertext }
    }
}

// ---------------------------------
//    Encryption/Decryption utils
// ---------------------------------

pub fn encrypt(bytes: &[u8], pk: &EncPubKey, aad: Option<&[u8; 32]>) -> GuardianResult<Ciphertext> {
    let (encapsulated_key, aes_ciphertext) =
        hpke::single_shot_seal::<AesGcm256, HkdfSha384, X25519HkdfSha256, _>(
            &hpke::OpModeS::Base,
            pk,
            &[],
            bytes,
            aad.unwrap_or(&[0; 32]),
            &mut rand::thread_rng(),
        )
        .map_err(|e| InternalError(format!("Failed to encrypt: {}", e)))?;
    Ok((encapsulated_key, aes_ciphertext).into())
}

pub fn decrypt(
    ciphertext: &Ciphertext,
    sk: &EncSecKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<Vec<u8>> {
    let (encapsulated_key, aes_ciphertext) = ciphertext.try_into().map_err(|e: HpkeError| {
        InternalError(format!("Failed to deserialize ciphertext: {}", e))
    })?;
    let decrypted = hpke::single_shot_open::<AesGcm256, HkdfSha384, X25519HkdfSha256>(
        &hpke::OpModeR::Base,
        sk,
        &encapsulated_key,
        &[],
        aes_ciphertext,
        aad.unwrap_or(&[0; 32]),
    )
    .map_err(|e| InternalError(format!("Failed to decrypt: {}", e)))?;
    Ok(decrypted)
}

// ---------------------------------
//    Secret Sharing utilities
// ---------------------------------

/// Split a k256 SecretKey into shares using Shamir's secret sharing
pub fn split_secret(sk: &k256::SecretKey) -> GuardianResult<Vec<MyShare>> {
    let nzs = sk.to_nonzero_scalar();
    let shared_secret = IdentifierPrimeField(*nzs.as_ref());
    let shares =
        shamir::split_secret::<MyShare>(THRESHOLD, LIMIT, &shared_secret, &mut rand::thread_rng())
            .map_err(|e| InternalError(format!("Failed to split secret: {}", e)))?;
    Ok(shares)
}

/// Combine shares back into a bitcoin secp256k1 SecretKey
pub fn combine_shares(shares: &[MyShare]) -> GuardianResult<bitcoin::secp256k1::SecretKey> {
    let result = shares
        .combine()
        .map_err(|e| InternalError(format!("Failed to combine share: {}", e)))?;

    // Note: Library switching works because k256's to_bytes and secp256k1's from_slice both
    //       use the same representation to store bytes (big-endian). We are juggling between two
    //       libraries because the secret-sharing lib expects RustCrypto traits
    //       that bitcoin lib does not implement.
    let sk = result.to_bytes();
    let secp_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk)
        .map_err(|e| InternalError(format!("Failed to cast combined secret key: {}", e)))?;
    Ok(secp_sk)
}

/// Create a commitment (hash) for a share
pub fn commit_share(share: &MyShare) -> GuardianResult<ShareCommitment> {
    let share_id = share.identifier;
    let share_value = share.value;
    let bytes = bincode::serialize(&share_value)
        .map_err(|e| InternalError(format!("Failed to serialize share value: {}", e)))?;
    Ok((share_id, Blake2b::<U32>::digest(&bytes).into()).into())
}

/// Encrypt a share with optional AAD
pub fn encrypt_share(
    share: &MyShare,
    pk: &EncPubKey,
    aad: Option<&[u8; 32]>,
) -> GuardianResult<EncryptedShare> {
    let share_id = share.identifier;
    let share_value = share.value;
    let bytes = bincode::serialize(&share_value)
        .map_err(|e| InternalError(format!("Failed to serialize share value: {}", e)))?;
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
    let share_value: ShareValue = bincode::deserialize(&serialized_share)
        .map_err(|e| InternalError(format!("Failed to deserialize share value: {}", e)))?;
    Ok(MyShare::with_identifier_and_value(share_id, share_value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::SecretKey;
    use vsss_rs::ReadableShareSet;

    #[test]
    fn test_encrypt_and_decrypt() {
        let bytes = b"Let's encrypt some stuff!";
        let keypair = EncKeyPair::random();
        let ciphertext = encrypt(bytes, keypair.public(), None).unwrap();
        let decrypted_plaintext = decrypt(&ciphertext, keypair.secret(), None).unwrap();
        assert_eq!(bytes, &decrypted_plaintext[..]);
    }

    #[test]
    fn basic_secret_sharing() {
        let mut osrng = rand_core::OsRng;
        let sk = SecretKey::random(&mut osrng);
        let shares = split_secret(&sk).unwrap();
        println!("{:?}", shares);
        let res = shares.combine().unwrap();
        let sk_dup = SecretKey::from_bytes(&res.to_bytes()).unwrap();
        assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
    }

    // Verify secret reconstruction with varying number of shares (0 to limit)
    // Tests that:
    // - With insufficient shares (< threshold): either error or wrong reconstruction
    // - Threshold shares can reconstruct the original secret
    // - Correct conversion to bitcoin::secp256k1::SecretKey
    // - Full round-trip produces equivalent keys
    #[test]
    fn test_varying_share_count() {
        let mut osrng = rand_core::OsRng;

        // Start with a k256::SecretKey
        let original_k256_sk = SecretKey::random(&mut osrng);
        let original_bytes = original_k256_sk.to_bytes();

        // Split the secret into shares
        let shares = split_secret(&original_k256_sk).unwrap();

        // Test reconstruction with varying numbers of shares from 0 to LIMIT
        for num_shares in 0..=LIMIT {
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
        let mut osrng = rand_core::OsRng;
        let original_sk = SecretKey::random(&mut osrng);
        let original_bytes = original_sk.to_bytes();

        // Generate all shares
        let shares = split_secret(&original_sk).unwrap();

        // Test different combinations of THRESHOLD shares
        // Try shares [0,1,2], [1,2,3], [2,3,4], etc.
        for start_idx in 0..=(LIMIT - THRESHOLD) {
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
}
