// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::guardian::errors::GuardianError::InvalidInputs;
use crate::guardian::errors::GuardianResult;
use hpke::Deserializable;
use hpke::Kem;
use hpke::Serializable;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kem::X25519HkdfSha256;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;

pub type EncSecKey = <X25519HkdfSha256 as Kem>::PrivateKey;
pub type EncPubKey = <X25519HkdfSha256 as Kem>::PublicKey;
pub type EncPubKeyBytes = Vec<u8>; // Use as an alternative to EncPubKey where Serialize is needed
pub type EncapsulatedKey = <X25519HkdfSha256 as Kem>::EncappedKey;

pub struct GuardianEncKeyPair {
    sk: EncSecKey,
    pk: EncPubKey,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Ciphertext {
    pub encapsulated_key: Vec<u8>,
    pub aes_ciphertext: Vec<u8>,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() {
        let bytes = b"Let's encrypt some stuff!";
        let keypair = GuardianEncKeyPair::random(&mut rand::thread_rng());
        let aad = Some(&[0; 32]);
        let ciphertext =
            encrypt(bytes, keypair.public_key(), aad, &mut rand::thread_rng()).unwrap();
        assert!(decrypt(&ciphertext, keypair.secret_key(), aad).is_ok_and(|x| x == bytes));

        let wrong_aad = Some(&[10; 32]);
        assert!(
            decrypt(&ciphertext, keypair.secret_key(), wrong_aad)
                .is_err_and(|x| matches!(x, InvalidInputs(_)))
        );
    }
}
