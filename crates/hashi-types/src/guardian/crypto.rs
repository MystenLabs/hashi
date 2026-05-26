// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianError::InvalidInputs;
use super::GuardianResult;
use super::GuardianSigned;
use super::SigningIntent;
use super::UnixMillis;
use super::bitcoin_utils::BTC_LIB;
use ed25519_consensus::SigningKey;
use ed25519_consensus::VerificationKey;
use hpke::Deserializable;
use hpke::Kem;
use hpke::Serializable;
use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha384;
use hpke::kem::X25519HkdfSha256;
use k256::CompressedPoint;
use k256::FieldBytes;
use k256::ProjectivePoint;
use k256::Scalar;
use k256::elliptic_curve::Field;
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use rand_core::CryptoRng;
use rand_core::RngCore;
use sequoia_openpgp as openpgp;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::Encryptor;
use sequoia_openpgp::serialize::stream::LiteralWriter;
use sequoia_openpgp::serialize::stream::Message;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Write;
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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianEncryptedShare {
    pub id: ShareID,
    pub ciphertext: Ciphertext,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KPEncryptedShare {
    pub id: ShareID,
    pub armored_ciphertext: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PgpPublicCert {
    armored: String,
    cert: openpgp::Cert,
}

pub type DigestBytes = Vec<u8>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitment {
    pub id: ShareID,
    pub digest: DigestBytes,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ShareCommitments(BTreeMap<ShareID, DigestBytes>);

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

impl PgpPublicCert {
    pub fn new(armored: String) -> GuardianResult<Self> {
        let cert = openpgp::Cert::from_bytes(armored.as_bytes())
            .map_err(|e| InvalidInputs(format!("invalid OpenPGP certificate: {e}")))?;
        validate_pgp_cert(&cert)?;
        Ok(Self { armored, cert })
    }

    pub fn armored(&self) -> &str {
        &self.armored
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

fn validate_pgp_cert(cert: &openpgp::Cert) -> GuardianResult<()> {
    let policy = StandardPolicy::new();
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .ok_or_else(|| InvalidInputs("OpenPGP certificate has no usable encryption key".into()))?;
    Ok(())
}

fn pgp_encrypt_armored(plaintext: &[u8], cert: &PgpPublicCert) -> String {
    let policy = StandardPolicy::new();
    let recipients = cert
        .cert
        .keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();
    let mut ciphertext = Vec::new();
    let message = Message::new(&mut ciphertext);
    let message = Armorer::new(message)
        .kind(openpgp::armor::Kind::Message)
        .build()
        .expect("OpenPGP armor setup should not fail when writing to Vec");
    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .expect("PgpPublicCert validation ensures an encryption recipient");
    let mut writer = LiteralWriter::new(message)
        .build()
        .expect("OpenPGP literal data setup should not fail");
    writer
        .write_all(plaintext)
        .expect("OpenPGP encryption should not fail when writing to Vec");
    writer
        .finalize()
        .expect("OpenPGP encryption finalization should not fail when writing to Vec");
    String::from_utf8(ciphertext).expect("OpenPGP ASCII armor should be valid UTF-8")
}

// ---------------------------------
//    Secret-sharing utilities
// ---------------------------------

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

/// Combine secret shares to a secp256k1 secret key with reconstruction
/// threshold `t`. Errors on duplicate share IDs or fewer than `t` shares.
pub fn combine_shares(shares: &[Share], t: usize) -> GuardianResult<bitcoin::secp256k1::Keypair> {
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
) -> GuardianEncryptedShare {
    GuardianEncryptedShare {
        id: share.id,
        ciphertext: encrypt(&share.value.to_bytes(), pk, aad, rng)
            .expect("neither plaintext nor aad are long"),
    }
}

/// Split `sk` into `params.num_shares()` shares with reconstruction threshold
/// `params.threshold()`, encrypt each to the matching KP OpenPGP cert, and
/// compute the corresponding commitments. Share ID `i` (1..=N) is paired with
/// `kp_certs[i-1]`.
///
/// # Panics
///
/// Panics if `kp_certs.len() != params.num_shares()`.
pub fn split_and_encrypt_for_kps<R: CryptoRng + RngCore>(
    sk: &k256::SecretKey,
    kp_certs: &[PgpPublicCert],
    params: &SecretSharingParams,
    rng: &mut R,
) -> (Vec<KPEncryptedShare>, ShareCommitments) {
    assert_eq!(
        kp_certs.len(),
        params.num_shares(),
        "SetupNewKeyRequest validation ensures one KP cert per share",
    );
    let shares = split_secret(sk, params, rng);
    let n = params.num_shares();
    let mut encrypted_shares = Vec::with_capacity(n);
    let mut commitments = Vec::with_capacity(n);
    for (share, cert) in shares.iter().zip(kp_certs.iter()) {
        encrypted_shares.push(encrypt_share_for_provisioner(share, cert));
        commitments.push(commit_share(share));
    }
    let commitments =
        ShareCommitments::new(commitments).expect("share IDs 1..=n are unique by construction");
    (encrypted_shares, commitments)
}

/// Encrypt a share for delivery to a key provisioner using OpenPGP ASCII armor.
pub fn encrypt_share_for_provisioner(share: &Share, cert: &PgpPublicCert) -> KPEncryptedShare {
    KPEncryptedShare {
        id: share.id,
        armored_ciphertext: pgp_encrypt_armored(&share.value.to_bytes(), cert),
    }
}

/// Decrypt an encrypted share with optional AAD
pub fn decrypt_share(
    encrypted_share: &GuardianEncryptedShare,
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
    pub fn new(data: T, signing_key: &SigningKey, timestamp_ms: UnixMillis) -> Self {
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
    use sequoia_openpgp::cert::prelude::CertBuilder;
    use sequoia_openpgp::crypto::SessionKey;
    use sequoia_openpgp::parse::stream::DecryptionHelper;
    use sequoia_openpgp::parse::stream::DecryptorBuilder;
    use sequoia_openpgp::parse::stream::MessageStructure;
    use sequoia_openpgp::parse::stream::VerificationHelper;
    use sequoia_openpgp::policy::Policy;
    use sequoia_openpgp::serialize::Serialize;
    use sequoia_openpgp::types::SymmetricAlgorithm;
    use std::io;

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

    #[test]
    fn test_pgp_encrypt_armored_and_decrypt() {
        let policy = StandardPolicy::new();
        let (cert, _) = CertBuilder::general_purpose(["kp@example.com"])
            .generate()
            .unwrap();
        let mut armored = Vec::new();
        cert.armored().export(&mut armored).unwrap();
        let public_cert = PgpPublicCert::new(String::from_utf8(armored).unwrap()).unwrap();

        let plaintext = b"secret share bytes";
        let ciphertext = pgp_encrypt_armored(plaintext, &public_cert);
        assert!(ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));

        let helper = PgpDecryptHelper {
            cert: &cert,
            policy: &policy,
        };
        let mut decryptor = DecryptorBuilder::from_bytes(ciphertext.as_bytes())
            .unwrap()
            .with_policy(&policy, None, helper)
            .unwrap();
        let mut decrypted = Vec::new();
        io::copy(&mut decryptor, &mut decrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    struct PgpDecryptHelper<'a> {
        cert: &'a openpgp::Cert,
        policy: &'a dyn Policy,
    }

    impl VerificationHelper for PgpDecryptHelper<'_> {
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<openpgp::Cert>> {
            Ok(Vec::new())
        }

        fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
            Ok(())
        }
    }

    impl DecryptionHelper for PgpDecryptHelper<'_> {
        fn decrypt(
            &mut self,
            pkesks: &[openpgp::packet::PKESK],
            _skesks: &[openpgp::packet::SKESK],
            sym_algo: Option<SymmetricAlgorithm>,
            decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
        ) -> openpgp::Result<Option<openpgp::Cert>> {
            let key = self
                .cert
                .keys()
                .unencrypted_secret()
                .with_policy(self.policy, None)
                .for_transport_encryption()
                .next()
                .unwrap()
                .key()
                .clone();
            let mut keypair = key.into_keypair()?;
            pkesks[0]
                .decrypt(&mut keypair, sym_algo)
                .map(|(algo, session_key)| decrypt(algo, &session_key));

            Ok(None)
        }
    }

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
                    original_bytes.as_slice(),
                    &reconstructed.secret_bytes(),
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
                original_bytes.as_slice(),
                &reconstructed.secret_bytes(),
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
