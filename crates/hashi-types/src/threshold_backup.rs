// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Threshold encryption for node backups.
//!
//! A threshold backup is encrypted to a passphrase derived from a fresh random
//! scalar. The scalar is Shamir-split `t`-of-`n`, and each share is encrypted to
//! one holder's OpenPGP certificate (typically YubiKey-backed), so any `t`
//! holders can restore a backup and `t - 1` learn nothing.
//!
//! Restore never moves a plaintext share between machines. The restore host
//! opens a [`RestoreSession`] and sends a [`ShareRequest`]; each holder decrypts
//! their share on their own YubiKey and returns a [`ShareResponse`] that is
//! HPKE-encrypted to the session key and bound to the archive header.
//!
//! See `design/docs/threshold-backup.mdx`.

use crate::guardian::crypto::primitives::Ciphertext;
use crate::guardian::crypto::primitives::EncPubKey;
use crate::guardian::crypto::primitives::EncSecKey;
use crate::guardian::crypto::primitives::GuardianEncKeyPair;
use crate::guardian::crypto::primitives::SecretSharingParams;
use crate::guardian::crypto::primitives::Share;
use crate::guardian::crypto::primitives::decrypt as hpke_decrypt;
use crate::guardian::crypto::primitives::encrypt as hpke_encrypt;
use crate::guardian::crypto::primitives::exp_g;
use crate::guardian::crypto::primitives::interpolate_secret;
use crate::guardian::crypto::primitives::split_secret;
use crate::pgp::PgpPublicCert;
use crate::pgp::encrypt_armored;
use anyhow::Context;
use anyhow::Result;
use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
use hpke::Deserializable;
use hpke::Serializable;
use k256::Scalar;
use k256::Secp256k1;
use k256::elliptic_curve::ScalarPrimitive;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::BufRead;
use std::io::Write;
use std::num::NonZeroU16;

pub const HEADER_BEGIN: &str = "-----BEGIN HASHI THRESHOLD BACKUP HEADER-----";
pub const HEADER_END: &str = "-----END HASHI THRESHOLD BACKUP HEADER-----";

const HEADER_VERSION: u32 = 1;
const PASSPHRASE_DOMAIN: &[u8] = b"hashi-threshold-backup-v1";
const HEADER_DIGEST_DOMAIN: &[u8] = b"hashi-threshold-backup-header-v1";
const RESPONSE_AAD_DOMAIN: &[u8] = b"hashi-threshold-backup-response-v1";
/// Generous bound on the header line so a corrupt file cannot make restore
/// buffer the whole archive looking for a newline.
const MAX_HEADER_BYTES: u64 = 4 * 1024 * 1024;

type Blake2b256 = Blake2b<U32>;

/// Validated holder roster: `threshold` of `certs.len()` holders must
/// cooperate to decrypt.
#[derive(Clone, Debug, PartialEq)]
pub struct ThresholdRecipients {
    threshold: usize,
    certs: Vec<PgpPublicCert>,
}

impl ThresholdRecipients {
    pub fn new(threshold: usize, certs: Vec<PgpPublicCert>) -> Result<Self> {
        SecretSharingParams::new(certs.len(), threshold)
            .map_err(|e| anyhow::anyhow!("invalid backup threshold: {e}"))?;

        let mut primaries = BTreeSet::new();
        let mut encryption_keys = BTreeSet::new();
        for cert in &certs {
            anyhow::ensure!(
                primaries.insert(cert.fingerprint()),
                "backup holder certificate {} is listed more than once",
                cert.fingerprint()
            );
            for key in cert.encryption_key_fingerprints() {
                anyhow::ensure!(
                    encryption_keys.insert(key.clone()),
                    "encryption key {key} appears in more than one backup holder certificate"
                );
            }
        }
        Ok(Self { threshold, certs })
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn certs(&self) -> &[PgpPublicCert] {
        &self.certs
    }

    fn params(&self) -> SecretSharingParams {
        SecretSharingParams::new(self.certs.len(), self.threshold)
            .expect("validated in ThresholdRecipients::new")
    }
}

/// One holder's entry in the archive header.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedShareEntry {
    pub id: u16,
    /// Primary fingerprint of the holder's certificate, uppercase hex.
    pub recipient: String,
    /// `G * share`, compressed SEC1, hex.
    pub commitment: String,
    /// The 32-byte share scalar, encrypted to the holder as an armored
    /// OpenPGP message.
    pub ciphertext: String,
}

/// Public header written in front of a threshold-encrypted archive.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ThresholdHeader {
    pub version: u32,
    pub threshold: u16,
    /// `G * s` for the shared secret `s`, compressed SEC1, hex.
    pub secret_commitment: String,
    pub shares: Vec<EncryptedShareEntry>,
}

/// Archive passphrase, derived from the shared secret.
pub struct Passphrase(String);

impl Passphrase {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(<redacted>)")
    }
}

fn derive_passphrase(secret: &k256::SecretKey) -> Passphrase {
    let mut hasher = Blake2b256::new();
    hasher.update(PASSPHRASE_DOMAIN);
    hasher.update(secret.to_bytes());
    Passphrase(hex::encode(hasher.finalize()))
}

/// Draw a fresh secret, split it across `recipients`, and return the header to
/// write in front of the archive plus the passphrase to encrypt it with.
pub fn seal<R: CryptoRng + RngCore>(
    recipients: &ThresholdRecipients,
    rng: &mut R,
) -> Result<(ThresholdHeader, Passphrase)> {
    let secret = k256::SecretKey::random(&mut *rng);
    let shares = split_secret(&secret, &recipients.params(), rng);
    let mut entries = Vec::with_capacity(shares.len());
    for (share, cert) in shares.iter().zip(recipients.certs()) {
        entries.push(EncryptedShareEntry {
            id: share.id.get(),
            recipient: cert.fingerprint().to_hex(),
            commitment: hex::encode(exp_g(&share.value)),
            ciphertext: encrypt_armored(&share.value.to_bytes(), cert)
                .with_context(|| format!("encrypt backup share to {}", cert.fingerprint()))?,
        });
    }
    let header = ThresholdHeader {
        version: HEADER_VERSION,
        threshold: u16::try_from(recipients.threshold()).expect("threshold <= n <= u16::MAX"),
        secret_commitment: hex::encode(exp_g(secret.to_nonzero_scalar().as_ref())),
        shares: entries,
    };
    Ok((header, derive_passphrase(&secret)))
}

impl ThresholdHeader {
    /// Write the header block, terminated by a newline. The armored archive
    /// follows directly.
    pub fn write_to<W: Write>(&self, mut out: W) -> Result<()> {
        let json = serde_json::to_string(self).context("serialize threshold backup header")?;
        writeln!(out, "{HEADER_BEGIN}")?;
        writeln!(out, "{json}")?;
        writeln!(out, "{HEADER_END}")?;
        Ok(())
    }

    /// Read a header block from the start of `input`, leaving `input`
    /// positioned at the armored archive.
    pub fn read_from<R: BufRead>(input: &mut R) -> Result<Self> {
        let mut limited = std::io::Read::take(&mut *input, MAX_HEADER_BYTES);
        let mut line = String::new();
        limited.read_line(&mut line)?;
        anyhow::ensure!(
            line.trim_end() == HEADER_BEGIN,
            "not a threshold backup: missing header"
        );
        line.clear();
        limited.read_line(&mut line)?;
        let header: Self =
            serde_json::from_str(line.trim_end()).context("malformed threshold backup header")?;
        line.clear();
        limited.read_line(&mut line)?;
        anyhow::ensure!(
            line.trim_end() == HEADER_END,
            "malformed threshold backup header: missing end marker"
        );
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.version == HEADER_VERSION,
            "unsupported threshold backup header version {}",
            self.version
        );
        SecretSharingParams::new(self.shares.len(), self.threshold as usize)
            .map_err(|e| anyhow::anyhow!("invalid threshold backup header: {e}"))?;
        let mut ids = BTreeSet::new();
        for entry in &self.shares {
            anyhow::ensure!(
                entry.id != 0 && ids.insert(entry.id),
                "threshold backup header has an invalid or duplicate share id {}",
                entry.id
            );
        }
        Ok(())
    }

    /// Digest binding share responses to this exact header.
    pub fn digest(&self) -> [u8; 32] {
        let json = serde_json::to_vec(self).expect("header serializes");
        let mut hasher = Blake2b256::new();
        hasher.update(HEADER_DIGEST_DOMAIN);
        hasher.update(json);
        hasher.finalize().into()
    }

    pub fn entry(&self, id: u16) -> Option<&EncryptedShareEntry> {
        self.shares.iter().find(|entry| entry.id == id)
    }

    /// The entry addressed to the holder whose certificate has primary
    /// fingerprint `recipient` (hex, case-insensitive).
    pub fn entry_for(&self, recipient: &str) -> Option<&EncryptedShareEntry> {
        self.shares
            .iter()
            .find(|entry| entry.recipient.eq_ignore_ascii_case(recipient))
    }

    /// Check `share` against its commitment in this header.
    pub fn verify_share(&self, share: &Share) -> Result<()> {
        let entry = self
            .entry(share.id.get())
            .with_context(|| format!("share {} is not part of this backup", share.id))?;
        anyhow::ensure!(
            hex::encode(exp_g(&share.value)) == entry.commitment,
            "share {} does not match its commitment",
            share.id
        );
        Ok(())
    }

    /// Combine at least `threshold` verified shares and derive the archive
    /// passphrase.
    pub fn passphrase_from_shares(&self, shares: &[Share]) -> Result<Passphrase> {
        for share in shares {
            self.verify_share(share)?;
        }
        let secret = interpolate_secret(shares, self.threshold as usize)
            .map_err(|e| anyhow::anyhow!("cannot combine backup shares: {e}"))?;
        anyhow::ensure!(
            hex::encode(exp_g(secret.to_nonzero_scalar().as_ref())) == self.secret_commitment,
            "combined shares do not match the backup's secret commitment"
        );
        Ok(derive_passphrase(&secret))
    }
}

/// True if `prefix` (the first bytes of an archive) starts a threshold header.
pub fn is_threshold_archive(prefix: &[u8]) -> bool {
    prefix.starts_with(HEADER_BEGIN.as_bytes())
}

fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar> {
    ScalarPrimitive::<Secp256k1>::from_slice(bytes)
        .map(Scalar::from)
        .map_err(|_| anyhow::anyhow!("share is not a valid scalar"))
}

/// One-time key pair the restore host uses to receive shares.
pub struct RestoreSession {
    secret_key: EncSecKey,
    public_key: EncPubKey,
}

impl RestoreSession {
    pub fn random<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let pair = GuardianEncKeyPair::random(rng);
        Self {
            secret_key: pair.secret_key().clone(),
            public_key: pair.public_key().clone(),
        }
    }

    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.to_bytes().to_vec()
    }

    pub fn from_secret_key_bytes(bytes: &[u8]) -> Result<Self> {
        let secret_key = EncSecKey::from_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("invalid restore session key: {e}"))?;
        let public_key = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::sk_to_pk(&secret_key);
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    pub fn request(&self, header: &ThresholdHeader) -> ShareRequest {
        ShareRequest {
            version: HEADER_VERSION,
            session_public_key: hex::encode(self.public_key.to_bytes()),
            header: header.clone(),
        }
    }

    /// Decrypt and verify responses, then derive the archive passphrase.
    pub fn open(
        &self,
        header: &ThresholdHeader,
        responses: &[ShareResponse],
    ) -> Result<Passphrase> {
        let aad = response_aad(header, &self.public_key);
        let mut shares = Vec::with_capacity(responses.len());
        for response in responses {
            anyhow::ensure!(
                response.header_digest == hex::encode(header.digest()),
                "share response {} is for a different backup",
                response.share_id
            );
            let plaintext = hpke_decrypt(&response.ciphertext, &self.secret_key, Some(&aad))
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot open share response {}: {e}; was it made for this restore session?",
                        response.share_id
                    )
                })?;
            let id = NonZeroU16::new(response.share_id).context("share id 0 is invalid")?;
            shares.push(Share {
                id,
                value: scalar_from_bytes(&plaintext)?,
            });
        }
        header.passphrase_from_shares(&shares)
    }
}

fn response_aad(header: &ThresholdHeader, session_public_key: &EncPubKey) -> [u8; 32] {
    let mut hasher = Blake2b256::new();
    hasher.update(RESPONSE_AAD_DOMAIN);
    hasher.update(header.digest());
    hasher.update(session_public_key.to_bytes());
    hasher.finalize().into()
}

/// Sent by the restore host to holders. Contains nothing secret.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ShareRequest {
    pub version: u32,
    /// The restore session's X25519 public key, hex.
    pub session_public_key: String,
    pub header: ThresholdHeader,
}

/// A holder's share, encrypted to one restore session.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ShareResponse {
    pub version: u32,
    pub share_id: u16,
    /// Hex digest of the header this response answers.
    pub header_digest: String,
    pub ciphertext: Ciphertext,
}

impl ShareRequest {
    /// Answer this request as the holder with primary fingerprint `recipient`.
    ///
    /// `decrypt` turns the holder's armored share ciphertext into plaintext; in
    /// production it calls gpg so the YubiKey does the decryption. The share
    /// is checked against its commitment before it is re-encrypted.
    pub fn respond<R: CryptoRng + RngCore>(
        &self,
        recipient: &str,
        decrypt: impl FnOnce(&str) -> Result<Vec<u8>>,
        rng: &mut R,
    ) -> Result<ShareResponse> {
        anyhow::ensure!(
            self.version == HEADER_VERSION,
            "unsupported share request version {}",
            self.version
        );
        self.header.validate()?;
        let entry = self
            .header
            .entry_for(recipient)
            .with_context(|| format!("this backup has no share for {recipient}"))?;
        let plaintext = decrypt(&entry.ciphertext)?;
        let share = Share {
            id: NonZeroU16::new(entry.id).expect("validated header"),
            value: scalar_from_bytes(&plaintext)?,
        };
        self.header.verify_share(&share)?;

        let session_key_bytes =
            hex::decode(&self.session_public_key).context("malformed session public key")?;
        let session_key = EncPubKey::from_bytes(&session_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid session public key: {e}"))?;
        let aad = response_aad(&self.header, &session_key);
        let ciphertext = hpke_encrypt(&share.value.to_bytes(), &session_key, Some(&aad), rng)
            .map_err(|e| anyhow::anyhow!("encrypt share response: {e}"))?;
        Ok(ShareResponse {
            version: HEADER_VERSION,
            share_id: entry.id,
            header_digest: hex::encode(self.header.digest()),
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pgp::armored_password_encrypt_writer;
    use crate::pgp::decrypt_with_password;
    use crate::pgp::decrypt_with_secret_key;
    use crate::pgp::test_utils::mock_pgp_keypair;
    use std::io::BufReader;
    use std::io::Read;

    struct Holder {
        cert: PgpPublicCert,
        secret: String,
    }

    impl Holder {
        fn new() -> Self {
            let (public, secret) = mock_pgp_keypair();
            Self {
                cert: PgpPublicCert::new(public).unwrap(),
                secret,
            }
        }

        fn fingerprint(&self) -> String {
            self.cert.fingerprint().to_hex()
        }

        fn decrypt(&self, armored: &str) -> Result<Vec<u8>> {
            let mut out = Vec::new();
            decrypt_with_secret_key(
                std::io::Cursor::new(armored.as_bytes().to_vec()),
                self.secret.as_bytes(),
            )?
            .read_to_end(&mut out)?;
            Ok(out)
        }
    }

    fn holders(n: usize) -> Vec<Holder> {
        (0..n).map(|_| Holder::new()).collect()
    }

    fn recipients(holders: &[Holder], t: usize) -> ThresholdRecipients {
        ThresholdRecipients::new(t, holders.iter().map(|h| h.cert.clone()).collect()).unwrap()
    }

    fn respond_all(request: &ShareRequest, participants: &[&Holder]) -> Vec<ShareResponse> {
        participants
            .iter()
            .map(|holder| {
                request
                    .respond(
                        &holder.fingerprint(),
                        |c| holder.decrypt(c),
                        &mut rand::thread_rng(),
                    )
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn any_threshold_subset_restores_the_archive() {
        let holders = holders(5);
        let (header, passphrase) = seal(&recipients(&holders, 3), &mut rand::thread_rng()).unwrap();

        // Write a full archive: header, then the passphrase-encrypted body.
        let mut file = Vec::new();
        header.write_to(&mut file).unwrap();
        {
            let mut writer =
                armored_password_encrypt_writer(&mut file, passphrase.as_str()).unwrap();
            writer.write_all(b"node backup contents").unwrap();
            writer.finalize().unwrap();
        }
        assert!(is_threshold_archive(&file));

        let mut reader = BufReader::new(std::io::Cursor::new(file));
        let parsed = ThresholdHeader::read_from(&mut reader).unwrap();
        assert_eq!(parsed, header);

        let session = RestoreSession::random(&mut rand::thread_rng());
        let request = session.request(&parsed);
        let responses = respond_all(&request, &[&holders[4], &holders[0], &holders[2]]);
        let restored = session.open(&parsed, &responses).unwrap();
        assert_eq!(restored.as_str(), passphrase.as_str());

        let mut body = Vec::new();
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        decrypt_with_password(std::io::Cursor::new(rest), restored.as_str())
            .unwrap()
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"node backup contents");
    }

    #[test]
    fn fewer_than_threshold_shares_fail() {
        let holders = holders(5);
        let (header, _) = seal(&recipients(&holders, 3), &mut rand::thread_rng()).unwrap();
        let session = RestoreSession::random(&mut rand::thread_rng());
        let responses = respond_all(&session.request(&header), &[&holders[0], &holders[1]]);
        assert!(session.open(&header, &responses).is_err());
    }

    #[test]
    fn duplicate_responses_do_not_count_twice() {
        let holders = holders(3);
        let (header, _) = seal(&recipients(&holders, 2), &mut rand::thread_rng()).unwrap();
        let session = RestoreSession::random(&mut rand::thread_rng());
        let responses = respond_all(&session.request(&header), &[&holders[0], &holders[0]]);
        assert!(session.open(&header, &responses).is_err());
    }

    #[test]
    fn response_for_another_session_is_rejected() {
        let holders = holders(3);
        let (header, _) = seal(&recipients(&holders, 2), &mut rand::thread_rng()).unwrap();
        let session = RestoreSession::random(&mut rand::thread_rng());
        let other = RestoreSession::random(&mut rand::thread_rng());
        let responses = respond_all(&other.request(&header), &[&holders[0], &holders[1]]);
        let err = session.open(&header, &responses).unwrap_err();
        assert!(err.to_string().contains("restore session"), "{err:#}");
    }

    #[test]
    fn response_for_another_backup_is_rejected() {
        let holders = holders(3);
        let r = recipients(&holders, 2);
        let (header, _) = seal(&r, &mut rand::thread_rng()).unwrap();
        let (other_header, _) = seal(&r, &mut rand::thread_rng()).unwrap();
        let session = RestoreSession::random(&mut rand::thread_rng());
        let responses = respond_all(&session.request(&other_header), &[&holders[0], &holders[1]]);
        let err = session.open(&header, &responses).unwrap_err();
        assert!(err.to_string().contains("different backup"), "{err:#}");
    }

    #[test]
    fn holder_rejects_a_share_that_does_not_match_its_commitment() {
        let holders = holders(3);
        let (mut header, _) = seal(&recipients(&holders, 2), &mut rand::thread_rng()).unwrap();
        // A holder whose share no longer matches the header's commitment must
        // refuse to send it.
        let c0 = header.shares[0].commitment.clone();
        header.shares[0].commitment = header.shares[1].commitment.clone();
        header.shares[1].commitment = c0;
        let session = RestoreSession::random(&mut rand::thread_rng());
        let request = session.request(&header);
        let err = request
            .respond(
                &holders[0].fingerprint(),
                |c| holders[0].decrypt(c),
                &mut rand::thread_rng(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("commitment"), "{err:#}");
    }

    #[test]
    fn tampered_secret_commitment_is_detected() {
        let holders = holders(3);
        let (mut header, _) = seal(&recipients(&holders, 2), &mut rand::thread_rng()).unwrap();
        header.secret_commitment = header.shares[0].commitment.clone();
        let session = RestoreSession::random(&mut rand::thread_rng());
        let responses = respond_all(&session.request(&header), &[&holders[0], &holders[1]]);
        let err = session.open(&header, &responses).unwrap_err();
        assert!(err.to_string().contains("secret commitment"), "{err:#}");
    }

    #[test]
    fn session_key_round_trips() {
        let session = RestoreSession::random(&mut rand::thread_rng());
        let restored = RestoreSession::from_secret_key_bytes(&session.secret_key_bytes()).unwrap();
        assert_eq!(
            restored.public_key.to_bytes(),
            session.public_key.to_bytes()
        );
    }

    #[test]
    fn roster_validation() {
        let holders = holders(3);
        let certs: Vec<_> = holders.iter().map(|h| h.cert.clone()).collect();
        assert!(ThresholdRecipients::new(1, certs.clone()).is_err());
        assert!(ThresholdRecipients::new(4, certs.clone()).is_err());
        assert!(ThresholdRecipients::new(2, certs.clone()).is_ok());
        let mut duplicated = certs.clone();
        duplicated.push(certs[0].clone());
        assert!(ThresholdRecipients::new(2, duplicated).is_err());
    }

    #[test]
    fn single_cert_archives_are_not_threshold_archives() {
        assert!(!is_threshold_archive(b"-----BEGIN PGP MESSAGE-----\n"));
    }

    #[test]
    fn wrong_passphrase_does_not_decrypt() {
        let mut file = Vec::new();
        {
            let mut writer = armored_password_encrypt_writer(&mut file, "right").unwrap();
            writer.write_all(b"secret").unwrap();
            writer.finalize().unwrap();
        }
        let result = decrypt_with_password(std::io::Cursor::new(file), "wrong")
            .and_then(|mut r| Ok(std::io::copy(&mut r, &mut std::io::sink())?));
        assert!(result.is_err());
    }
}
