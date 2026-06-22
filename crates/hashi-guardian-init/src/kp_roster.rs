// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared KP-roster config + ceremony-state verification, used by both the
//! `ceremony verify` and `provision` commands.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::KPEncryptedShares;
use hashi_types::guardian::KPFingerprint;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::SharesLogMessage;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::cert_owns_key_handle;
use hashi_types::pgp::pgp_message_recipients;
use serde::Deserialize;
use tracing::info;

/// Common KP-roster config: the sharing params, the guardian's S3 log bucket,
/// the full KP cert roster, and the expected enclave measurement.
#[derive(Deserialize)]
pub struct KpRosterConfig {
    /// Total number of shares. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// S3 config for the guardian's log bucket (object-lock enabled).
    pub guardian_s3: S3Config,
    /// Paths to each KP's armored OpenPGP public cert. Order matters for
    /// `ceremony run` (the cert at index `i` is assigned share id `i + 1`); for
    /// read-only commands, shares are matched by fingerprint so order is
    /// irrelevant.
    pub kp_pgp_cert_paths: Vec<PathBuf>,
    /// Expected enclave-image measurement: PCR0 as hex, pinned against every
    /// session's attestation. Required even in non-Nitro dev, where the
    /// attestation verifier is stubbed.
    pub expected_pcr0: BuildPcrs,
}

impl KpRosterConfig {
    pub fn validate(&self) -> Result<()> {
        SecretSharingParams::new(self.num_shares, self.threshold)
            .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;

        let cert_count = self.kp_pgp_cert_paths.len();
        anyhow::ensure!(
            self.num_shares == cert_count,
            "num_shares ({}) must equal the number of KP certs ({cert_count})",
            self.num_shares
        );

        Ok(())
    }
}

/// Validated ceremony state. It may come from the live `SetupNewKeyResponse` or
/// be reconstructed from the guardian's `ceremony/` + `shares/` logs.
#[derive(Debug, PartialEq)]
pub struct VerifiedCeremonyState {
    pub session_id: String,
    pub encrypted_shares: KPEncryptedShares,
    pub secret_sharing_instance: SecretSharingInstance,
}

impl VerifiedCeremonyState {
    pub fn from_response(
        response: SetupNewKeyResponse,
        session_id: String,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        let state = Self {
            session_id,
            encrypted_shares: response.encrypted_shares,
            secret_sharing_instance: response.secret_sharing_instance,
        };
        state.validate(expected_sharing_seq, expected_n, expected_t)?;
        Ok(state)
    }

    pub async fn latest_from_s3(
        reader: &mut GuardianReader,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        let (session_id, instance, roster) = reader
            .read_latest_ceremony()
            .await?
            .ok_or_else(|| anyhow!("no ceremony logs found in guardian S3 bucket"))?;
        let encrypted_shares = reader
            .read_shares(&session_id, instance.sharing_seq())
            .await?;
        Self::from_scraped(
            session_id,
            instance,
            encrypted_shares,
            &roster,
            expected_sharing_seq,
            expected_n,
            expected_t,
        )
    }

    pub fn from_scraped(
        session_id: String,
        secret_sharing_instance: SecretSharingInstance,
        encrypted_shares: KPEncryptedShares,
        roster: &[KPFingerprint],
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<Self> {
        let state = Self {
            session_id,
            encrypted_shares,
            secret_sharing_instance,
        };
        state.validate(expected_sharing_seq, expected_n, expected_t)?;
        state.ensure_roster_matches(roster)?;
        Ok(state)
    }

    /// Confirm the state uses the expected ceremony instance and carries
    /// exactly `expected_n` encrypted shares.
    pub fn validate(
        &self,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<()> {
        anyhow::ensure!(
            self.secret_sharing_instance.sharing_seq() == expected_sharing_seq,
            "ceremony sharing_seq ({}) differs from expected ({expected_sharing_seq})",
            self.secret_sharing_instance.sharing_seq()
        );
        anyhow::ensure!(
            self.secret_sharing_instance.num_shares() == expected_n,
            "ceremony num_shares ({}) differs from expected ({expected_n})",
            self.secret_sharing_instance.num_shares()
        );
        anyhow::ensure!(
            self.secret_sharing_instance.threshold() == expected_t,
            "ceremony threshold ({}) differs from expected ({expected_t})",
            self.secret_sharing_instance.threshold()
        );
        anyhow::ensure!(
            self.encrypted_shares.len() == expected_n,
            "expected {expected_n} encrypted shares, got {}",
            self.encrypted_shares.len()
        );
        info!("ceremony state verified: {expected_n} shares, sharing_seq {expected_sharing_seq}");
        Ok(())
    }

    /// Confirm the agreed `ceremony/` roster matches the recipient fingerprints
    /// on the `shares/` ciphertexts.
    pub fn ensure_roster_matches(&self, roster: &[KPFingerprint]) -> Result<()> {
        let got = self.encrypted_shares.recipient_roster();
        anyhow::ensure!(
            roster == got.as_slice(),
            "ceremony/ roster differs from shares/ recipient fingerprints"
        );
        Ok(())
    }

    /// For each encrypted share, confirm (a) its `recipient_fingerprint` label
    /// names exactly one of the operator-supplied certs, and (b) the ciphertext is
    /// actually encrypted only to that cert (parsed via PKESK without decrypting).
    ///
    /// Identity is by fingerprint, not positional index: a share is matched to its
    /// cert by `recipient_fingerprint`, independent of ordering.
    pub fn verify_encrypted_share_recipients(&self, certs: &[PgpPublicCert]) -> Result<()> {
        let by_fingerprint: std::collections::HashMap<KPFingerprint, &PgpPublicCert> =
            certs.iter().map(|c| (c.fingerprint(), c)).collect();
        anyhow::ensure!(
            by_fingerprint.len() == certs.len(),
            "duplicate fingerprints among the supplied KP certs"
        );

        let mut expected_fingerprints: Vec<KPFingerprint> =
            by_fingerprint.keys().cloned().collect();
        expected_fingerprints.sort_unstable();
        let mut labeled_fingerprints: Vec<KPFingerprint> = self
            .encrypted_shares
            .iter()
            .map(|s| s.recipient_fingerprint.clone())
            .collect();
        labeled_fingerprints.sort_unstable();
        anyhow::ensure!(
            labeled_fingerprints == expected_fingerprints,
            "encrypted share recipient roster differs from expected KP certs: expected \
             {expected_fingerprints:?}, got {labeled_fingerprints:?}"
        );

        for share in self.encrypted_shares.iter() {
            let expected_cert = by_fingerprint
                .get(&share.recipient_fingerprint)
                .with_context(|| {
                    format!(
                        "share id {} is labeled for fingerprint {}, which is not among the \
                             operator-supplied KP certs",
                        share.id.get(),
                        share.recipient_fingerprint
                    )
                })?;
            let recipients = pgp_message_recipients(&share.armored_ciphertext)
                .with_context(|| format!("parse PGP recipients for share id {}", share.id.get()))?;
            anyhow::ensure!(
                !recipients.is_empty(),
                "share id {} has no PGP recipients",
                share.id.get()
            );
            for handle in &recipients {
                anyhow::ensure!(
                    cert_owns_key_handle(expected_cert, handle),
                    "share id {} (labeled {}) is encrypted to key {handle}, which is not in \
                     that cert",
                    share.id.get(),
                    share.recipient_fingerprint
                );
            }
            info!(
                share_id = share.id.get(),
                fingerprint = %share.recipient_fingerprint,
                recipient_count = recipients.len(),
                "verified share is encrypted only to its labeled cert"
            );
        }
        info!(
            "all {} shares encrypted to their labeled certs",
            self.encrypted_shares.len()
        );
        Ok(())
    }

    pub fn print_summary(&self) {
        println!("Guardian key ceremony complete.");
        println!("  session_id:        {}", self.session_id);
        println!(
            "  sharing_seq:       {}",
            self.secret_sharing_instance.sharing_seq()
        );
        println!(
            "  shares key:        {}",
            SharesLogMessage::object_key(
                &self.session_id,
                self.secret_sharing_instance.sharing_seq()
            )
        );
        println!("  share commitments:");
        for commitment in self.secret_sharing_instance.commitments().iter() {
            println!(
                "    id {:<5} {}",
                commitment.id.get(),
                hex::encode(&commitment.digest)
            );
        }
    }
}

/// Confirm this KP's own cert is one of the operator-supplied roster certs.
/// Catches a typo'd `kp_pgp_cert_path` before any S3 or yubikey work.
pub fn ensure_cert_in_roster(kp_cert: &PgpPublicCert, certs: &[PgpPublicCert]) -> Result<()> {
    let want_fp = kp_cert.fingerprint();
    anyhow::ensure!(
        certs.iter().any(|c| c.fingerprint() == want_fp),
        "this KP's cert (fingerprint {want_fp}) is not among the configured kp_pgp_cert_paths"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::KPEncryptedShare;
    use hashi_types::guardian::ShareCommitment;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::pgp::encrypt_armored;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use std::num::NonZeroU16;

    fn share(id: u16) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint: format!("DUMMY FINGERPRINT {id}"),
            armored_ciphertext: "dummy".into(),
        }
    }

    fn commitments(ids: &[u16]) -> ShareCommitments {
        let vec: Vec<ShareCommitment> = ids
            .iter()
            .map(|&i| ShareCommitment {
                id: NonZeroU16::new(i).unwrap(),
                digest: vec![i as u8],
            })
            .collect();
        ShareCommitments::new(vec).unwrap()
    }

    fn response(shares: &[u16], commitment_ids: &[u16]) -> SetupNewKeyResponse {
        response_with_instance(
            shares,
            SecretSharingInstance::new(commitments(commitment_ids), commitment_ids.len(), 2, 0)
                .unwrap(),
        )
    }

    fn response_with_instance(
        shares: &[u16],
        secret_sharing_instance: SecretSharingInstance,
    ) -> SetupNewKeyResponse {
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedShares::new(shares.iter().map(|&i| share(i)).collect())
                .unwrap(),
            secret_sharing_instance,
        }
    }

    fn mock_cert() -> PgpPublicCert {
        let (public, _secret) = mock_pgp_keypair();
        PgpPublicCert::new(public).unwrap()
    }

    fn encrypted_share(id: u16, cert: &PgpPublicCert) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
            recipient_fingerprint: cert.fingerprint(),
            armored_ciphertext: encrypt_armored(&[id as u8; 32], cert).unwrap(),
        }
    }

    fn encrypted_response(certs_by_share: &[&PgpPublicCert]) -> SetupNewKeyResponse {
        let n = certs_by_share.len();
        SetupNewKeyResponse {
            encrypted_shares: KPEncryptedShares::new(
                certs_by_share
                    .iter()
                    .enumerate()
                    .map(|(i, cert)| encrypted_share((i + 1) as u16, cert))
                    .collect(),
            )
            .unwrap(),
            secret_sharing_instance: SecretSharingInstance::new(
                commitments(&(1..=n as u16).collect::<Vec<_>>()),
                n,
                2,
                0,
            )
            .unwrap(),
        }
    }

    #[test]
    fn verified_ceremony_state_accepts_well_formed() {
        let resp = response(&[1, 2, 3], &[1, 2, 3]);
        VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("well-formed response should pass");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_share_count() {
        let resp = response(&[1, 2], &[1, 2, 3]);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("encrypted shares"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_num_shares() {
        let resp = response(&[1, 2], &[1, 2]);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("num_shares"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_threshold() {
        let instance = SecretSharingInstance::new(commitments(&[1, 2, 3]), 3, 3, 0).unwrap();
        let resp = response_with_instance(&[1, 2, 3], instance);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("threshold"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_rejects_wrong_instance_sharing_seq() {
        let instance = SecretSharingInstance::new(commitments(&[1, 2, 3]), 3, 2, 1).unwrap();
        let resp = response_with_instance(&[1, 2, 3], instance);
        let err =
            VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2).unwrap_err();
        assert!(format!("{err}").contains("sharing_seq"), "{err}");
    }

    #[test]
    fn verified_ceremony_state_matches_roster_by_share_id() {
        let resp = response(&[3, 1, 2], &[1, 2, 3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");
        let roster = vec![
            "DUMMY FINGERPRINT 1".to_string(),
            "DUMMY FINGERPRINT 2".to_string(),
            "DUMMY FINGERPRINT 3".to_string(),
        ];
        state
            .ensure_roster_matches(&roster)
            .expect("roster is ordered by share id");

        let wrong_roster = vec![
            "DUMMY FINGERPRINT 3".to_string(),
            "DUMMY FINGERPRINT 2".to_string(),
            "DUMMY FINGERPRINT 1".to_string(),
        ];
        let err = state.ensure_roster_matches(&wrong_roster).unwrap_err();
        assert!(format!("{err}").contains("roster differs"), "{err}");
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_reordered_expected_certs() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        state
            .verify_encrypted_share_recipients(&[cert3, cert1, cert2])
            .expect("recipient validation should be by fingerprint, not config order");
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_duplicate_share_labels() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert1, &cert3]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        let err = state
            .verify_encrypted_share_recipients(&[cert1, cert2, cert3])
            .unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
            "{err}"
        );
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_omitted_expected_cert() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let unexpected = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &unexpected]);
        let state = VerifiedCeremonyState::from_response(resp, "session".into(), 0, 3, 2)
            .expect("valid state");

        let err = state
            .verify_encrypted_share_recipients(&[cert1, cert2, cert3])
            .unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
            "{err}"
        );
    }

    #[test]
    fn ensure_cert_in_roster_accepts_member() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let roster = [cert1, cert2, cert3.clone()];
        ensure_cert_in_roster(&cert3, &roster).expect("cert is in the roster");
    }

    #[test]
    fn ensure_cert_in_roster_rejects_non_member() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let outsider = mock_cert();
        let roster = [cert1, cert2];
        let err = ensure_cert_in_roster(&outsider, &roster).unwrap_err();
        assert!(
            format!("{err}").contains("not among the configured"),
            "{err}"
        );
    }
}
