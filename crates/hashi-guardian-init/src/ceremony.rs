// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony commands.
//!
//! `ceremony run` drives a fresh ceremony-mode guardian through genesis BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) → [`SetupNewKey`] → inspect each
//! returned encrypted share to confirm it is addressed to the expected KP cert
//! (without decrypting) → cross-check the guardian's `ceremony/` audit log and
//! `shares/` recovery log.
//!
//! [`OperatorInit`]: hashi_types::guardian::OperatorInitRequest
//! [`SetupNewKey`]: hashi_types::guardian::SetupNewKeyRequest
//! [`SetupNewKeyResponse`]: hashi_types::guardian::SetupNewKeyResponse

use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::KPEncryptedShares;
use hashi_types::guardian::KPFingerprint;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::Share;
use hashi_types::guardian::SharesLogMessage;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::cert_owns_key_handle;
use hashi_types::pgp::decrypt_with_gpg;
use hashi_types::pgp::pgp_message_recipients;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use serde::Deserialize;
use tempfile::NamedTempFile;
use tracing::info;

#[derive(Deserialize)]
pub struct CeremonyCommonConfig {
    /// Total number of shares. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// S3 config for the guardian's log bucket (object-lock enabled).
    pub guardian_s3: S3Config,
    /// Paths to each KP's armored OpenPGP public cert. Order matters: the cert
    /// at index `i` (0-based) is assigned share id `i + 1`.
    pub kp_pgp_cert_paths: Vec<PathBuf>,
}

impl CeremonyCommonConfig {
    fn validate(&self) -> Result<()> {
        SecretSharingParams::new(self.num_shares, self.threshold)
            .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;

        let cert_count = self.kp_pgp_cert_paths.len();
        ensure!(
            self.num_shares == cert_count,
            "num_shares ({}) must equal the number of KP certs ({cert_count})",
            self.num_shares
        );

        Ok(())
    }
}

#[derive(Deserialize)]
pub struct CeremonyRunConfig {
    #[serde(flatten)]
    pub common: CeremonyCommonConfig,
    /// gRPC endpoint of the ceremony-mode guardian.
    pub guardian_endpoint: String,
}

impl CeremonyRunConfig {
    pub fn load_yaml(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read ceremony-run config at {}", path.display()))?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse ceremony-run yaml at {}", path.display()))
    }
}

#[derive(Deserialize)]
pub struct CeremonyVerifyConfig {
    #[serde(flatten)]
    pub common: CeremonyCommonConfig,
    /// Path to this KP's armored OpenPGP public cert (the one they exported and
    /// gave to the operator at `run` time). Used to derive the fingerprint that
    /// finds this KP's share in `shares/`, and to confirm the share's ciphertext
    /// is genuinely encrypted to this cert before decrypting.
    pub kp_pgp_cert_path: PathBuf,
    /// Expected secret-sharing sequence. Use 0 for genesis setup, or N+1 for a
    /// rotation from prior sequence N.
    pub sharing_seq: u64,
    /// Optional gpg homedir for the yubikey-backed agent. Defaults to gpg's
    /// default (`~/.gnupg`) when unset.
    pub gpg_homedir: Option<PathBuf>,
}

impl CeremonyVerifyConfig {
    pub fn load_yaml(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| {
            format!(
                "failed to read ceremony-verify config at {}",
                path.display()
            )
        })?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse ceremony-verify yaml at {}", path.display()))
    }
}

/// Run the one-time production guardian key ceremony.
///
/// See the module docs for the full step-by-step flow. Each step is logged via
/// `tracing` so the operator can follow exactly what is happening.
pub async fn run(cfg: CeremonyRunConfig) -> Result<()> {
    info!(
        num_shares = cfg.common.num_shares,
        threshold = cfg.common.threshold,
        cert_count = cfg.common.kp_pgp_cert_paths.len(),
        "running guardian key ceremony"
    );

    // 1. Validate config-level sharing params up front (also re-validated by
    //    SetupNewKeyRequest::new).
    cfg.common.validate()?;

    // 2. Load + validate each KP's PGP cert.
    let certs = load_kp_certs(&cfg.common.kp_pgp_cert_paths)?;
    let setup_req =
        SetupNewKeyRequest::new(certs.clone(), cfg.common.num_shares, cfg.common.threshold)
            .map_err(|e| anyhow!("build SetupNewKeyRequest: {e:?}"))?;

    // 3. Connect to the ceremony-mode guardian.
    info!(endpoint = %cfg.guardian_endpoint, "connecting to guardian");
    let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", cfg.guardian_endpoint))?;
    info!("connected to guardian");

    // 4. operator_init (ceremony mode: S3 config only, no WithdrawModeConfig).
    info!(
        bucket = cfg.common.guardian_s3.bucket_name(),
        region = cfg.common.guardian_s3.region(),
        "calling OperatorInit (ceremony mode)"
    );
    let oi_req = operator_init_request_to_pb(OperatorInitRequest::new_ceremony_mode(
        cfg.common.guardian_s3.clone(),
    ))
    .map_err(|e| anyhow!("encode OperatorInitRequest: {e:?}"))?;
    client
        .operator_init(oi_req)
        .await
        .context("OperatorInit RPC failed")?;
    info!("operator_init complete; guardian S3 logger installed");

    // 5. get_guardian_info → verify the enclave's self-signature on its info →
    //    pin the session id. This binds `signing_pub_key` (and thus the session)
    //    before we trust the SetupNewKey response we'll verify against it below.
    //
    //    NOTE: like dev_bootstrap, this authenticates the guardian's *internal*
    //    consistency, not the enclave's hardware attestation — TODO(check C)
    //    makes verify_enclave_attestation a no-op today.
    info!("calling GetGuardianInfo");
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    let signing_pub_key = info_resp.signing_pub_key;
    let session_id = session_id_from_signing_pubkey(&signing_pub_key);
    info_resp
        .signed_info
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify GuardianInfo signature (session={session_id}): {e:?}"))?;
    info!(session_id = %session_id, "guardian info signature verified; session pinned");

    let mut reader = GuardianReader::new(&cfg.common.guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let attested_signing_pub_key = reader.verified_pubkey(&session_id).await?;
    ensure!(
        attested_signing_pub_key == signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    info!(session_id = %session_id, "guardian S3 attestation matches gRPC signing key");

    // 6. setup_new_key.
    info!(
        n = cfg.common.num_shares,
        t = cfg.common.threshold,
        "calling SetupNewKey"
    );
    let signed_resp_pb = client
        .setup_new_key(setup_new_key_request_to_pb(setup_req))
        .await
        .context("SetupNewKey RPC failed")?
        .into_inner();
    let signed_resp = GuardianSigned::<SetupNewKeyResponse>::try_from(signed_resp_pb)
        .map_err(|e| anyhow!("decode SignedSetupNewKeyResponse: {e:?}"))?;
    info!(
        n = cfg.common.num_shares,
        t = cfg.common.threshold,
        encrypted_share_count = signed_resp.data.encrypted_shares.len(),
        "setup_new_key response received"
    );

    // 7. Verify the response signature under the pinned session's signing key,
    //    and sanity-check the response shape.
    let sharing_seq = 0u64;
    let live = signed_resp
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e:?}"))
        .and_then(|response| {
            VerifiedCeremonyState::from_response(
                response,
                session_id.clone(),
                sharing_seq,
                cfg.common.num_shares,
                cfg.common.threshold,
            )
        })?;

    // 8. Inspect each encrypted share's PGP recipients WITHOUT decrypting, and
    //    confirm every share is addressed only to its expected cert.
    live.verify_encrypted_share_recipients(&certs)?;

    // 9. Cross-check the latest guardian ceremony/ and shares/ logs.
    //    KPs will fetch the same shares/ object during ceremony verify.
    let logged = VerifiedCeremonyState::latest_from_s3(
        &mut reader,
        sharing_seq,
        cfg.common.num_shares,
        cfg.common.threshold,
    )
    .await?;
    ensure!(
        logged == live,
        "ceremony/ and shares/ logs differ from the SetupNewKeyResponse"
    );
    info!("ceremony/ and shares/ logs match the SetupNewKeyResponse");

    // 10. Summary.
    live.print_summary();

    Ok(())
}

/// Verify this KP can fetch and decrypt its ceremony share.
///
/// Trust is anchored entirely to the guardian's S3 attestation log (unlike
/// `run`, which talks to the live guardian over gRPC): the `GuardianReader`
/// resolves the session's attested signing pubkey once (cached), and both the
/// `ceremony/` audit entry and `shares/` recovery entry are verified under it.
/// Each step is logged.
///
/// Security: only the share's **ciphertext** is written to disk (a `NamedTempFile`
/// that is deleted on drop); the decrypted 32-byte scalar lives only in the
/// in-memory `Scalar`. `gpg --decrypt` streams its plaintext over a pipe — it is
/// never given an `--output` path.
pub async fn verify(cfg: CeremonyVerifyConfig) -> Result<()> {
    cfg.common.validate()?;

    let certs = load_kp_certs(&cfg.common.kp_pgp_cert_paths)?;

    // Load this KP's cert. Its fingerprint finds our share in `shares/`, and
    // the cert itself lets us confirm the ciphertext is genuinely encrypted to
    // us before we touch the yubikey.
    let cert_armored = std::fs::read_to_string(&cfg.kp_pgp_cert_path)
        .with_context(|| format!("read KP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let kp_cert = PgpPublicCert::new(cert_armored)
        .with_context(|| format!("invalid PGP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let want_fp = kp_cert.fingerprint();
    info!(fingerprint = %want_fp, "verifying ceremony share");

    // 1. Discover and verify the latest ceremony from the immutable log
    //    (attestation-verified once via the reader's session-key cache).
    let sharing_seq = cfg.sharing_seq;
    let mut reader = GuardianReader::new(&cfg.common.guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let state = VerifiedCeremonyState::latest_from_s3(
        &mut reader,
        sharing_seq,
        cfg.common.num_shares,
        cfg.common.threshold,
    )
    .await?;
    info!(
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        session_id = %state.session_id,
        "discovered latest ceremony session"
    );

    // 2. Confirm every share is addressed only to its labeled KP cert.
    state.verify_encrypted_share_recipients(&certs)?;
    info!("ceremony/ and shares/ logs verified against expected params and KP certs");

    // 3. Find this KP's share by exact fingerprint match (both sides derive
    //    from PgpPublicCert::fingerprint over the same key, so they're
    //    canonical and identical — no normalization needed). The matched share
    //    carries its own crypto `id`.
    let share = state
        .encrypted_shares
        .iter()
        .find(|s| s.recipient_fingerprint == want_fp)
        .ok_or_else(|| {
            anyhow!(
                "no share in the shares/ log is labeled for this KP's fingerprint \
                 {want_fp} (labeled fingerprints: {:?})",
                state
                    .encrypted_shares
                    .iter()
                    .map(|s| s.recipient_fingerprint.clone())
                    .collect::<Vec<_>>()
            )
        })?;
    info!(
        share_id = share.id.get(),
        fingerprint = %share.recipient_fingerprint,
        "found this KP's encrypted share"
    );

    let share_id = share.id;

    // 4. Decrypt the share with the yubikey via gpg. Only the CIPHERTEXT is
    //    written to the temp file; the decrypted bytes stream over gpg's stdout
    //    pipe into memory and never touch disk.
    let mut ciphertext_file = NamedTempFile::new().context("create temp file for ciphertext")?;
    ciphertext_file
        .write_all(share.armored_ciphertext.as_bytes())
        .context("write ciphertext to temp file")?;
    let mut decryptor = decrypt_with_gpg(ciphertext_file.path(), cfg.gpg_homedir.as_deref())?;
    let mut plaintext = Vec::with_capacity(32);
    decryptor
        .read_to_end(&mut plaintext)
        .context("read decrypted share from gpg")?;
    // `ciphertext_file` drops here, unlinking the ciphertext temp file.
    drop(ciphertext_file);

    let scalar_bytes: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("decrypted share is {} bytes, expected 32", plaintext.len()))?;
    let scalar = Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(scalar_bytes)))
        .ok_or_else(|| anyhow!("decrypted share is not a valid secp256k1 scalar"))?;
    info!("decrypted share via yubikey (plaintext stayed in memory)");

    // 5. Verify the decrypted share's commitment is in the set — proves the
    //    bytes we decrypted are a valid share of the guardian's BTC key.
    let reconstructed = Share {
        id: share_id,
        value: scalar,
    };
    state
        .secret_sharing_instance
        .commitments()
        .verify_share(&reconstructed)
        .map_err(|e| anyhow!("decrypted share does not match its commitment: {e:?}"))?;
    info!(
        share_id = share_id.get(),
        "decrypted share matches its commitment"
    );

    // 6. Summary.
    let expected_commitment = state
        .secret_sharing_instance
        .commitments()
        .iter()
        .find(|c| c.id == share_id)
        .expect("share verified above so its commitment exists");
    println!("Ceremony share verified.");
    println!("  session_id:    {}", state.session_id);
    println!("  share_id:      {}", share_id.get());
    println!(
        "  sharing_seq:   {}",
        state.secret_sharing_instance.sharing_seq()
    );
    println!("  fingerprint:   {want_fp}");
    println!(
        "  commitment:    {}",
        hex::encode(&expected_commitment.digest)
    );
    Ok(())
}

/// Load and validate each KP's armored OpenPGP cert, logging the fingerprint +
/// assigned share id for each. Returns the certs in config order.
fn load_kp_certs(paths: &[PathBuf]) -> Result<Vec<PgpPublicCert>> {
    let mut certs = Vec::with_capacity(paths.len());
    for path in paths {
        let armored = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read KP cert at {}", path.display()))?;
        let cert = PgpPublicCert::new(armored)
            .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
        info!(fingerprint = %cert, path = %path.display(), "loaded KP cert");
        certs.push(cert);
    }
    Ok(certs)
}

/// Validated ceremony state. It may come from the live `SetupNewKeyResponse` or
/// be reconstructed from the guardian's `ceremony/` + `shares/` logs.
#[derive(Debug, PartialEq)]
struct VerifiedCeremonyState {
    session_id: String,
    encrypted_shares: KPEncryptedShares,
    secret_sharing_instance: SecretSharingInstance,
}

impl VerifiedCeremonyState {
    fn from_response(
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

    async fn latest_from_s3(
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
        let state = Self {
            session_id,
            encrypted_shares,
            secret_sharing_instance: instance,
        };

        state.validate(expected_sharing_seq, expected_n, expected_t)?;
        state.ensure_roster_matches(&roster)?;
        Ok(state)
    }

    /// Confirm the state uses the expected ceremony instance and carries
    /// exactly `expected_n` encrypted shares.
    fn validate(
        &self,
        expected_sharing_seq: u64,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<()> {
        ensure!(
            self.secret_sharing_instance.sharing_seq() == expected_sharing_seq,
            "ceremony sharing_seq ({}) differs from expected ({expected_sharing_seq})",
            self.secret_sharing_instance.sharing_seq()
        );
        ensure!(
            self.secret_sharing_instance.num_shares() == expected_n,
            "ceremony num_shares ({}) differs from expected ({expected_n})",
            self.secret_sharing_instance.num_shares()
        );
        ensure!(
            self.secret_sharing_instance.threshold() == expected_t,
            "ceremony threshold ({}) differs from expected ({expected_t})",
            self.secret_sharing_instance.threshold()
        );
        ensure!(
            self.encrypted_shares.len() == expected_n,
            "expected {expected_n} encrypted shares, got {}",
            self.encrypted_shares.len()
        );
        info!("ceremony state verified: {expected_n} shares, sharing_seq {expected_sharing_seq}");
        Ok(())
    }

    /// Confirm the agreed `ceremony/` roster matches the recipient fingerprints
    /// on the `shares/` ciphertexts.
    fn ensure_roster_matches(&self, roster: &[KPFingerprint]) -> Result<()> {
        let got = self.encrypted_shares.recipient_roster();
        ensure!(
            roster == got.as_slice(),
            "ceremony/ roster differs from shares/ recipient fingerprints"
        );
        Ok(())
    }

    /// For each encrypted share, confirm (a) its `recipient_fingerprint` label
    /// names exactly one of the operator-supplied certs, and (b) the ciphertext is
    /// actually encrypted only to that cert (parsed via PKESK without decrypting).
    ///
    /// Identity is by fingerprint, not positional index — a share is matched to its
    /// cert by `recipient_fingerprint`, independent of ordering.
    fn verify_encrypted_share_recipients(&self, certs: &[PgpPublicCert]) -> Result<()> {
        let by_fingerprint: std::collections::HashMap<KPFingerprint, &PgpPublicCert> =
            certs.iter().map(|c| (c.fingerprint(), c)).collect();
        ensure!(
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
        ensure!(
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
            ensure!(
                !recipients.is_empty(),
                "share id {} has no PGP recipients",
                share.id.get()
            );
            for handle in &recipients {
                ensure!(
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

    fn print_summary(&self) {
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
    fn kp_encrypted_shares_rejects_wrong_share_ids() {
        let err = KPEncryptedShares::new(vec![share(1), share(2), share(4)]).unwrap_err();
        assert!(format!("{err}").contains("share ids"), "{err}");
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
}
