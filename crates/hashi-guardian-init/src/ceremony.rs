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
use anyhow::bail;
use anyhow::ensure;
use hashi_guardian::s3_client::GuardianS3Client;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::KPEncryptedShare;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::S3_DIR_CEREMONY;
use hashi_types::guardian::S3_DIR_SHARES;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SecretSharingInstance;
use hashi_types::guardian::SecretSharingParams;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::Share;
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
    validate_sharing_config(
        cfg.common.num_shares,
        cfg.common.threshold,
        cfg.common.kp_pgp_cert_paths.len(),
    )?;

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

    let guardian_client = GuardianS3Client::new_checked(&cfg.common.guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let attested_signing_pub_key = guardian_client
        .get_verified_enclave_pubkey(&session_id)
        .await?;
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
    let response = signed_resp
        .clone()
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e:?}"))?;
    verify_response_shape(&response, cfg.common.num_shares)?;

    // 8. Inspect each encrypted share's PGP recipients WITHOUT decrypting, and
    //    confirm every share is addressed only to its expected cert.
    verify_encrypted_share_recipients(&response, &certs)?;

    // 9. Cross-check the guardian's ceremony/ and shares/ logs by exact key.
    //    KPs will fetch the same shares/ object during ceremony verify.
    let sharing_seq = 0u64;
    let logged = read_verified_ceremony_state(
        &guardian_client,
        &session_id,
        sharing_seq,
        &signing_pub_key,
        cfg.common.num_shares,
        cfg.common.threshold,
    )
    .await?;
    ensure!(
        logged.response.share_commitments == response.share_commitments,
        "ceremony/ log commitments differ from the SetupNewKeyResponse commitments"
    );
    ensure!(
        logged.response.encrypted_shares == response.encrypted_shares,
        "shares/ log encrypted shares differ from the SetupNewKeyResponse shares"
    );
    info!("ceremony/ and shares/ logs match the SetupNewKeyResponse");

    // 10. Summary.
    print_summary(&session_id, sharing_seq, &response);

    Ok(())
}

/// Verify this KP can fetch and decrypt its ceremony share.
///
/// Trust is anchored entirely to the guardian's S3 attestation log (unlike
/// `run`, which talks to the live guardian over gRPC): the signing pubkey is
/// loaded via `get_verified_enclave_pubkey`, and both the `ceremony/` audit
/// entry and `shares/` recovery entry are verified under it. Each step is logged.
///
/// Security: only the share's **ciphertext** is written to disk (a `NamedTempFile`
/// that is deleted on drop); the decrypted 32-byte scalar lives only in the
/// in-memory `Scalar`. `gpg --decrypt` streams its plaintext over a pipe — it is
/// never given an `--output` path.
pub async fn verify(cfg: CeremonyVerifyConfig) -> Result<()> {
    validate_sharing_config(
        cfg.common.num_shares,
        cfg.common.threshold,
        cfg.common.kp_pgp_cert_paths.len(),
    )?;

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

    // 1. Discover the latest ceremony session and ensure it is the sequence the
    //    KP intended to verify.
    let sharing_seq = cfg.sharing_seq;
    let mut reader = GuardianReader::new(&cfg.common.guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let (session_id, latest_instance) = reader
        .read_latest_ceremony()
        .await?
        .ok_or_else(|| anyhow!("no ceremony logs found in guardian S3 bucket"))?;
    ensure!(
        latest_instance.sharing_seq() == sharing_seq,
        "latest ceremony sharing_seq ({}) differs from expected ({sharing_seq})",
        latest_instance.sharing_seq()
    );
    info!(
        sharing_seq,
        session_id = %session_id,
        "discovered latest ceremony session"
    );

    // 2. Load the session's attested signing pubkey from the guardian log
    //    bucket (reads + verifies the attestation — TODO check C).
    let guardian_client = GuardianS3Client::new_checked(&cfg.common.guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let signing_pub_key = guardian_client
        .get_verified_enclave_pubkey(&session_id)
        .await?;
    info!(session_id = %session_id, "attestation-anchored signing pubkey loaded");

    // 3. Read and verify the guardian-authored ceremony/ instance and shares/.
    let state = read_verified_ceremony_state(
        &guardian_client,
        &session_id,
        sharing_seq,
        &signing_pub_key,
        cfg.common.num_shares,
        cfg.common.threshold,
    )
    .await?;
    verify_encrypted_share_recipients(&state.response, &certs)?;
    info!("ceremony/ and shares/ logs verified against expected params and KP certs");

    // 4. Find this KP's share by exact fingerprint match (both sides derive
    //    from PgpPublicCert::fingerprint over the same key, so they're
    //    canonical and identical — no normalization needed). The matched share
    //    carries its own crypto `id`.
    let share = state
        .response
        .encrypted_shares
        .iter()
        .find(|s| s.recipient_fingerprint == want_fp)
        .ok_or_else(|| {
            anyhow!(
                "no share in the shares/ log is labeled for this KP's fingerprint \
                 {want_fp} (labeled fingerprints: {:?})",
                state
                    .response
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

    // 5. Decrypt the share with the yubikey via gpg. Only the CIPHERTEXT is
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

    // 6. Verify the decrypted share's commitment is in the set — proves the
    //    bytes we decrypted are a valid share of the guardian's BTC key.
    let reconstructed = Share {
        id: share_id,
        value: scalar,
    };
    state
        .response
        .share_commitments
        .verify_share(&reconstructed)
        .map_err(|e| anyhow!("decrypted share does not match its commitment: {e:?}"))?;
    info!(
        share_id = share_id.get(),
        "decrypted share matches its commitment"
    );

    // 7. Summary.
    let expected_commitment = state
        .response
        .share_commitments
        .iter()
        .find(|c| c.id == share_id)
        .expect("share verified above so its commitment exists");
    println!("Ceremony share verified.");
    println!("  session_id:    {session_id}");
    println!("  share_id:      {}", share_id.get());
    println!("  sharing_seq:   {sharing_seq}");
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

fn validate_sharing_config(num_shares: usize, threshold: usize, cert_count: usize) -> Result<()> {
    SecretSharingParams::new(num_shares, threshold)
        .map_err(|e| anyhow!("invalid sharing params: {e:?}"))?;
    ensure!(
        num_shares == cert_count,
        "num_shares ({num_shares}) must equal the number of KP certs ({cert_count})"
    );
    Ok(())
}

/// Confirm the response carries exactly `n` encrypted shares and `n`
/// commitments, with both share ids and commitment ids exactly `1..=n`.
fn verify_response_shape(response: &SetupNewKeyResponse, n: usize) -> Result<()> {
    ensure!(
        response.encrypted_shares.len() == n,
        "expected {n} encrypted shares, got {}",
        response.encrypted_shares.len()
    );
    ensure!(
        response.share_commitments.len() == n,
        "expected {n} commitments, got {}",
        response.share_commitments.len()
    );
    let expected: Vec<u16> = (1..=n as u16).collect();

    let mut share_ids: Vec<u16> = response
        .encrypted_shares
        .iter()
        .map(|s| s.id.get())
        .collect();
    share_ids.sort_unstable();
    ensure!(
        share_ids == expected,
        "encrypted share ids are not exactly 1..={n}, got {share_ids:?}"
    );

    let mut commitment_ids: Vec<u16> = response
        .share_commitments
        .iter()
        .map(|c| c.id.get())
        .collect();
    commitment_ids.sort_unstable();
    ensure!(
        commitment_ids == expected,
        "commitment ids are not exactly 1..={n}, got {commitment_ids:?}"
    );

    info!("response shape verified: {n} shares, {n} commitments, ids 1..={n}");
    Ok(())
}

/// For each encrypted share, confirm (a) its `recipient_fingerprint` label
/// names exactly one of the operator-supplied certs, and (b) the ciphertext is
/// actually encrypted only to that cert (parsed via PKESK without decrypting).
///
/// Identity is by fingerprint, not positional index — a share is matched to its
/// cert by `recipient_fingerprint`, independent of ordering.
fn verify_encrypted_share_recipients(
    response: &SetupNewKeyResponse,
    certs: &[PgpPublicCert],
) -> Result<()> {
    let by_fingerprint: std::collections::HashMap<String, &PgpPublicCert> =
        certs.iter().map(|c| (c.fingerprint(), c)).collect();
    ensure!(
        by_fingerprint.len() == certs.len(),
        "duplicate fingerprints among the supplied KP certs"
    );

    let mut expected_fingerprints: Vec<String> = by_fingerprint.keys().cloned().collect();
    expected_fingerprints.sort_unstable();
    let mut labeled_fingerprints: Vec<String> = response
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

    for share in &response.encrypted_shares {
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
        response.encrypted_shares.len()
    );
    Ok(())
}

struct VerifiedCeremonyState {
    response: SetupNewKeyResponse,
}

async fn read_verified_ceremony_state(
    s3: &GuardianS3Client,
    session_id: &str,
    sharing_seq: u64,
    signing_pub_key: &GuardianPubKey,
    expected_n: usize,
    expected_t: usize,
) -> Result<VerifiedCeremonyState> {
    let (instance, roster) =
        read_session_ceremony(s3, session_id, sharing_seq, signing_pub_key).await?;
    ensure!(
        instance.num_shares() == expected_n,
        "ceremony/ log num_shares ({}) differs from expected ({})",
        instance.num_shares(),
        expected_n
    );
    ensure!(
        instance.threshold() == expected_t,
        "ceremony/ log threshold ({}) differs from expected ({})",
        instance.threshold(),
        expected_t
    );
    ensure!(
        instance.sharing_seq() == sharing_seq,
        "ceremony/ log sharing_seq ({}) differs from expected ({})",
        instance.sharing_seq(),
        sharing_seq
    );

    let encrypted_shares =
        read_session_shares(s3, session_id, sharing_seq, signing_pub_key).await?;
    let response = SetupNewKeyResponse {
        encrypted_shares,
        share_commitments: instance.commitments().clone(),
    };
    verify_response_shape(&response, expected_n)?;
    let share_roster: Vec<String> = response
        .encrypted_shares
        .iter()
        .map(|s| s.recipient_fingerprint.clone())
        .collect();
    ensure!(
        roster == share_roster,
        "ceremony/ roster differs from shares/ recipient fingerprints"
    );

    Ok(VerifiedCeremonyState { response })
}

/// Read + verify THIS session's `ceremony/` entry by its exact key, returning
/// the resulting `SecretSharingInstance` and recipient roster. For setup this is
/// the `NewKey` instance; for rotation this is the `Rotate` new_instance.
///
/// Reading by the exact key (`ceremony/{sharing_seq:020}-{session_id}.json`)
/// avoids the multi-session ambiguity of `read_latest_ceremony_instance`, which
/// takes the lex-greatest key across *all* sessions — wrong when a log bucket
/// already holds a prior session's ceremony entry. The record's `session_id` is
/// asserted to match, and the signature is verified under `signing_pub_key`
/// (whatever the caller already anchored: the live guardian's gRPC-sourced key
/// for `run`; the attestation-anchored key for `verify`).
async fn read_session_ceremony(
    s3: &GuardianS3Client,
    session_id: &str,
    sharing_seq: u64,
    signing_pub_key: &GuardianPubKey,
) -> Result<(SecretSharingInstance, Vec<String>)> {
    let ceremony_key = format!("{S3_DIR_CEREMONY}/{sharing_seq:020}-{session_id}.json");
    info!(key = %ceremony_key, "reading guardian ceremony/ log");
    let verified = s3
        .get_verified_log_record(&ceremony_key, session_id, Some(signing_pub_key))
        .await
        .map_err(|e| anyhow!("verify ceremony log at {ceremony_key}: {e:?}"))?;
    let LogMessage::Ceremony(msg) = verified.message else {
        bail!("expected a Ceremony log at {ceremony_key}");
    };
    let (instance, roster) = match *msg {
        CeremonyLogMessage::NewKey { instance, roster } => (instance, roster),
        CeremonyLogMessage::Rotate {
            old_instance,
            new_instance,
            roster,
        } => {
            let expected_new_seq = old_instance
                .sharing_seq()
                .checked_add(1)
                .ok_or_else(|| anyhow!("Rotate old sharing_seq is u64::MAX at {ceremony_key}"))?;
            ensure!(
                new_instance.sharing_seq() == expected_new_seq,
                "Rotate ceremony log at {ceremony_key} has non-contiguous sharing_seq: \
                 old={}, new={}",
                old_instance.sharing_seq(),
                new_instance.sharing_seq()
            );
            (new_instance, roster)
        }
    };
    Ok((instance, roster))
}

/// Read + verify THIS session's `shares/` entry by exact key.
async fn read_session_shares(
    s3: &GuardianS3Client,
    session_id: &str,
    sharing_seq: u64,
    signing_pub_key: &GuardianPubKey,
) -> Result<Vec<KPEncryptedShare>> {
    let shares_key = format!("{S3_DIR_SHARES}/{sharing_seq:020}-{session_id}.json");
    info!(key = %shares_key, "reading guardian shares/ log");
    let log: LogRecord = s3
        .get_object_no_lock(&shares_key)
        .await
        .map_err(|e| anyhow!("read shares log at {shares_key}: {e:?}"))?;
    ensure!(
        log.session_id == session_id,
        "shares/ log session_id mismatch at {shares_key}: expected {session_id}, got {}",
        log.session_id
    );
    let verified = log
        .verify(signing_pub_key)
        .map_err(|e| anyhow!("verify shares log at {shares_key}: {e:?}"))?;
    let LogMessage::Shares(msg) = verified.message else {
        bail!("expected a Shares log at {shares_key}");
    };
    ensure!(
        msg.sharing_seq == sharing_seq,
        "shares/ log sharing_seq mismatch at {shares_key}: expected {sharing_seq}, got {}",
        msg.sharing_seq
    );
    Ok(msg.encrypted_shares)
}

fn print_summary(session_id: &str, sharing_seq: u64, response: &SetupNewKeyResponse) {
    println!("Guardian key ceremony complete.");
    println!("  session_id:        {session_id}");
    println!("  sharing_seq:       {sharing_seq}");
    println!("  shares key:        {S3_DIR_SHARES}/{sharing_seq:020}-{session_id}.json");
    println!("  share commitments:");
    for commitment in response.share_commitments.iter() {
        println!(
            "    id {:<5} {}",
            commitment.id.get(),
            hex::encode(&commitment.digest)
        );
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
        SetupNewKeyResponse {
            encrypted_shares: shares.iter().map(|&i| share(i)).collect(),
            share_commitments: commitments(commitment_ids),
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
        SetupNewKeyResponse {
            encrypted_shares: certs_by_share
                .iter()
                .enumerate()
                .map(|(i, cert)| encrypted_share((i + 1) as u16, cert))
                .collect(),
            share_commitments: commitments(&(1..=certs_by_share.len() as u16).collect::<Vec<_>>()),
        }
    }

    #[test]
    fn verify_response_shape_accepts_well_formed() {
        let resp = response(&[1, 2, 3], &[1, 2, 3]);
        verify_response_shape(&resp, 3).expect("well-formed response should pass");
    }

    #[test]
    fn verify_response_shape_rejects_wrong_share_count() {
        let resp = response(&[1, 2], &[1, 2, 3]);
        let err = verify_response_shape(&resp, 3).unwrap_err();
        assert!(format!("{err}").contains("encrypted shares"), "{err}");
    }

    #[test]
    fn verify_response_shape_rejects_wrong_commitment_count() {
        let resp = response(&[1, 2, 3], &[1, 2]);
        let err = verify_response_shape(&resp, 3).unwrap_err();
        assert!(format!("{err}").contains("commitments"), "{err}");
    }

    #[test]
    fn verify_response_shape_rejects_wrong_share_ids() {
        // 3 shares/commitments, but share ids skip 3 (use 1,2,4).
        let resp = response(&[1, 2, 4], &[1, 2, 3]);
        let err = verify_response_shape(&resp, 3).unwrap_err();
        assert!(format!("{err}").contains("share ids"), "{err}");
    }

    #[test]
    fn verify_response_shape_rejects_wrong_commitment_ids() {
        // share ids are 1..=3, but commitment ids skip 3 (use 1,2,4).
        let resp = response(&[1, 2, 3], &[1, 2, 4]);
        let err = verify_response_shape(&resp, 3).unwrap_err();
        assert!(format!("{err}").contains("commitment ids"), "{err}");
    }

    #[test]
    fn verify_encrypted_share_recipients_accepts_reordered_expected_certs() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert2, &cert3]);

        verify_encrypted_share_recipients(&resp, &[cert3, cert1, cert2])
            .expect("recipient validation should be by fingerprint, not config order");
    }

    #[test]
    fn verify_encrypted_share_recipients_rejects_duplicate_share_labels() {
        let cert1 = mock_cert();
        let cert2 = mock_cert();
        let cert3 = mock_cert();
        let resp = encrypted_response(&[&cert1, &cert1, &cert3]);

        let err = verify_encrypted_share_recipients(&resp, &[cert1, cert2, cert3]).unwrap_err();
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

        let err = verify_encrypted_share_recipients(&resp, &[cert1, cert2, cert3]).unwrap_err();
        assert!(
            format!("{err}").contains("recipient roster differs"),
            "{err}"
        );
    }
}
