// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony — operator-side `ceremony run`.
//!
//! Drives a fresh ceremony-mode guardian through the one-time BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) → [`SetupNewKey`] → inspect each
//! returned encrypted share to confirm it is addressed to the expected KP cert
//! (without decrypting) → cross-check the guardian's `ceremony/` audit log →
//! upload the guardian-signed [`SetupNewKeyResponse`] (the ceremony artifact)
//! to a deletable artifacts bucket for each KP to later fetch and verify.
//!
//! Ceremony `verify` (per-KP) is stubbed for now.
//!
//! [`OperatorInit`]: hashi_types::guardian::OperatorInitRequest
//! [`SetupNewKey`]: hashi_types::guardian::SetupNewKeyRequest
//! [`SetupNewKeyResponse`]: hashi_types::guardian::SetupNewKeyResponse

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use hashi_guardian::s3_client::GuardianS3Client;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::LogMessage;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::S3_DIR_CEREMONY;
use hashi_types::guardian::S3Config;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use hashi_types::guardian::session_id_from_signing_pubkey;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::cert_owns_key_handle;
use hashi_types::pgp::pgp_message_recipients;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use serde::Deserialize;
use tracing::info;

/// S3 object key prefix for ceremony artifacts in the artifacts bucket.
///
/// Mirrors the guardian's own `ceremony/` log directory (different prefix so the
/// two are distinguishable), and the per-object key shape is the same:
/// `{sharing_seq:020}-{session_id}.json` so lexicographic listing sorts by the
/// secret-sharing version (0 at setup, +1 per rotation).
const ARTIFACT_DIR: &str = "ceremony-artifacts";

#[derive(Deserialize)]
pub struct CeremonyRunConfig {
    /// gRPC endpoint of the ceremony-mode guardian.
    pub guardian_endpoint: String,
    /// Total number of shares. Must equal `kp_pgp_cert_paths.len()`.
    pub num_shares: usize,
    /// Reconstruction threshold. Must satisfy `2 <= threshold <= num_shares`.
    pub threshold: usize,
    /// S3 config for the guardian's log bucket. Passed to [`OperatorInit`] so the
    /// guardian can write its `init/` + `ceremony/` logs. Must have object-lock
    /// enabled.
    pub guardian_s3: S3Config,
    /// S3 config for the ceremony artifacts bucket (object-lock DISABLED, so
    /// encrypted shares can be deleted if ever needed). Integrity of the
    /// artifact comes from the guardian's signature, not S3 immutability.
    pub artifact_s3: S3Config,
    /// Paths to each KP's armored OpenPGP public cert. Order matters: the cert
    /// at index `i` (0-based) is assigned share id `i + 1`.
    pub kp_pgp_cert_paths: Vec<PathBuf>,
}

impl CeremonyRunConfig {
    pub fn load_yaml(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read ceremony-run config at {}", path.display()))?;
        serde_yaml::from_slice(&bytes)
            .with_context(|| format!("failed to parse ceremony-run yaml at {}", path.display()))
    }
}

/// Run the one-time production guardian key ceremony.
///
/// See the module docs for the full step-by-step flow. Each step is logged via
/// `tracing` so the operator can follow exactly what is happening.
pub async fn run(cfg: CeremonyRunConfig) -> Result<()> {
    info!(
        num_shares = cfg.num_shares,
        threshold = cfg.threshold,
        cert_count = cfg.kp_pgp_cert_paths.len(),
        "running guardian key ceremony"
    );

    // 1. Validate config-level sharing params up front (also re-validated by
    //    SetupNewKeyRequest::new).
    ensure!(
        cfg.num_shares == cfg.kp_pgp_cert_paths.len(),
        "num_shares ({}) must equal the number of KP certs ({})",
        cfg.num_shares,
        cfg.kp_pgp_cert_paths.len()
    );
    ensure!(
        cfg.threshold >= 2,
        "threshold must be at least 2, got {}",
        cfg.threshold
    );
    ensure!(
        cfg.threshold <= cfg.num_shares,
        "threshold ({}) must be <= num_shares ({})",
        cfg.threshold,
        cfg.num_shares
    );

    // 2. Load + validate each KP's PGP cert.
    let certs = load_kp_certs(&cfg.kp_pgp_cert_paths)?;

    // 3. Connect to the ceremony-mode guardian.
    info!(endpoint = %cfg.guardian_endpoint, "connecting to guardian");
    let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", cfg.guardian_endpoint))?;
    info!("connected to guardian");

    // 4. operator_init (ceremony mode: S3 config only, no WithdrawModeConfig).
    info!(
        bucket = cfg.guardian_s3.bucket_name(),
        region = cfg.guardian_s3.region(),
        "calling OperatorInit (ceremony mode)"
    );
    let oi_req = operator_init_request_to_pb(OperatorInitRequest::new_ceremony_mode(
        cfg.guardian_s3.clone(),
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

    // 6. setup_new_key.
    info!(n = cfg.num_shares, t = cfg.threshold, "calling SetupNewKey");
    let setup_req = SetupNewKeyRequest::new(certs.clone(), cfg.num_shares, cfg.threshold)
        .map_err(|e| anyhow!("build SetupNewKeyRequest: {e:?}"))?;
    let signed_resp_pb = client
        .setup_new_key(setup_new_key_request_to_pb(setup_req))
        .await
        .context("SetupNewKey RPC failed")?
        .into_inner();
    let signed_resp = GuardianSigned::<SetupNewKeyResponse>::try_from(signed_resp_pb)
        .map_err(|e| anyhow!("decode SignedSetupNewKeyResponse: {e:?}"))?;
    info!(
        n = cfg.num_shares,
        t = cfg.threshold,
        encrypted_share_count = signed_resp.data.encrypted_shares.len(),
        "setup_new_key response received"
    );

    // 7. Verify the response signature under the pinned session's signing key,
    //    and sanity-check the response shape. `verify` consumes, so verify a
    //    clone and keep `signed_resp` for the upload below.
    let response = signed_resp
        .clone()
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e:?}"))?;
    verify_response_shape(&response, cfg.num_shares)?;

    // 8. Inspect each encrypted share's PGP recipients WITHOUT decrypting, and
    //    confirm every share is addressed only to its expected cert.
    verify_encrypted_share_recipients(&response, &certs)?;

    // 9. Cross-check the guardian's ceremony/ audit log: read THIS session's
    //    logged instance by its exact key and confirm commitments / n / t /
    //    sharing_seq match what we requested and got back.
    let sharing_seq = 0u64;
    verify_ceremony_log(
        &cfg.guardian_s3,
        &session_id,
        &signing_pub_key,
        sharing_seq,
        cfg.num_shares,
        cfg.threshold,
        &response,
    )
    .await?;

    // 10. Upload the guardian-signed response to the artifacts bucket.
    let artifact_key = artifact_object_key(sharing_seq, &session_id);
    let artifact_client = GuardianS3Client::new(&cfg.artifact_s3).await;
    info!(
        bucket = cfg.artifact_s3.bucket_name(),
        region = cfg.artifact_s3.region(),
        key = %artifact_key,
        "uploading ceremony artifact"
    );
    artifact_client
        .write_at_key_no_lock(&artifact_key, &signed_resp)
        .await?;

    // 11. Read it back and confirm it round-trips to an equal value.
    let read_back = artifact_client
        .get_at_key::<GuardianSigned<SetupNewKeyResponse>>(&artifact_key)
        .await?;
    ensure!(
        read_back == signed_resp,
        "ceremony artifact round-trip mismatch at {artifact_key}"
    );
    info!("ceremony artifact uploaded and round-trip verified");

    // 12. Summary.
    print_summary(&session_id, &artifact_key, &cfg.artifact_s3, &response);

    Ok(())
}

/// Load and validate each KP's armored OpenPGP cert, logging the fingerprint +
/// assigned share id for each. Returns the certs in config order.
fn load_kp_certs(paths: &[PathBuf]) -> Result<Vec<PgpPublicCert>> {
    let mut certs = Vec::with_capacity(paths.len());
    for (i, path) in paths.iter().enumerate() {
        let armored = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read KP cert at {}", path.display()))?;
        let cert = PgpPublicCert::new(armored)
            .with_context(|| format!("invalid PGP cert at {}", path.display()))?;
        info!(
            share_id = i + 1,
            fingerprint = %cert,
            path = %path.display(),
            "loaded KP cert"
        );
        certs.push(cert);
    }
    Ok(certs)
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

/// For each encrypted share, parse its PKESK recipients (without decrypting)
/// and confirm every recipient key belongs to the share's expected cert. Catches
/// a guardian that encrypted a share to the wrong cert — or to an extra/attacker
/// key alongside the right one.
fn verify_encrypted_share_recipients(
    response: &SetupNewKeyResponse,
    certs: &[PgpPublicCert],
) -> Result<()> {
    for share in &response.encrypted_shares {
        let id = share.id.get() as usize;
        ensure!(
            (1..=certs.len()).contains(&id),
            "share id {id} is outside 1..={}",
            certs.len()
        );
        let expected_cert = &certs[id - 1];
        let recipients = pgp_message_recipients(&share.armored_ciphertext)
            .with_context(|| format!("parse PGP recipients for share id {id}"))?;
        ensure!(
            !recipients.is_empty(),
            "share id {id} has no PGP recipients"
        );
        for handle in &recipients {
            ensure!(
                cert_owns_key_handle(expected_cert, handle),
                "share id {id} is encrypted to key {handle}, which is not in the \
                 expected cert (fingerprint {})",
                expected_cert
            );
        }
        info!(
            share_id = id,
            fingerprint = %expected_cert,
            recipient_count = recipients.len(),
            "verified share is encrypted only to its expected cert"
        );
    }
    info!(
        "all {} shares encrypted to their expected certs",
        certs.len()
    );
    Ok(())
}

/// Read THIS session's `ceremony/` entry by its exact key and confirm the
/// logged `SecretSharingInstance` (commitments / n / t / sharing_seq) matches
/// what we requested and what came back in the `SetupNewKeyResponse`.
///
/// Reading by the exact key (`ceremony/{sharing_seq:020}-{session_id}.json`)
/// avoids the multi-session ambiguity of `read_latest_ceremony_instance`, which
/// takes the lex-greatest key across *all* sessions — wrong when a log bucket
/// already holds a prior session's ceremony entry. The record is verified under
/// `signing_pub_key` (the key we pinned at step 5), which is consistent with the
/// current trust model; the attestation gate (TODO check C) composes here once
/// implemented.
async fn verify_ceremony_log(
    guardian_s3: &S3Config,
    session_id: &str,
    signing_pub_key: &GuardianPubKey,
    sharing_seq: u64,
    n: usize,
    t: usize,
    response: &SetupNewKeyResponse,
) -> Result<()> {
    let ceremony_key = format!("{S3_DIR_CEREMONY}/{sharing_seq:020}-{session_id}.json");
    info!(key = %ceremony_key, "reading guardian ceremony/ log to cross-check");

    let s3 = GuardianS3Client::new_checked(guardian_s3)
        .await
        .context("connect to guardian log bucket")?;
    let record = s3.get_log_record(&ceremony_key).await?;
    let verified = record
        .verify(signing_pub_key)
        .map_err(|e| anyhow!("verify ceremony log signature at {ceremony_key}: {e:?}"))?;

    let LogMessage::Ceremony(msg) = verified.message else {
        bail!("expected a Ceremony log at {ceremony_key}");
    };
    let CeremonyLogMessage::NewKey { instance } = *msg else {
        bail!("expected a CeremonyLogMessage::NewKey at {ceremony_key}");
    };

    ensure!(
        *instance.commitments() == response.share_commitments,
        "ceremony/ log commitments differ from the SetupNewKeyResponse commitments"
    );
    ensure!(
        instance.num_shares() == n,
        "ceremony/ log num_shares ({}) differs from requested ({})",
        instance.num_shares(),
        n
    );
    ensure!(
        instance.threshold() == t,
        "ceremony/ log threshold ({}) differs from requested ({})",
        instance.threshold(),
        t
    );
    ensure!(
        instance.sharing_seq() == sharing_seq,
        "ceremony/ log sharing_seq ({}) differs from expected ({})",
        instance.sharing_seq(),
        sharing_seq
    );
    info!("ceremony/ log matches the SetupNewKeyResponse");
    Ok(())
}

/// `ceremony-artifacts/{sharing_seq:020}-{session_id}.json`.
fn artifact_object_key(sharing_seq: u64, session_id: &str) -> String {
    format!("{ARTIFACT_DIR}/{sharing_seq:020}-{session_id}.json")
}

fn print_summary(
    session_id: &str,
    artifact_key: &str,
    artifact_s3: &S3Config,
    response: &SetupNewKeyResponse,
) {
    println!("Guardian key ceremony complete.");
    println!("  session_id:        {session_id}");
    println!(
        "  artifact bucket:   {}/{}",
        artifact_s3.region(),
        artifact_s3.bucket_name()
    );
    println!("  artifact key:      {artifact_key}");
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
    use std::num::NonZeroU16;

    fn share(id: u16) -> KPEncryptedShare {
        KPEncryptedShare {
            id: NonZeroU16::new(id).unwrap(),
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

    #[test]
    fn artifact_object_key_zero_pads_sharing_seq_and_sorts() {
        assert_eq!(
            artifact_object_key(0, "abc"),
            "ceremony-artifacts/00000000000000000000-abc.json"
        );
        assert_eq!(
            artifact_object_key(1, "abc"),
            "ceremony-artifacts/00000000000000000001-abc.json"
        );
        // Lexicographic order tracks sharing_seq (so listing sorts numerically).
        assert!(artifact_object_key(1, "abc") > artifact_object_key(0, "abc"));
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
}
