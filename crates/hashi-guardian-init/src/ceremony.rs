// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony commands.
//!
//! `ceremony run` drives a fresh ceremony-mode guardian through genesis BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) -> [`SetupNewKey`] -> inspect each
//! returned encrypted share to confirm it is addressed to the expected KP cert
//! (without decrypting) -> cross-check the guardian's `ceremony/` audit log and
//! `shares/` recovery log.
//!
//! [`OperatorInit`]: hashi_types::guardian::OperatorInitRequest
//! [`SetupNewKey`]: hashi_types::guardian::SetupNewKeyRequest
//! [`SetupNewKeyResponse`]: hashi_types::guardian::SetupNewKeyResponse

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::Share;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::decrypt_armored_via_gpg;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use k256::FieldBytes;
use k256::Scalar;
use k256::elliptic_curve::PrimeField;
use serde::Deserialize;
use tracing::info;

use crate::kp_roster::KpRosterConfig;
use crate::kp_roster::VerifiedCeremonyState;
use crate::kp_roster::ensure_cert_in_roster;

#[derive(Deserialize)]
pub struct CeremonyRunConfig {
    #[serde(flatten)]
    pub common: KpRosterConfig,
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
    pub common: KpRosterConfig,
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
    let certs = load_certs(&cfg.common.kp_pgp_cert_paths)?;
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

    // 5. get_guardian_info -> verify attestation/PCRs and signed info -> pin the
    //    session id. This binds `signing_pub_key` (and thus the session) before
    //    we trust the SetupNewKey response we'll verify against it below.
    info!("calling GetGuardianInfo");
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    let verified = info_resp
        .verify(&cfg.common.expected_pcr0)
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e:?}"))?;
    let signing_pub_key = verified.signing_pub_key;
    let session_id = verified.session_id;
    info!(session_id = %session_id, "guardian info attestation verified; session pinned");

    let mut reader = GuardianReader::new(&cfg.common.guardian_s3, cfg.common.expected_pcr0.clone())
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
/// Security: the ciphertext is piped into `gpg --decrypt` over stdin and the
/// plaintext streams back over stdout; neither ciphertext nor plaintext is
/// written to disk by this flow.
pub async fn verify(cfg: CeremonyVerifyConfig) -> Result<()> {
    cfg.common.validate()?;

    let certs = load_certs(&cfg.common.kp_pgp_cert_paths)?;

    // Load this KP's cert. Its fingerprint finds our share in `shares/`, and
    // the cert itself lets us confirm the ciphertext is genuinely encrypted to
    // us before we touch the yubikey.
    let cert_armored = std::fs::read_to_string(&cfg.kp_pgp_cert_path)
        .with_context(|| format!("read KP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let kp_cert = PgpPublicCert::new(cert_armored)
        .with_context(|| format!("invalid PGP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let want_fp = kp_cert.fingerprint();
    info!(fingerprint = %want_fp, "verifying ceremony share");
    ensure_cert_in_roster(&kp_cert, &certs)?;

    // 1. Discover and verify the latest ceremony from the immutable log
    //    (attestation-verified once via the reader's session-key cache).
    let sharing_seq = cfg.sharing_seq;
    let mut reader = GuardianReader::new(&cfg.common.guardian_s3, cfg.common.expected_pcr0.clone())
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

    // 4. Decrypt the share with the yubikey via gpg. The ciphertext is piped
    //    into gpg over stdin; decrypted bytes stream back into memory.
    let plaintext = decrypt_armored_via_gpg(&share.armored_ciphertext, cfg.gpg_homedir.as_deref())?;

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
