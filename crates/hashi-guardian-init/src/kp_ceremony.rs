// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner ceremony` verifies, decrypts, saves, and confirms this KP's ceremony share.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::CeremonyConfirmationResponse;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::proto_conversions::signed_ceremony_confirmation_request_to_pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use std::path::Path;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::verified_ceremony_guardian_info;
use crate::kp_roster::decrypt_kp_share;
use crate::kp_roster::load_kp_cert;

/// Verify this KP can fetch and decrypt its ceremony share, then submit a
/// signed confirmation to the live ceremony guardian.
///
/// The share state is anchored to the guardian's S3 attestation log. The live
/// confirmation endpoint is independently attestation-verified and
/// authoritatively matches the signed ceremony digest against its pending state.
/// Through the proxy, the ceremony guardian is the provisioning target: the
/// standby during a KP-set rotation, else the active guardian.
///
/// Security: the ceremony state containing the encrypted shares is saved to the
/// requested path. Each ciphertext is piped into `gpg --decrypt` over stdin and
/// the plaintext streams back over stdout; neither ciphertext nor plaintext is
/// separately written to disk by this flow.
pub async fn run(cfg: Config, encrypted_shares_path: &Path) -> Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        num_shares = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        sui_rpc = %cfg.hashi.sui_rpc,
        package_id = %cfg.hashi.hashi_ids.package_id,
        hashi_object_id = %cfg.hashi.hashi_ids.hashi_object_id,
        "verifying ceremony share",
    );

    info!(
        phase = "roster load",
        share_count = cfg.kp_roster.kp_pgp_cert_paths.len(),
        "loading + validating full KP certificate roster",
    );
    let certs_roster = cfg.kp_roster.load_certs_roster()?;
    info!(
        phase = "roster load",
        share_count = certs_roster.num_kps(),
        "KP certificate roster loaded"
    );

    // The selected cert identifies this KP's roster entry.
    let kp_pgp_cert_path = cfg.require_kp_pgp_cert_path("key-provisioner ceremony")?;
    let kp_cert = load_kp_cert(kp_pgp_cert_path)?;
    certs_roster
        .cert_for_fingerprint(&kp_cert.fingerprint())
        .with_context(|| {
            format!(
                "this KP's cert (fingerprint {}) is not among the configured \
                 kp_roster.kp_pgp_cert_paths",
                kp_cert.fingerprint()
            )
        })?;
    info!(
        phase = "setup",
        fingerprint = %kp_cert.fingerprint(),
        "identified this KP's configured certificate",
    );

    // 1. Discover and verify the latest ceremony from the immutable log
    //    (attestation-verified once via the reader's session-key cache).
    info!(
        phase = "s3 connect",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        current_pcr0 = hex::encode(cfg.kp_roster.pcr_allowlist.current_build().pcr0()),
        "connecting to guardian log bucket",
    );
    let mut reader = GuardianReader::new(&guardian_s3, cfg.kp_roster.pcr_allowlist())
        .await
        .context("connect to guardian log bucket")?;
    info!(phase = "s3 connect", "connected to guardian log bucket");

    info!(
        phase = "ceremony scrape",
        "scraping latest ceremony/ + kp-shares/ logs (attestation-anchored)",
    );
    let state = reader
        .read_latest_ceremony_state_from_current_build()
        .await?;
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    info!(
        phase = "ceremony scrape",
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        cert_seq = state.cert_seq,
        n = state.secret_sharing_instance.num_shares(),
        t = state.secret_sharing_instance.threshold(),
        share_count = state.encrypted_shares.share_count(),
        "discovered + validated latest ceremony state",
    );

    // 2. Confirm every PGP-encrypted share is addressed to the expected KP cert.
    info!(
        phase = "roster verify",
        share_count = state.encrypted_shares.share_count(),
        "verifying every PGP-encrypted share against the expected KP certs (without decrypting)",
    );
    state.encrypted_shares.verify_recipients(&certs_roster)?;
    info!(
        phase = "roster verify",
        "ceremony/ and kp-shares/ logs verified against expected params and KP certs",
    );

    // 3. Decrypt and commitment-check this KP's ciphertext.
    let reconstructed = decrypt_kp_share(&state, &kp_cert)?;
    let share_id = reconstructed.id;
    let expected_commitment = state
        .secret_sharing_instance
        .commitments()
        .iter()
        .find(|c| c.id == share_id)
        .ok_or_else(|| {
            anyhow!(
                "commitment for share id {} missing despite verify_share success",
                share_id
            )
        })?;
    info!(
        phase = "commitment verify",
        share_id = share_id.get(),
        commitment = hex::encode(&expected_commitment.digest),
        "decrypted share matches its commitment",
    );

    // 4. Save the ceremony state only after every verification step succeeds.
    let ceremony_state_bytes =
        serde_json::to_vec(&state).context("serialize ceremony state with encrypted shares")?;
    std::fs::write(encrypted_shares_path, ceremony_state_bytes).with_context(|| {
        format!(
            "write ceremony state with encrypted shares to {}",
            encrypted_shares_path.display()
        )
    })?;
    info!(
        phase = "share save",
        path = %encrypted_shares_path.display(),
        share_count = state.encrypted_shares.share_count(),
        "saved ceremony state with encrypted shares",
    );

    // 5. Submit a signed confirmation only after the verified recovery artifact
    //    is safely stored locally.
    info!(
        phase = "confirmation",
        endpoint = %cfg.guardian_endpoint,
        "connecting to live ceremony guardian",
    );
    let verified = verified_ceremony_guardian_info(
        &cfg.guardian_endpoint,
        cfg.kp_roster.pcr_allowlist.current_build(),
    )
    .await?;
    let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to ceremony guardian at {}", cfg.guardian_endpoint))?;
    ensure!(
        verified.info.lifecycle == CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
            || verified.info.lifecycle == CeremonyStage::Completed.into(),
        "guardian is not accepting key provisioner ceremony confirmations"
    );
    let kp_fingerprint = kp_cert.fingerprint();
    let confirmation = CeremonyConfirmationRequest::new(verified.session_id, state.digest());
    let signed = KpSigned::sign(confirmation, kp_cert, None)
        .map_err(anyhow::Error::msg)
        .context("sign ceremony confirmation with the KP key")?;
    let status = CeremonyConfirmationResponse::try_from(
        client
            .confirm_ceremony(signed_ceremony_confirmation_request_to_pb(signed))
            .await
            .context("ConfirmCeremony RPC failed")?
            .into_inner(),
    )
    .map_err(|error| anyhow!("decode CeremonyConfirmationResponse: {error:?}"))?;
    info!(
        phase = "confirmation",
        share_id = share_id.get(),
        have = status.have,
        need = status.need,
        completed = status.completed,
        "ceremony confirmation progress",
    );

    info!(
        phase = "summary",
        share_id = share_id.get(),
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        cert_seq = state.cert_seq,
        fingerprint = %kp_fingerprint,
        commitment = hex::encode(&expected_commitment.digest),
        "ceremony share verified through this KP's configured certificate",
    );
    Ok(())
}
