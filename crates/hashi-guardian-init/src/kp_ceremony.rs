// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner ceremony` verifies and decrypts this KP's ceremony share.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use std::path::Path;
use tracing::info;

use crate::config::Config;
use crate::kp_roster::decrypt_kp_share_copies;
use crate::kp_roster::load_kp_cert;

/// Verify this KP can fetch and decrypt its ceremony share.
///
/// Trust is anchored entirely to the guardian's S3 attestation log: the
/// `GuardianReader` resolves the session's attested signing pubkey through the
/// reader cache, and both the `ceremony/` audit entry and `kp-shares/` recovery
/// entry are verified under it. Each step is logged.
///
/// Security: the ceremony state containing the encrypted shares is saved to the
/// requested path. Each ciphertext is piped into `gpg --decrypt` over stdin and
/// the plaintext streams back over stdout; neither ciphertext nor plaintext is
/// separately written to disk by this flow.
pub async fn run(cfg: Config, encrypted_shares_path: &Path) -> Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = cfg.guardian_s3.resolve().await?;

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
        certificate_count = cfg.kp_roster.cert_count(),
        "loading + validating full KP certificate roster",
    );
    let certs_roster = cfg.kp_roster.load_certs_roster()?;
    info!(
        phase = "roster load",
        share_count = certs_roster.num_kps(),
        certificate_count = cfg.kp_roster.cert_count(),
        "KP certificate roster loaded"
    );

    // The selected cert identifies this KP's roster entry. Ceremony validation
    // then exercises every cert assigned to that KP/share.
    let kp_pgp_cert_path = cfg.require_kp_pgp_cert_path("key-provisioner ceremony")?;
    let kp_cert = load_kp_cert(kp_pgp_cert_path)?;
    let kp_certs = certs_roster
        .certs_for_fingerprint(&kp_cert.fingerprint())
        .with_context(|| {
            format!(
                "this KP's cert (fingerprint {}) is not among the configured \
                 kp_roster.kp_pgp_cert_paths",
                kp_cert.fingerprint()
            )
        })?;
    let fingerprints = kp_certs.fingerprints();
    info!(
        phase = "setup",
        selected_fingerprint = %kp_cert.fingerprint(),
        certificate_count = kp_certs.pgp_certs().len(),
        fingerprints = ?fingerprints,
        "identified this KP's complete roster entry",
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
        .read_latest_ceremony_state(BuildPolicy::Current)
        .await?
        .context("no ceremony logs found in guardian S3 bucket")?;
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    info!(
        phase = "ceremony scrape",
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        cert_seq = state.cert_seq,
        n = state.secret_sharing_instance.num_shares(),
        t = state.secret_sharing_instance.threshold(),
        share_count = state.encrypted_shares.share_count(),
        ciphertext_count = state.encrypted_shares.ciphertext_count(),
        "discovered + validated latest ceremony state",
    );

    // 2. Confirm every PGP-encrypted share is addressed to the expected KP cert set.
    info!(
        phase = "roster verify",
        share_count = state.encrypted_shares.share_count(),
        ciphertext_count = state.encrypted_shares.ciphertext_count(),
        "verifying every PGP-encrypted share against the expected KP cert sets (without decrypting)",
    );
    state.encrypted_shares.verify_recipients(&certs_roster)?;
    info!(
        phase = "roster verify",
        "ceremony/ and kp-shares/ logs verified against expected params and KP certs",
    );

    // 3. Decrypt and commitment-check every ciphertext in this KP's roster entry.
    let reconstructed = decrypt_kp_share_copies(&state, kp_certs.pgp_certs())?;
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
        ciphertext_count = state.encrypted_shares.ciphertext_count(),
        "saved ceremony state with encrypted shares",
    );

    info!(
        phase = "summary",
        share_id = share_id.get(),
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        cert_seq = state.cert_seq,
        certificate_count = kp_certs.pgp_certs().len(),
        fingerprints = ?fingerprints,
        commitment = hex::encode(&expected_commitment.digest),
        "ceremony share verified through every certificate in this KP's roster entry",
    );
    Ok(())
}
