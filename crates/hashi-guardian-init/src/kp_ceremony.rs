// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner ceremony` verifies and decrypts this KP's ceremony share.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::load_certs;
use serde::Deserialize;
use tracing::info;

use crate::kp_roster::KpRosterConfig;
use crate::kp_roster::VerifiedCeremonyState;
use crate::kp_roster::decrypt_share;
use crate::kp_roster::ensure_cert_in_roster;

#[derive(Deserialize)]
pub struct CeremonyConfig {
    #[serde(flatten)]
    pub common: KpRosterConfig,
    /// Path to this KP's armored OpenPGP public cert (the one they exported and
    /// gave to the operator at `operator ceremony` time). Used to derive the
    /// fingerprint that finds this KP's share in `shares/`, and to confirm the
    /// share's ciphertext is genuinely encrypted to this cert before decrypting.
    pub kp_pgp_cert_path: PathBuf,
}

impl CeremonyConfig {
    pub fn load_yaml(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).with_context(|| {
            format!(
                "failed to read key-provisioner ceremony config at {}",
                path.display()
            )
        })?;
        serde_yaml::from_slice(&bytes).with_context(|| {
            format!(
                "failed to parse key-provisioner ceremony yaml at {}",
                path.display()
            )
        })
    }
}

/// Verify this KP can fetch and decrypt its ceremony share.
///
/// Trust is anchored entirely to the guardian's S3 attestation log: the
/// `GuardianReader` resolves the session's attested signing pubkey through the
/// reader cache, and both the `ceremony/` audit entry and `shares/` recovery
/// entry are verified under it. Each step is logged.
///
/// Security: the ciphertext is piped into `gpg --decrypt` over stdin and the
/// plaintext streams back over stdout; neither ciphertext nor plaintext is
/// written to disk by this flow.
pub async fn run(cfg: CeremonyConfig) -> Result<()> {
    cfg.common.validate()?;

    info!(
        phase = "setup",
        bucket = cfg.common.guardian_s3.bucket_name(),
        region = cfg.common.guardian_s3.region(),
        num_shares = cfg.common.num_shares,
        threshold = cfg.common.threshold,
        "verifying ceremony share",
    );

    info!(
        phase = "roster load",
        cert_count = cfg.common.kp_pgp_cert_paths.len(),
        "loading + validating full KP cert roster",
    );
    let certs = load_certs(&cfg.common.kp_pgp_cert_paths)?;
    info!(
        phase = "roster load",
        cert_count = certs.len(),
        "KP cert roster loaded"
    );

    // Load this KP's cert. Its fingerprint finds our share in `shares/`, and
    // the cert itself lets us confirm the ciphertext is genuinely encrypted to
    // us before we touch the yubikey.
    let cert_armored = std::fs::read_to_string(&cfg.kp_pgp_cert_path)
        .with_context(|| format!("read KP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let kp_cert = PgpPublicCert::new(cert_armored)
        .with_context(|| format!("invalid PGP cert at {}", cfg.kp_pgp_cert_path.display()))?;
    let want_fp = kp_cert.fingerprint();
    info!(
        phase = "setup",
        fingerprint = %want_fp,
        kp_cert_path = %cfg.kp_pgp_cert_path.display(),
        "loaded this KP's cert",
    );
    ensure_cert_in_roster(&kp_cert, &certs)?;

    // 1. Discover and verify the latest ceremony from the immutable log
    //    (attestation-verified once via the reader's session-key cache).
    info!(
        phase = "s3 connect",
        bucket = cfg.common.guardian_s3.bucket_name(),
        region = cfg.common.guardian_s3.region(),
        current_pcr0 = hex::encode(cfg.common.pcr_allowlist.current_build().pcr0()),
        "connecting to guardian log bucket",
    );
    let mut reader = GuardianReader::new(&cfg.common.guardian_s3, cfg.common.pcr_allowlist())
        .await
        .context("connect to guardian log bucket")?;
    info!(phase = "s3 connect", "connected to guardian log bucket");

    info!(
        phase = "ceremony scrape",
        "scraping latest ceremony/ + shares/ logs (attestation-anchored)",
    );
    let state = VerifiedCeremonyState::latest_from_s3(
        &mut reader,
        cfg.common.num_shares,
        cfg.common.threshold,
    )
    .await?;
    info!(
        phase = "ceremony scrape",
        session_id = %state.session_id,
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        n = state.secret_sharing_instance.num_shares(),
        t = state.secret_sharing_instance.threshold(),
        share_count = state.encrypted_shares.len(),
        "discovered + validated latest ceremony session",
    );

    // 2. Confirm every share is addressed only to its labeled KP cert.
    info!(
        phase = "roster verify",
        share_count = state.encrypted_shares.len(),
        "verifying every share is addressed only to its labeled KP cert (without decrypting)",
    );
    state.verify_encrypted_share_recipients(&certs)?;
    info!(
        phase = "roster verify",
        "ceremony/ and shares/ logs verified against expected params and KP certs",
    );

    // 3. Find this KP's share by exact fingerprint match (both sides derive
    //    from PgpPublicCert::fingerprint over the same key, so they're
    //    canonical and identical: no normalization needed). The matched share
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
    let share_id = share.id;
    info!(
        phase = "share find",
        share_id = share_id.get(),
        fingerprint = %share.recipient_fingerprint,
        "located this KP's encrypted share",
    );

    // 4. Decrypt the share with the yubikey via gpg. The ciphertext is piped
    //    into gpg over stdin; decrypted bytes stream back into memory.
    info!(
        phase = "share decrypt",
        share_id = share_id.get(),
        "decrypting share via yubikey (ciphertext piped via stdin; plaintext in memory)",
    );
    let reconstructed = decrypt_share(share)?;
    info!(
        phase = "share decrypt",
        share_id = share_id.get(),
        "decrypted share via yubikey",
    );

    // 5. Verify the decrypted share's commitment is in the set: proves the
    //    bytes we decrypted are a valid share of the guardian's BTC key.
    info!(
        phase = "commitment verify",
        share_id = share_id.get(),
        "verifying decrypted share against its commitment",
    );
    state
        .secret_sharing_instance
        .commitments()
        .verify_share(&reconstructed)
        .map_err(|e| anyhow!("decrypted share does not match its commitment: {e:?}"))?;
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

    info!(
        phase = "summary",
        session_id = %state.session_id,
        share_id = share_id.get(),
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        fingerprint = %want_fp,
        commitment = hex::encode(&expected_commitment.digest),
        "ceremony share verified",
    );
    Ok(())
}
