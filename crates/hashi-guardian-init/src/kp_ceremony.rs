// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner ceremony` verifies and decrypts this KP's ceremony share.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::load_certs;
use tracing::info;

use crate::config::Config;
use crate::kp_roster::decrypt_share;
use crate::kp_roster::ensure_cert_in_roster;
use crate::kp_roster::verify_encrypted_share_recipients;

/// Verify this KP can fetch and decrypt its ceremony share.
///
/// Trust is anchored entirely to the guardian's S3 attestation log: the
/// `GuardianReader` resolves the session's attested signing pubkey through the
/// reader cache, and both the `ceremony/` audit entry and `kp-shares/` recovery
/// entry are verified under it. Each step is logged.
///
/// Security: the ciphertext is piped into `gpg --decrypt` over stdin and the
/// plaintext streams back over stdout; neither ciphertext nor plaintext is
/// written to disk by this flow.
pub async fn run(cfg: Config) -> Result<()> {
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
        cert_count = cfg.kp_roster.kp_pgp_cert_paths.len(),
        "loading + validating full KP cert roster",
    );
    let certs = load_certs(&cfg.kp_roster.kp_pgp_cert_paths)?;
    info!(
        phase = "roster load",
        cert_count = certs.len(),
        "KP cert roster loaded"
    );

    // Load this KP's cert. Its fingerprint finds our share in `kp-shares/`, and
    // the cert itself lets us confirm the ciphertext is genuinely encrypted to
    // us before we touch the yubikey.
    let kp_pgp_cert_path = cfg.require_kp_pgp_cert_path("key-provisioner ceremony")?;
    let cert_armored = std::fs::read_to_string(kp_pgp_cert_path)
        .with_context(|| format!("read KP cert at {}", kp_pgp_cert_path.display()))?;
    let kp_cert = PgpPublicCert::new(cert_armored)
        .with_context(|| format!("invalid PGP cert at {}", kp_pgp_cert_path.display()))?;
    let want_fp = kp_cert.fingerprint();
    info!(
        phase = "setup",
        fingerprint = %want_fp,
        kp_cert_path = %kp_pgp_cert_path.display(),
        "loaded this KP's cert",
    );
    ensure_cert_in_roster(&kp_cert, &certs)?;

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
        share_count = state.encrypted_shares.len(),
        "discovered + validated latest ceremony state",
    );

    // 2. Confirm every share is addressed only to its labeled KP cert.
    info!(
        phase = "roster verify",
        share_count = state.encrypted_shares.len(),
        "verifying every share is addressed only to its labeled KP cert (without decrypting)",
    );
    verify_encrypted_share_recipients(&state, &certs)?;
    info!(
        phase = "roster verify",
        "ceremony/ and kp-shares/ logs verified against expected params and KP certs",
    );

    // 3. Find this KP's share by exact fingerprint match (both sides derive
    //    from `Fingerprint::to_hex` over the same key, so they're canonical
    //    and identical). The matched share carries its own crypto `id`.
    let want_fp_hex = want_fp.to_hex();
    let share = state
        .encrypted_shares
        .iter()
        .find(|s| s.recipient_fingerprint == want_fp_hex)
        .ok_or_else(|| {
            anyhow!(
                "no share in the kp-shares log is labeled for this KP's fingerprint \
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
        share_id = share_id.get(),
        sharing_seq = state.secret_sharing_instance.sharing_seq(),
        cert_seq = state.cert_seq,
        fingerprint = %want_fp,
        commitment = hex::encode(&expected_commitment.digest),
        "ceremony share verified",
    );
    Ok(())
}
