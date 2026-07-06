// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner provision` (per-KP recovery against a fresh withdraw-mode guardian).
//!
//! Run by a key provisioner when a new guardian instance is brought up to
//! replace one that went down. The KP decrypts through their yubikey-backed gpg
//! setup; plaintext never touches disk, but the raw share scalar is held in this
//! process' memory long enough to verify and re-encrypt it. The flow:
//!
//! 1. The relay/standby endpoint's signed `GuardianInfo` is fetched and
//!    verified against the enclave attestation, pinning the standby session.
//! 2. The same session's S3 `init/` log is fetched and required to match the
//!    endpoint `GuardianInfo`. Bucket, limiter config, `mpc_master_g`, and
//!    `enclave_btc_pubkey == None` are all confirmed.
//! 3. The authoritative `ceremony/` log is scraped for the secret-sharing
//!    instance the new guardian was booted with; it must match.
//! 4. The stable `InitConfig` is recomputed from the configured S3 bucket,
//!    limiter config, master G, PCR allowlist, and network; its `config_hash`
//!    is confirmed (check C).
//! 5. This KP's encrypted share is read from `shares/{seq}-{session}.json`
//!    (attestation-anchored), every share's recipients are verified against
//!    the roster, and this KP's share is located by fingerprint.
//! 6. The share is decrypted via the yubikey (`gpg --decrypt` over a pipe;
//!    plaintext stays in memory) and verified against its commitment.
//! 7. The decrypted share is HPKE-encrypted to the new guardian's
//!    `encryption_pubkey` (from its `GuardianInfo`), with `config_hash` as AAD,
//!    producing a `GuardianEncryptedShare` ready for `provisioner_init`.
//! 8. The share is submitted to the configured relay endpoint via
//!    `SingleProvisionerInit`. The relay rejects if the backend session no
//!    longer matches the session pinned above, otherwise it accumulates T-of-N
//!    shares and calls the guardian's batch `provisioner_init` once it has
//!    enough.

use anyhow::Context;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianEncryptedShare;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::proto_conversions::guardian_encrypted_share_to_pb;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::Config;
use crate::kp_roster::VerifiedCeremonyState;
use crate::kp_roster::decrypt_share;
use crate::kp_roster::ensure_cert_in_roster;

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = cfg.guardian_s3.resolve().await?;

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        num_shares = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        relay_endpoint = %cfg.relay_endpoint,
        "running provision flow",
    );

    // One reader for the whole run: it owns the S3 client and the trusted-key
    // cache, so each session's attestation is verified once whichever check
    // reads that session first.
    info!(
        phase = "s3 connect",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        current_git_revision = %cfg.kp_roster.pcr_allowlist.current_build().git_revision(),
        current_pcr0 = hex::encode(cfg.kp_roster.pcr_allowlist.current_build().pcr0()),
        prev_build_count = cfg.kp_roster.pcr_allowlist.prev_builds().len(),
        "connecting to guardian log bucket",
    );
    let allowlist = cfg.kp_roster.pcr_allowlist();
    let mut reader = GuardianReader::new(&guardian_s3, allowlist.clone())
        .await
        .context("connect to guardian log bucket")?;
    info!(phase = "s3 connect", "connected to guardian log bucket");

    info!(
        phase = "sui connect",
        sui_rpc = %cfg.hashi.sui_rpc,
        package_id = %cfg.hashi.hashi_ids.package_id,
        hashi_object_id = %cfg.hashi.hashi_ids.hashi_object_id,
        "connecting to Sui RPC for Hashi on-chain state",
    );
    let onchain_state = cfg.hashi.onchain_state().await?;
    info!(phase = "sui connect", "connected to Sui RPC");

    let master_g = onchain_state.onchain_verifying_key_g()?;
    info!(phase = "setup", master_g = ?master_g, "fetched on-chain MPC master G");

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

    let kp_pgp_cert_path = cfg.require_kp_pgp_cert_path("key-provisioner provision")?;
    let kp_cert = PgpPublicCert::new(
        std::fs::read_to_string(kp_pgp_cert_path)
            .with_context(|| format!("read KP cert at {}", kp_pgp_cert_path.display()))?,
    )
    .with_context(|| format!("invalid PGP cert at {}", kp_pgp_cert_path.display()))?;
    let want_fp = kp_cert.fingerprint();
    info!(
        phase = "setup",
        fingerprint = %want_fp,
        kp_cert_path = %kp_pgp_cert_path.display(),
        "loaded this KP's cert",
    );
    ensure_cert_in_roster(&kp_cert, &certs)?;

    // 1. Ask the relay/standby endpoint which session KPs are provisioning.
    // Active guardian heartbeats may still exist, so identity comes from the
    // endpoint KPs will submit to rather than from S3 heartbeat discovery.
    info!(
        phase = "guardian endpoint",
        endpoint = %cfg.relay_endpoint,
        "fetching + verifying relay endpoint GuardianInfo",
    );
    let endpoint_verified =
        verified_endpoint_guardian_info(&cfg.relay_endpoint, allowlist.current_build()).await?;
    let session_id = endpoint_verified.session_id;
    let guardian_info = endpoint_verified.info;
    info!(
        phase = "guardian endpoint",
        session_id = %session_id,
        "relay endpoint GuardianInfo verified; pinned standby session",
    );

    // 2. Check B — fetch + verify the same session's signed `GuardianInfo` from S3.
    info!(
        phase = "guardian info",
        session_id = %session_id,
        "fetching + verifying pinned standby session's signed GuardianInfo from S3",
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    anyhow::ensure!(
        verified_session.info == guardian_info,
        "S3 GuardianInfo mismatch for session {}: endpoint {:?}, S3 {:?}",
        session_id,
        guardian_info,
        verified_session.info
    );
    let GuardianInfo {
        secret_sharing_instance,
        bucket_info,
        encryption_pubkey: enclave_enc_pubkey_bytes,
        config_hash,
        state_hash: enclave_state_hash,
        untrusted_git_revision: enclave_git_revision,
        enclave_btc_pubkey,
        limiter_state: enclave_limiter_state,
        limiter_config,
        current_committee_epoch: enclave_current_committee_epoch,
        mpc_master_g,
    } = &guardian_info;
    let enclave_ss_instance = secret_sharing_instance
        .as_ref()
        .context("Guardian info missing secret_sharing_instance")?;
    let enclave_bucket_info = bucket_info
        .as_ref()
        .context("Guardian info missing bucket_info")?;
    let enclave_config_hash = config_hash
        .as_ref()
        .copied()
        .context("Guardian info missing config_hash")?;
    let enclave_limiter_config = limiter_config
        .as_ref()
        .copied()
        .context("Guardian info missing limiter_config")?;
    let enclave_mpc_master_g = mpc_master_g
        .as_ref()
        .context("Guardian info missing mpc_master_g")?;
    info!(
        phase = "guardian info",
        session_id = %session_id,
        bucket = %enclave_bucket_info.bucket,
        region = %enclave_bucket_info.region,
        enc_pubkey = hex::encode(enclave_enc_pubkey_bytes),
        config_hash = hex::encode(enclave_config_hash),
        btc_pubkey_set = enclave_btc_pubkey.is_some(),
        limiter_refill_rate = enclave_limiter_config.refill_rate,
        limiter_max_capacity = enclave_limiter_config.max_bucket_capacity,
        verified_git_revision = %enclave_git_revision,
        "guardian info verified against current build; cross-checking against config",
    );
    anyhow::ensure!(
        enclave_git_revision == allowlist.current_build().git_revision(),
        "Guardian git revision mismatch: expected {}, got {}",
        allowlist.current_build().git_revision(),
        enclave_git_revision
    );
    anyhow::ensure!(
        &guardian_s3.bucket_info == enclave_bucket_info,
        "Guardian bucket info mismatch: expected {:?}, got {:?}",
        guardian_s3.bucket_info,
        enclave_bucket_info
    );
    anyhow::ensure!(
        cfg.limiter_config == enclave_limiter_config,
        "Guardian limiter config mismatch: expected {:?}, got {:?}",
        cfg.limiter_config,
        enclave_limiter_config
    );
    anyhow::ensure!(
        enclave_btc_pubkey.is_none(),
        "Guardian has a BTC pubkey => provisioner init over"
    );
    anyhow::ensure!(
        enclave_state_hash.is_none(),
        "Guardian has state_hash => operator activation already ran"
    );
    anyhow::ensure!(
        enclave_limiter_state.is_none(),
        "Guardian has limiter_state => operator activation already ran"
    );
    anyhow::ensure!(
        enclave_current_committee_epoch.is_none(),
        "Guardian has current_committee_epoch => operator activation already ran"
    );
    anyhow::ensure!(
        &master_g == enclave_mpc_master_g,
        "MPC master g mismatch: expected {:?}, got {:?}",
        master_g,
        enclave_mpc_master_g
    );
    info!(
        phase = "guardian info",
        session_id = %session_id,
        "guardian info checks passed (bucket, limiter config, mpc_master_g, standby not activated)",
    );

    // 3. Confirm the new guardian was booted with the same secret-sharing
    //    instance the authoritative `ceremony/` log records.
    info!(
        phase = "ceremony instance",
        "scraping authoritative ceremony/ log for the secret-sharing instance",
    );
    let (ceremony_session, scraped_instance, roster, btc_master_pubkey) = reader
        .read_latest_ceremony(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    let sharing_seq = scraped_instance.sharing_seq();
    info!(
        phase = "ceremony instance",
        ceremony_session = %ceremony_session,
        sharing_seq,
        n = scraped_instance.num_shares(),
        t = scraped_instance.threshold(),
        roster_len = roster.len(),
        "scraped latest ceremony entry",
    );
    anyhow::ensure!(
        scraped_instance == *enclave_ss_instance,
        "Enclave secret sharing instance mismatch: expected {:?}, got {:?}",
        scraped_instance,
        enclave_ss_instance
    );
    info!(
        phase = "ceremony instance",
        ceremony_session = %ceremony_session,
        sharing_seq,
        "ceremony instance matches enclave",
    );

    // 4. Check C — recompute the stable config the operator armed the enclave
    //    with; its digest is the `config_hash` we bind as the share's AAD.
    info!(
        phase = "config hash",
        "recomputing config_hash from S3 bucket + limiter config + master G",
    );
    let expected_config = InitConfig::new(
        guardian_s3.bucket_info.clone(),
        cfg.limiter_config,
        master_g,
        allowlist.clone(),
        cfg.bitcoin_network,
    )?;
    let config_hash = expected_config.digest();
    anyhow::ensure!(
        config_hash == enclave_config_hash,
        "config_hash mismatch: expected {}, got {}",
        hex::encode(config_hash),
        hex::encode(enclave_config_hash)
    );
    info!(
        phase = "config hash",
        config_hash = hex::encode(config_hash),
        "recomputed config_hash matches enclave",
    );

    // 5. Check D — read + verify this KP's encrypted share. The ceremony state
    //    is constructed directly from the S3 log reads above so we don't pay
    //    for a second ceremony/ + shares/ walk.
    info!(
        phase = "share read",
        ceremony_session = %ceremony_session,
        sharing_seq,
        "reading + verifying this KP's encrypted share from shares/",
    );
    let encrypted_shares = reader
        .read_shares(&ceremony_session, sharing_seq, BuildPolicy::AnyAllowlisted)
        .await?;
    let state = VerifiedCeremonyState::from_scraped(
        ceremony_session.clone(),
        scraped_instance.clone(),
        encrypted_shares,
        &roster,
        btc_master_pubkey,
        cfg.kp_roster.num_shares,
        cfg.kp_roster.threshold,
    )?;
    state.verify_encrypted_share_recipients(&certs)?;
    info!(
        phase = "share read",
        share_count = state.encrypted_shares.len(),
        roster_matches = true,
        all_recipients_verified = true,
        "shares/ log verified: every share is addressed only to its labeled KP cert",
    );

    // Find this KP's share by exact fingerprint match. Given the roster checks
    // above, this should always succeed; keep the error for defensive clarity.
    let kp_encrypted_share = state
        .encrypted_shares
        .iter()
        .find(|s| s.recipient_fingerprint == want_fp)
        .ok_or_else(|| {
            anyhow::anyhow!(
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
        phase = "share read",
        share_id = kp_encrypted_share.id.get(),
        fingerprint = %kp_encrypted_share.recipient_fingerprint,
        "located this KP's encrypted share",
    );

    // 6. Decrypt via yubikey (gpg streams plaintext over a pipe — never hits
    //    disk) and verify the decrypted share matches its commitment.
    info!(
        phase = "share decrypt",
        share_id = kp_encrypted_share.id.get(),
        "decrypting share via yubikey (ciphertext piped via stdin; plaintext in memory)",
    );
    let decrypted = decrypt_share(kp_encrypted_share)?;
    state
        .secret_sharing_instance
        .commitments()
        .verify_share(&decrypted)
        .context("decrypted share does not match its commitment")?;
    let expected_commitment = state
        .secret_sharing_instance
        .commitments()
        .iter()
        .find(|c| c.id == decrypted.id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "commitment for share id {} missing despite verify_share success",
                decrypted.id
            )
        })?;
    info!(
        phase = "share decrypt",
        share_id = decrypted.id.get(),
        commitment = hex::encode(&expected_commitment.digest),
        "decrypted share matches its commitment",
    );

    // 7. HPKE-encrypt the decrypted share to the new guardian's pubkey, binding
    //    the verified `config_hash` as AAD.
    info!(
        phase = "share build",
        share_id = decrypted.id.get(),
        enc_pubkey = hex::encode(enclave_enc_pubkey_bytes),
        config_hash = hex::encode(config_hash),
        "HPKE-encrypting share to new guardian's pubkey (config_hash AAD)",
    );
    let guardian_pub_key =
        EncPubKey::from_bytes(enclave_enc_pubkey_bytes).map_err(anyhow::Error::msg)?;
    let encrypted_share = ProvisionerInitRequest::build_from_share(
        &decrypted,
        &guardian_pub_key,
        config_hash,
        &mut thread_rng(),
    );
    info!(
        phase = "share build",
        share_id = encrypted_share.id.get(),
        "built GuardianEncryptedShare ready for submission",
    );

    // 8. Submit. The relay collects T-of-N shares before forwarding them to the
    //    guardian in one `ProvisionerInit` call.
    info!(
        phase = "summary",
        session_id = %session_id,
        ceremony_session = %ceremony_session,
        share_id = decrypted.id.get(),
        fingerprint = %want_fp,
        sharing_seq,
        config_hash = hex::encode(config_hash),
        enc_pubkey = hex::encode(enclave_enc_pubkey_bytes),
        relay_endpoint = %cfg.relay_endpoint,
        "share built; submitting to relay",
    );
    submit_provisioner_init_to_relay(&cfg.relay_endpoint, &session_id, encrypted_share).await?;
    Ok(())
}

async fn verified_endpoint_guardian_info(
    endpoint: &str,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(endpoint.to_string())
            .await
            .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;
    let resp_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .with_context(|| "GetGuardianInfo RPC failed")?
        .into_inner();
    let resp = GetGuardianInfoResponse::try_from(resp_pb)?;
    resp.verify(current_build)
        .map_err(|e| anyhow::anyhow!("verify endpoint GuardianInfo: {e}"))
}

/// Submit this KP's share to the relay endpoint. The relay fronts the
/// guardian's current session and rejects `SingleProvisionerInit` if it no
/// longer matches the session this KP pinned before encrypting the share. The
/// relay collects T-of-N shares and calls the guardian's batch `provisioner_init`
/// once it has enough.
async fn submit_provisioner_init_to_relay(
    endpoint: &str,
    expected_session_id: &str,
    encrypted_share: GuardianEncryptedShare,
) -> anyhow::Result<()> {
    info!(
        phase = "relay submit",
        endpoint = %endpoint,
        "connecting to relay endpoint",
    );
    let share_id = encrypted_share.id.get();
    info!(
        phase = "relay submit",
        endpoint = %endpoint,
        share_id,
        expected_session_id = %expected_session_id,
        "submitting share via SingleProvisionerInit",
    );

    let mut relay_client = pb::guardian_relay_service_client::GuardianRelayServiceClient::connect(
        endpoint.to_string(),
    )
    .await
    .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;
    info!(phase = "relay submit", endpoint = %endpoint, "connected to relay");
    let resp = relay_client
        .single_provisioner_init(pb::SingleProvisionerInitRequest {
            encrypted_share: Some(guardian_encrypted_share_to_pb(encrypted_share)),
            expected_session_id: expected_session_id.to_string(),
        })
        .await
        .with_context(|| "SingleProvisionerInit RPC failed")?
        .into_inner();

    if resp.completed {
        info!(
            phase = "relay submit",
            share_id, "share accepted; the relay has provisioned the guardian (threshold reached)",
        );
    } else {
        info!(
            phase = "relay submit",
            share_id,
            have = resp.have,
            need = resp.need,
            "share accepted; the relay is still collecting shares before it provisions the guardian",
        );
    }
    Ok(())
}
