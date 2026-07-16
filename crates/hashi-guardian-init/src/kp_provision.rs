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
//! 4. The stable `InitConfig` is recomputed from limiter config, master G, PCR
//!    allowlist, and network; its `config_hash` is confirmed.
//! 5. This KP's encrypted share is read from the latest `kp-shares/{seq}/`
//!    state (attestation-anchored), every share's recipients are verified
//!    against the roster, and this KP's share is located by fingerprint.
//! 6. The share is decrypted via the yubikey (`gpg --decrypt` over a pipe;
//!    plaintext stays in memory) and verified against its commitment.
//! 7. The decrypted share is HPKE-encrypted to the new guardian's
//!    `encryption_pubkey` (from its `GuardianInfo`) while constructing a PI
//!    request bound to the pinned session and verified `config_hash`.
//! 8. The request is signed and submitted to the configured relay endpoint via
//!    `SingleProvisionerInit`. The relay accumulates T-of-N signed submissions
//!    and calls the guardian's batch `provisioner_init` once it has enough; the
//!    enclave re-verifies every signature and binding.

use anyhow::Context;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::InitConfig;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::SingleProvisionerInitRequest;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::WithdrawStage;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::ensure_oi_info_matches_post_init;
use crate::guardian_info::verified_live_guardian_info;
use crate::kp_roster::decrypt_share;
use crate::kp_roster::ensure_cert_in_roster;
use crate::kp_roster::verify_encrypted_share_recipients;

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

    // 2. Fetch + verify the same session's signed `GuardianInfo` from S3.
    info!(
        phase = "guardian info",
        session_id = %session_id,
        "fetching + verifying pinned standby session's signed GuardianInfo from S3",
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    let GuardianInfo {
        lifecycle,
        secret_sharing_instance,
        bucket_info,
        encryption_pubkey: enclave_enc_pubkey_bytes,
        config_hash,
        untrusted_git_revision: enclave_git_revision,
        enclave_btc_pubkey,
        limiter_state: enclave_limiter_state,
        limiter_config,
        current_committee_epoch: enclave_current_committee_epoch,
        mpc_master_g,
    } = &guardian_info;
    anyhow::ensure!(
        *lifecycle == WithdrawStage::OperatorInitialized.into(),
        "Guardian lifecycle is {lifecycle:?}; expected withdraw/operator_initialized"
    );
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
        enclave_limiter_state.is_none(),
        "Guardian has limiter_state => operator activation already ran"
    );
    anyhow::ensure!(
        enclave_current_committee_epoch.is_none(),
        "Guardian has current_committee_epoch => operator activation already ran"
    );
    let oi_info = verified_session.info;
    ensure_oi_info_matches_post_init(&oi_info, &guardian_info)
        .with_context(|| format!("S3 GuardianInfo mismatch for session {session_id}"))?;
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

    // 3. Read the ceremony + KP share state and confirm the new guardian was
    //    booted with the same secret-sharing instance.
    info!(
        phase = "ceremony instance",
        "scraping authoritative ceremony/ and kp-shares/ logs",
    );
    let state = reader
        .read_latest_ceremony_state(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    let sharing_seq = state.secret_sharing_instance.sharing_seq();
    info!(
        phase = "ceremony instance",
        sharing_seq,
        n = state.secret_sharing_instance.num_shares(),
        t = state.secret_sharing_instance.threshold(),
        "scraped latest ceremony entry",
    );
    anyhow::ensure!(
        state.secret_sharing_instance == *enclave_ss_instance,
        "Enclave secret sharing instance mismatch: expected {:?}, got {:?}",
        state.secret_sharing_instance,
        enclave_ss_instance
    );
    info!(
        phase = "ceremony instance",
        sharing_seq, "ceremony instance matches enclave",
    );

    // 4. Recompute the stable config the operator armed the enclave with; its
    //    digest is the `config_hash` bound into the signed PI submission.
    info!(
        phase = "config hash",
        "recomputing config_hash from limiter config + master G + PCR allowlist + network",
    );
    let expected_config = InitConfig::new(
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

    // 5. Verify this KP's encrypted share from the ceremony + KP-share state
    //    read above.
    info!(
        phase = "share read",
        sharing_seq, "verifying this KP's encrypted share from kp-shares/",
    );
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    verify_encrypted_share_recipients(&state, &certs)?;
    info!(
        phase = "share read",
        cert_seq = state.cert_seq,
        share_count = state.encrypted_shares.len(),
        all_recipients_verified = true,
        "kp-shares log verified: every share is addressed only to its labeled KP cert",
    );

    // Find this KP's share by exact fingerprint match. Given the roster checks
    // above, this should always succeed; keep the error for defensive clarity.
    let want_fp_hex = want_fp.to_hex();
    let kp_encrypted_share = state
        .encrypted_shares
        .iter()
        .find(|s| s.recipient_fingerprint == want_fp_hex)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no share in the kp-shares log is labeled for this KP's fingerprint \
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

    // 7. HPKE-encrypt the decrypted share to the new guardian's pubkey. The
    //    signed relay request below binds it to the verified config hash.
    info!(
        phase = "share build",
        share_id = decrypted.id.get(),
        enc_pubkey = hex::encode(enclave_enc_pubkey_bytes),
        config_hash = hex::encode(config_hash),
        "HPKE-encrypting share to new guardian's pubkey",
    );
    let guardian_pub_key =
        EncPubKey::from_bytes(enclave_enc_pubkey_bytes).map_err(anyhow::Error::msg)?;
    let request = SingleProvisionerInitRequest::build_from_share(
        session_id.clone(),
        config_hash,
        &decrypted,
        &guardian_pub_key,
        &mut thread_rng(),
    );
    info!(
        phase = "share build",
        share_id = request.encrypted_share().id.get(),
        "built SingleProvisionerInitRequest ready for signing",
    );

    // 8. Submit. The relay collects T-of-N shares before forwarding them to the
    //    guardian in one `ProvisionerInit` call.
    info!(
        phase = "summary",
        session_id = %session_id,
        share_id = decrypted.id.get(),
        fingerprint = %want_fp,
        sharing_seq,
        config_hash = hex::encode(config_hash),
        enc_pubkey = hex::encode(enclave_enc_pubkey_bytes),
        relay_endpoint = %cfg.relay_endpoint,
        "share built; submitting to relay",
    );
    submit_provisioner_init_to_relay(
        &cfg.relay_endpoint,
        guardian_info,
        request,
        &kp_cert,
        allowlist.current_build(),
    )
    .await?;
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
    verified_live_guardian_info(&mut client, current_build)
        .await
        .with_context(|| format!("verify relay endpoint GuardianInfo at {endpoint}"))
}

/// Submit this KP's share to the relay endpoint. The relay fronts the
/// guardian's current session and rejects `SingleProvisionerInit` if it no
/// longer matches the session or config this KP signed. The relay collects
/// T-of-N submissions and calls the guardian's batch `provisioner_init` once it
/// has enough; the guardian re-verifies every signature.
async fn submit_provisioner_init_to_relay(
    endpoint: &str,
    expected_guardian_info: GuardianInfo,
    request: SingleProvisionerInitRequest,
    signer_cert: &PgpPublicCert,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
    let expected_session_id = request.expected_session_id();
    info!(
        phase = "relay submit",
        endpoint = %endpoint,
        "connecting to relay endpoint",
    );
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(endpoint.to_string())
            .await
            .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;
    info!(phase = "relay submit", endpoint = %endpoint, "connected to relay");

    info!(
        phase = "relay submit",
        endpoint = %endpoint,
        expected_session_id = %expected_session_id,
        "running relay-side prechecks (GetGuardianInfo + session pin + GuardianInfo match)",
    );
    prechecks(
        &mut client,
        expected_session_id,
        &expected_guardian_info,
        current_build,
    )
    .await
    .with_context(|| "relay endpoint pre-check failed")?;
    let share_id = request.encrypted_share().id.get();
    info!(
        phase = "relay submit",
        endpoint = %endpoint,
        share_id,
        "relay prechecks passed; submitting share via SingleProvisionerInit",
    );

    let mut relay_client = pb::guardian_relay_service_client::GuardianRelayServiceClient::connect(
        endpoint.to_string(),
    )
    .await
    .with_context(|| format!("failed to connect to relay endpoint {endpoint}"))?;

    // Detached-sign the exact (session, config, share) bytes with this KP's
    // offline key. The relay pre-verifies the request before buffering it and
    // the enclave authoritatively re-verifies it before using the share.
    let signed_request = KpSigned::new(request, signer_cert.clone(), None)
        .map_err(anyhow::Error::msg)
        .context("sign the relay submission with the KP key")?;
    let resp = relay_client
        .single_provisioner_init(pb::SignedSingleProvisionerInitRequest::from(signed_request))
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

async fn prechecks(
    client: &mut pb::guardian_service_client::GuardianServiceClient<tonic::transport::Channel>,
    expected_session_id: &str,
    expected_guardian_info: &GuardianInfo,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
    let verified = verified_live_guardian_info(client, current_build).await?;
    let actual_session_id = verified.session_id;
    info!(
        phase = "relay submit",
        actual_session_id = %actual_session_id,
        expected_session_id = %expected_session_id,
        "relay returned GuardianInfo; verifying attestation + signature + session match",
    );

    anyhow::ensure!(
        actual_session_id.as_str() == expected_session_id,
        "relay endpoint session mismatch: expected {}, got {}",
        expected_session_id,
        actual_session_id
    );
    anyhow::ensure!(
        &verified.info == expected_guardian_info,
        "relay endpoint GuardianInfo mismatch: expected {:?}, got {:?}",
        expected_guardian_info,
        verified.info
    );
    info!(
        phase = "relay submit",
        session_id = %actual_session_id,
        "relay GuardianInfo matches expected (attestation, signature, session, fields)",
    );

    Ok(())
}
