// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner provision` (per-KP recovery against a fresh withdraw-mode guardian).
//!
//! Run by a key provisioner when a new guardian instance is brought up to
//! replace one that went down. The KP decrypts through their yubikey-backed gpg
//! setup; plaintext never touches disk, but the raw share scalar is held in this
//! process' memory long enough to verify and re-encrypt it. The flow:
//!
//! 1. Heartbeat audit (check A) selects the single live session.
//! 2. The new guardian's signed `GuardianInfo` is fetched from its S3 `init/`
//!    log and verified against the enclave attestation (check B). Bucket,
//!    limiter config, `mpc_master_g`, and `enclave_btc_pubkey == None` are all
//!    confirmed.
//! 3. The authoritative `ceremony/` log is scraped for the secret-sharing
//!    instance the new guardian was booted with; it must match.
//! 4. Initial limiter state is recovered from the prior enclave's max-seq
//!    Success withdrawal log (or genesis) and confirmed equal (check C).
//! 5. The committee comes from the latest signed `committee-update/` log (or
//!    on-chain Hashi state); the `state_hash` is recomputed and confirmed (check D).
//! 6. This KP's encrypted share is read from `shares/{seq}-{session}.json`
//!    (attestation-anchored), every share's recipients are verified against
//!    the roster, and this KP's share is located by fingerprint.
//! 7. The share is decrypted via the yubikey (`gpg --decrypt` over a pipe;
//!    plaintext stays in memory) and verified against its commitment.
//! 8. The decrypted share is HPKE-encrypted to the new guardian's
//!    `encryption_pubkey` (from its `GuardianInfo`), with `state_hash` as AAD,
//!    producing a `GuardianEncryptedShare` ready for `provisioner_init`.
//! 9. The share is submitted to the configured relay endpoint via
//!    `SingleProvisionerInit`, after the relay-side pre-checks pass. The relay
//!    accumulates T-of-N shares and calls the guardian's batch
//!    `provisioner_init` once it has enough.

use anyhow::Context;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianEncryptedShare;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::ProvisionerInitRequest;
use hashi_types::guardian::WithdrawModeState;
use hashi_types::guardian::proto_conversions::guardian_encrypted_share_to_pb;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::Config;
use crate::heartbeat_checks;
use crate::kp_roster::VerifiedCeremonyState;
use crate::kp_roster::decrypt_share;
use crate::kp_roster::ensure_cert_in_roster;
use crate::limiter_recovery;

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

    // 1. Check A — no past enclave's heartbeats remain & gather the latest
    //    enclave's session id.
    info!(
        phase = "heartbeat audit",
        "auditing heartbeats to select the single live session",
    );
    let session_id = heartbeat_checks::heartbeat_audit(&mut reader).await?;
    info!(
        phase = "heartbeat audit",
        session_id = %session_id,
        "selected live session",
    );

    // 2. Check B — fetch + verify the new guardian's signed `GuardianInfo`.
    info!(
        phase = "guardian info",
        session_id = %session_id,
        "fetching + verifying new guardian's signed GuardianInfo from S3",
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    let guardian_info = verified_session.info;
    let (
        enclave_ss_instance,
        enclave_bucket_info,
        enclave_enc_pubkey_bytes,
        enclave_state_hash,
        enclave_git_revision,
        enclave_btc_pubkey,
        enclave_limiter_state,
        enclave_limiter_config,
        enclave_current_committee_epoch,
        enclave_mpc_master_g,
    ) = guardian_info
        .clone()
        .into_parts()
        .context("Guardian info has missing fields")?;
    info!(
        phase = "guardian info",
        session_id = %session_id,
        bucket = %enclave_bucket_info.bucket,
        region = %enclave_bucket_info.region,
        enc_pubkey = hex::encode(&enclave_enc_pubkey_bytes),
        state_hash = hex::encode(enclave_state_hash),
        btc_pubkey_set = enclave_btc_pubkey.is_some(),
        committee_epoch = enclave_current_committee_epoch,
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
        guardian_s3.bucket_info == enclave_bucket_info,
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
        master_g == enclave_mpc_master_g,
        "MPC master g mismatch: expected {:?}, got {:?}",
        master_g,
        enclave_mpc_master_g
    );
    info!(
        phase = "guardian info",
        session_id = %session_id,
        "guardian info checks passed (bucket, limiter config, mpc_master_g, btc_pubkey=None)",
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
        scraped_instance == enclave_ss_instance,
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

    // 4. Check C — source the initial limiter state. If a prior enclave left
    //    Success withdrawal logs we recover from them; otherwise (first
    //    deployment, or a rotation where the prior enclave processed no
    //    withdrawals) we initialize from genesis.
    info!(
        phase = "limiter recovery",
        "recovering initial limiter state from prior enclave's withdraw logs",
    );
    let limiter_state = match limiter_recovery::recover_limiter_state(&mut reader).await? {
        Some(mut recovered) => {
            // Cap to the current config's bucket capacity in case max capacity
            // was lowered across the rotation. (Raising is fine — refill will
            // fill it.)
            recovered.num_tokens_available = recovered
                .num_tokens_available
                .min(cfg.limiter_config.max_bucket_capacity);
            info!(
                phase = "limiter recovery",
                source = "recovered",
                next_seq = recovered.next_seq,
                num_tokens_available = recovered.num_tokens_available,
                last_updated_at = recovered.last_updated_at,
                "recovered limiter state from prior enclave's max-seq Success log",
            );
            recovered
        }
        None => {
            info!(
                phase = "limiter recovery",
                source = "genesis",
                "no prior Success withdrawal logs found; initializing limiter from genesis",
            );
            LimiterState::genesis(&cfg.limiter_config)
        }
    };
    anyhow::ensure!(
        limiter_state == enclave_limiter_state,
        "limiter state mismatch: expected {:?}, got {:?}",
        limiter_state,
        enclave_limiter_state
    );
    info!(
        phase = "limiter recovery",
        next_seq = limiter_state.next_seq,
        num_tokens_available = limiter_state.num_tokens_available,
        "recovered limiter state matches enclave",
    );

    // 5. Check D — recompute the init state the operator booted the enclave
    //    with; its digest is the `state_hash` we bind as the share's AAD. The
    //    committee comes from the latest signed `committee-update/` log or,
    //    before any update exists, from authoritative on-chain Hashi state.
    info!(
        phase = "state hash",
        "recomputing state_hash from committee + limiter + master_g",
    );
    let committee = match reader
        .read_latest_committee(BuildPolicy::AnyAllowlisted)
        .await?
    {
        Some(scraped) => {
            info!(
                phase = "state hash",
                epoch = scraped.epoch,
                source = "committee-update log",
                "scraped latest committee-update log",
            );
            scraped.try_into()?
        }
        None => {
            let committee = onchain_state
                .current_committee()
                .context("no current committee on chain (DKG not yet complete?)")?;
            info!(
                phase = "state hash",
                epoch = committee.epoch(),
                source = "on-chain Hashi state",
                "no committee-update log; falling back to on-chain current committee",
            );
            committee
        }
    };
    anyhow::ensure!(
        committee.epoch() == enclave_current_committee_epoch,
        "committee epoch mismatch: expected {}, got {}",
        committee.epoch(),
        enclave_current_committee_epoch
    );
    let committee_epoch = committee.epoch();
    let expected_state =
        WithdrawModeState::new(committee, cfg.limiter_config, limiter_state, master_g)?;
    let state_hash = expected_state.digest();
    anyhow::ensure!(
        state_hash == enclave_state_hash,
        "state_hash mismatch: expected {}, got {}",
        hex::encode(state_hash),
        hex::encode(enclave_state_hash)
    );
    info!(
        phase = "state hash",
        committee_epoch = committee_epoch,
        state_hash = hex::encode(state_hash),
        "recomputed state_hash matches enclave",
    );

    // 6. Check E — read + verify this KP's encrypted share. The ceremony state
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

    // 7. Decrypt via yubikey (gpg streams plaintext over a pipe — never hits
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

    // 8. HPKE-encrypt the decrypted share to the new guardian's pubkey, binding
    //    the verified `state_hash` as AAD.
    info!(
        phase = "share build",
        share_id = decrypted.id.get(),
        enc_pubkey = hex::encode(&enclave_enc_pubkey_bytes),
        state_hash = hex::encode(state_hash),
        "HPKE-encrypting share to new guardian's pubkey (state_hash AAD)",
    );
    let guardian_pub_key =
        EncPubKey::from_bytes(&enclave_enc_pubkey_bytes).map_err(anyhow::Error::msg)?;
    let encrypted_share = ProvisionerInitRequest::build_from_share(
        &decrypted,
        &guardian_pub_key,
        state_hash,
        &mut thread_rng(),
    );
    info!(
        phase = "share build",
        share_id = encrypted_share.id.get(),
        "built GuardianEncryptedShare ready for submission",
    );

    // 9. Submit. The relay collects T-of-N shares before forwarding them to the
    //    guardian in one `ProvisionerInit` call.
    info!(
        phase = "summary",
        session_id = %session_id,
        ceremony_session = %ceremony_session,
        share_id = decrypted.id.get(),
        fingerprint = %want_fp,
        sharing_seq,
        state_hash = hex::encode(state_hash),
        enc_pubkey = hex::encode(&enclave_enc_pubkey_bytes),
        relay_endpoint = %cfg.relay_endpoint,
        "share built; submitting to relay",
    );
    submit_provisioner_init_to_relay(
        &cfg.relay_endpoint,
        &session_id,
        guardian_info,
        encrypted_share,
        allowlist.current_build(),
    )
    .await?;
    Ok(())
}

/// Submit this KP's share to the relay endpoint. The relay fronts the
/// guardian's `GetGuardianInfo`, so we verify the relay's reported session +
/// `GuardianInfo` against the values we already pinned from S3 before submitting
/// the share via `SingleProvisionerInit`. The relay collects T-of-N shares and
/// calls the guardian's batch `provisioner_init` once it has enough.
async fn submit_provisioner_init_to_relay(
    endpoint: &str,
    expected_session_id: &str,
    expected_guardian_info: GuardianInfo,
    encrypted_share: GuardianEncryptedShare,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
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
        expected_guardian_info,
        current_build,
    )
    .await
    .with_context(|| "relay endpoint pre-check failed")?;
    let share_id = encrypted_share.id.get();
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

async fn prechecks(
    client: &mut pb::guardian_service_client::GuardianServiceClient<tonic::transport::Channel>,
    expected_session_id: &str,
    expected_guardian_info: GuardianInfo,
    current_build: &BuildPcrs,
) -> anyhow::Result<()> {
    let resp_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .with_context(|| "GetGuardianInfo RPC failed")?
        .into_inner();

    let resp = GetGuardianInfoResponse::try_from(resp_pb)?;

    let verified = resp.verify(current_build)?;
    let actual_session_id = verified.session_id;
    info!(
        phase = "relay submit",
        actual_session_id = %actual_session_id,
        expected_session_id = %expected_session_id,
        "relay returned GuardianInfo; verifying attestation + signature + session match",
    );

    anyhow::ensure!(
        actual_session_id == expected_session_id,
        "relay endpoint session mismatch: expected {}, got {}",
        expected_session_id,
        actual_session_id
    );
    anyhow::ensure!(
        verified.info == expected_guardian_info,
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
