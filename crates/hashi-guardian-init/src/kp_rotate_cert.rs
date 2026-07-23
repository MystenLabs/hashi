// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner rotate-cert` replaces one certificate in a KP roster entry
//! while preserving every other encrypted copy of that KP's share.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::ProvisionerRotateCertResponse;
use hashi_types::guardian::WithdrawStage;
use hashi_types::proto as pb;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::verified_live_guardian_info;
use crate::kp_roster::decrypt_kp_share_copies;
use crate::kp_roster::load_kp_cert;

pub async fn run(
    cfg: Config,
    target_kp_pgp_fingerprint: String,
    new_kp_pgp_cert_path: PathBuf,
) -> anyhow::Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = cfg.guardian_s3.resolve().await?;
    let allowlist = cfg.kp_roster.pcr_allowlist();
    let certs_roster = cfg.kp_roster.load_certs_roster()?;

    let signing_cert = load_kp_cert(cfg.require_kp_pgp_cert_path("key-provisioner rotate-cert")?)?;
    let new_cert = load_kp_cert(&new_kp_pgp_cert_path).with_context(|| {
        format!(
            "load replacement KP cert at {}",
            new_kp_pgp_cert_path.display()
        )
    })?;
    let signing_fingerprint = signing_cert.fingerprint();
    let signing_fingerprint_hex = signing_fingerprint.to_hex();
    let signing_entry = certs_roster
        .certs_for_fingerprint(&signing_fingerprint)
        .with_context(|| {
            format!(
                "signing KP cert fingerprint {signing_fingerprint} is not among the configured \
                 kp_roster.kp_pgp_cert_paths"
            )
        })?;
    let requested_target_fingerprint = target_kp_pgp_fingerprint.trim().to_ascii_uppercase();
    let target_cert = signing_entry
        .pgp_certs()
        .iter()
        .find(|cert| cert.fingerprint().to_hex() == requested_target_fingerprint)
        .with_context(|| {
            format!(
                "target KP fingerprint {requested_target_fingerprint} does not belong to the \
                 signing cert's KP entry; available fingerprints: {:?}",
                signing_entry.fingerprints()
            )
        })?;
    let target_fingerprint = target_cert.fingerprint();
    let target_fingerprint_hex = target_fingerprint.to_hex();
    let new_fingerprint = new_cert.fingerprint().to_hex();
    let expected_certs_roster = certs_roster
        .clone()
        .replace_cert(&target_fingerprint, new_cert.clone())
        .context("replace the target cert in the expected KP certificate roster")?;

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        relay_endpoint = %cfg.relay_endpoint,
        signing_fingerprint = %signing_fingerprint_hex,
        target_fingerprint = %target_fingerprint_hex,
        new_fingerprint = %new_fingerprint,
        "running individual KP certificate rotation",
    );

    let mut reader = GuardianReader::new(&guardian_s3, allowlist.clone())
        .await
        .context("connect to guardian log bucket")?;
    let mut client =
        pb::guardian_service_client::GuardianServiceClient::connect(cfg.relay_endpoint.clone())
            .await
            .with_context(|| {
                format!("failed to connect to relay endpoint {}", cfg.relay_endpoint)
            })?;
    let endpoint_verified = verified_live_guardian_info(&mut client, allowlist.current_build())
        .await
        .with_context(|| format!("verify active GuardianInfo at {}", cfg.relay_endpoint))?;
    anyhow::ensure!(
        endpoint_verified.info.lifecycle == WithdrawStage::Activated.into(),
        "Guardian lifecycle is {:?}; expected withdraw/activated",
        endpoint_verified.info.lifecycle
    );
    let session_id = endpoint_verified.session_id;
    let signing_pub_key = endpoint_verified.signing_pub_key;
    let endpoint_bucket_info = endpoint_verified
        .info
        .bucket_info
        .as_ref()
        .context("active GuardianInfo missing bucket_info")?;
    anyhow::ensure!(
        &guardian_s3.bucket_info == endpoint_bucket_info,
        "Guardian bucket info mismatch: expected {:?}, got {:?}",
        guardian_s3.bucket_info,
        endpoint_bucket_info
    );
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    anyhow::ensure!(
        verified_session.signing_pubkey == signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    anyhow::ensure!(
        verified_session.info.bucket_info.as_ref() == Some(endpoint_bucket_info),
        "guardian S3 session bucket info differs from live GuardianInfo"
    );
    let endpoint_btc_pubkey = endpoint_verified
        .info
        .enclave_btc_pubkey
        .as_ref()
        .context("active GuardianInfo missing enclave_btc_pubkey")?;
    let guardian_pub_key = EncPubKey::from_bytes(&endpoint_verified.info.encryption_pubkey)
        .map_err(anyhow::Error::msg)?;

    let state = reader
        .read_latest_ceremony_state(BuildPolicy::AnyAllowlisted)
        .await?
        .context("no ceremony log found in S3; key setup has not run")?;
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    anyhow::ensure!(
        &state.btc_master_pubkey == endpoint_btc_pubkey,
        "active guardian BTC pubkey differs from latest ceremony log: active \
         {endpoint_btc_pubkey:?}, latest {:?}",
        state.btc_master_pubkey
    );
    let sharing_seq = state.secret_sharing_instance.sharing_seq();

    state.encrypted_shares.verify_recipients(&certs_roster)?;
    let old_cert_seq = state.cert_seq;
    let old_encrypted_shares = state.encrypted_shares.clone();
    let decrypted = decrypt_kp_share_copies(&state, std::slice::from_ref(&signing_cert))?;

    let request = ProvisionerRotateCertRequest::new(
        session_id.clone(),
        old_cert_seq,
        target_fingerprint_hex.clone(),
        new_cert,
        &decrypted,
        &guardian_pub_key,
        &mut thread_rng(),
    );
    let signed_request = KpSigned::new(request, signing_cert, None)
        .context("sign the certificate-rotation request with the authorizing KP key")?;
    let response_pb = client
        .provisioner_rotate_cert(pb::SignedProvisionerRotateCertRequest::from(signed_request))
        .await
        .context("ProvisionerRotateCert RPC failed")?
        .into_inner();
    let signed_response = GuardianSigned::<ProvisionerRotateCertResponse>::try_from(response_pb)
        .map_err(|e| anyhow!("decode SignedProvisionerRotateCertResponse: {e:?}"))?;
    let response = signed_response
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify ProvisionerRotateCertResponse signature: {e:?}"))?;
    let expected_cert_seq = old_cert_seq.checked_add(1).context("cert_seq overflow")?;
    anyhow::ensure!(
        response.cert_seq == expected_cert_seq,
        "ProvisionerRotateCert returned cert_seq {}, expected {}",
        response.cert_seq,
        expected_cert_seq
    );
    anyhow::ensure!(
        response.encrypted_shares.id == decrypted.id,
        "ProvisionerRotateCert returned share id {}, expected {}",
        response.encrypted_shares.id.get(),
        decrypted.id.get()
    );
    let expected_certs = expected_certs_roster
        .certs_for_share(decrypted.id)
        .context("rotated share id missing from expected KP certificate roster")?;
    response
        .encrypted_shares
        .verify_recipients(expected_certs)
        .context("verify the rotated KP entry returned by the guardian")?;

    let replacement_ciphertext = response
        .encrypted_shares
        .ciphertexts_by_fingerprint
        .get(&new_fingerprint)
        .expect("the rotated entry was verified against the replacement cert roster")
        .clone();
    let (expected_encrypted_shares, expected_changed_entry) = old_encrypted_shares
        .replace_recipient(
            &target_fingerprint_hex,
            new_fingerprint.clone(),
            replacement_ciphertext,
        )?;
    anyhow::ensure!(
        response.encrypted_shares == expected_changed_entry,
        "ProvisionerRotateCert response changed ciphertexts other than the requested certificate"
    );

    let updated_state = reader
        .read_kp_share_state_log(
            &session_id,
            sharing_seq,
            response.cert_seq,
            BuildPolicy::Current,
        )
        .await
        .context("read the certificate-rotation kp-shares snapshot")?;
    updated_state
        .encrypted_shares
        .verify_recipients(&expected_certs_roster)
        .context("verify persisted kp-shares snapshot against the rotated certificate roster")?;
    anyhow::ensure!(
        updated_state.encrypted_shares == expected_encrypted_shares,
        "persisted kp-shares snapshot changed entries other than the requested certificate rotation"
    );

    println!(
        "KP certificate rotation complete: sharing_seq={}, cert_seq={}, share_id={}, \
         signing_fingerprint={}, target_fingerprint={}, new_fingerprint={}",
        sharing_seq,
        response.cert_seq,
        response.encrypted_shares.id.get(),
        signing_fingerprint_hex,
        target_fingerprint_hex,
        new_fingerprint
    );
    Ok(())
}
