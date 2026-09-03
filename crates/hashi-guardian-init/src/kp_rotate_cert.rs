// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner rotate-cert` replaces this KP's configured signing
//! certificate while preserving every other KP's encrypted share.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::anyhow;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::GuardianSignedResponse;
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
use crate::kp_roster::decrypt_kp_share;
use crate::kp_roster::load_kp_cert;

pub async fn run(cfg: Config, new_kp_pgp_cert_path: PathBuf) -> anyhow::Result<()> {
    cfg.kp_roster.validate()?;
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;
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
    certs_roster
        .cert_for_fingerprint(&signing_fingerprint)
        .with_context(|| {
            format!(
                "signing KP cert fingerprint {signing_fingerprint} is not among the configured \
                 kp_roster.kp_pgp_cert_paths"
            )
        })?;
    let new_fingerprint = new_cert.fingerprint().to_hex();
    let expected_certs_roster = certs_roster
        .replace_cert(&signing_fingerprint, new_cert.clone())
        .context("replace the signing cert in the expected KP certificate roster")?;

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        relay_endpoint = %cfg.relay_endpoint,
        signing_fingerprint = %signing_fingerprint_hex,
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
    let verified_session = reader.get_current_session_info(&session_id).await?;
    anyhow::ensure!(
        verified_session.signing_pubkey() == &signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    anyhow::ensure!(
        verified_session.info().bucket_info.as_ref() == Some(endpoint_bucket_info),
        "guardian S3 session bucket info differs from live GuardianInfo"
    );
    let endpoint_btc_pubkey = endpoint_verified
        .info
        .enclave_btc_pubkey
        .as_ref()
        .context("active GuardianInfo missing enclave_btc_pubkey")?;
    let guardian_pub_key = EncPubKey::from_bytes(&endpoint_verified.info.encryption_pubkey)
        .map_err(anyhow::Error::msg)?;

    let state = reader.read_latest_ceremony_state().await?;
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
    let decrypted = decrypt_kp_share(&state, &signing_cert)?;

    let request = ProvisionerRotateCertRequest::new(
        session_id.clone(),
        old_cert_seq,
        new_cert,
        &decrypted,
        &guardian_pub_key,
        &mut thread_rng(),
    );
    let signed_request = KpSigned::sign(request, signing_cert, None)
        .context("sign the certificate-rotation request with the authorizing KP key")?;
    let response_pb = client
        .provisioner_rotate_cert(pb::SignedProvisionerRotateCertRequest::from(signed_request))
        .await
        .context("ProvisionerRotateCert RPC failed")?
        .into_inner();
    let signed_response =
        GuardianSignedResponse::<ProvisionerRotateCertResponse>::try_from(response_pb)
            .map_err(|e| anyhow!("decode SignedProvisionerRotateCertResponse: {e:?}"))?;
    let ProvisionerRotateCertResponse {
        cert_seq,
        encrypted_share,
    } = signed_response
        .verify_into_data(&signing_pub_key)
        .map_err(|e| anyhow!("verify ProvisionerRotateCertResponse signature: {e}"))?
        .response;
    let expected_cert_seq = old_cert_seq.checked_add(1).context("cert_seq overflow")?;
    anyhow::ensure!(
        cert_seq == expected_cert_seq,
        "ProvisionerRotateCert returned cert_seq {cert_seq}, expected {expected_cert_seq}"
    );
    anyhow::ensure!(
        encrypted_share.id == decrypted.id,
        "ProvisionerRotateCert returned share id {}, expected {}",
        encrypted_share.id.get(),
        decrypted.id.get()
    );
    let rotated_share_id = encrypted_share.id;
    let expected_cert = expected_certs_roster
        .cert_for_share(rotated_share_id)
        .context("rotated share id missing from expected KP certificate roster")?;
    encrypted_share
        .verify_recipient(expected_cert)
        .context("verify the rotated KP share returned by the guardian")?;

    let (expected_encrypted_shares, _) = old_encrypted_shares.replace_recipient(
        &signing_fingerprint_hex,
        new_fingerprint.clone(),
        encrypted_share.armored_ciphertext,
    )?;

    let updated_state = reader
        .read_kp_share_state_log_from_current_build(&session_id, sharing_seq, cert_seq)
        .await
        .context("read the certificate-rotation kp-shares snapshot")?;
    updated_state
        .encrypted_shares
        .verify_recipients(&expected_certs_roster)
        .context("verify persisted kp-shares snapshot against the rotated certificate roster")?;
    anyhow::ensure!(
        updated_state.encrypted_shares == expected_encrypted_shares,
        "persisted kp-shares snapshot changed entries other than the signing certificate rotation"
    );

    println!(
        "KP certificate rotation complete: sharing_seq={sharing_seq}, cert_seq={cert_seq}, \
         share_id={}, signing_fingerprint={signing_fingerprint_hex}, \
         new_fingerprint={new_fingerprint}",
        rotated_share_id.get()
    );
    Ok(())
}
