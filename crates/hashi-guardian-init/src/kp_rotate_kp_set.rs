// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `key-provisioner rotate-kp-set`: one current KP's half of a KP-set rotation.
//!
//! The KP verifies the fresh ceremony guardian the operator initialized,
//! decrypts its share of the dealt (current) set through its yubikey, and
//! signs a submission that binds that share, re-encrypted to the guardian's
//! session key, to the proposed new roster and sharing params. The submission
//! is written to a file for the operator, who batches threshold-many of them
//! into one `RotateKpSet`. The enclave re-verifies every signature and binding;
//! the file carries nothing secret.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::EncPubKey;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateKpSetRequest;
use hpke::Deserializable;
use rand::thread_rng;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::verified_ceremony_guardian_info;
use crate::kp_roster::decrypt_kp_share;
use crate::kp_roster::load_kp_cert;
use crate::submission;

pub async fn run(cfg: Config, submission_path: &Path) -> Result<()> {
    cfg.kp_roster.validate()?;
    let new_kp_set = cfg.require_new_kp_roster("key-provisioner rotate-kp-set")?;
    new_kp_set.validate()?;
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;
    let allowlist = cfg.kp_roster.pcr_allowlist();

    info!(
        phase = "setup",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        num_shares = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        new_num_shares = new_kp_set.num_shares,
        new_threshold = new_kp_set.threshold,
        endpoint = %cfg.guardian_endpoint,
        "signing a KP-set rotation submission",
    );

    let certs_roster = cfg.kp_roster.load_certs_roster()?;
    let new_certs_roster = new_kp_set.load_certs_roster()?;
    let new_params = new_kp_set.params()?;
    let kp_cert = load_kp_cert(cfg.require_kp_pgp_cert_path("key-provisioner rotate-kp-set")?)?;
    ensure!(
        certs_roster
            .cert_for_fingerprint(&kp_cert.fingerprint())
            .is_some(),
        "this KP's cert (fingerprint {}) is not among the current kp_roster.kp_pgp_cert_paths",
        kp_cert.fingerprint()
    );
    // What this KP is about to authorize. Compare it with the operator's.
    for (index, fingerprint) in new_certs_roster.fingerprints().iter().enumerate() {
        info!(
            phase = "proposal",
            share_id = index + 1,
            recipient_fingerprint = %fingerprint,
            "proposed new KP set entry",
        );
    }

    // 1. The ceremony guardian this submission is for: attested as the current
    //    build, operator-initialized on the expected bucket, and its session
    //    attestation in S3.
    let target =
        verified_ceremony_guardian_info(&cfg.guardian_endpoint, allowlist.current_build()).await?;
    ensure!(
        target.info.lifecycle == CeremonyStage::OperatorInitialized.into(),
        "guardian lifecycle is {:?}; expected ceremony/operator_initialized (run `operator rotate-kp-set init`)",
        target.info.lifecycle
    );
    ensure!(
        target.info.bucket_info.as_ref() == Some(&guardian_s3.bucket_info),
        "guardian bucket info mismatch: expected {:?}, got {:?}",
        guardian_s3.bucket_info,
        target.info.bucket_info
    );
    let guardian_pub_key =
        EncPubKey::from_bytes(&target.info.encryption_pubkey).map_err(anyhow::Error::msg)?;
    let session_id = target.session_id;
    let mut reader = GuardianReader::new(&guardian_s3, allowlist.clone())
        .await
        .context("connect to guardian log bucket")?;
    let verified_session = reader.get_current_session_info(&session_id).await?;
    ensure!(
        verified_session.signing_pubkey() == &target.signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    info!(
        phase = "guardian info",
        session_id = %session_id,
        enc_pubkey = hex::encode(&target.info.encryption_pubkey),
        "ceremony guardian verified; session pinned",
    );

    // 2. This KP's share of the dealt set, from the latest attested logs.
    let state = reader.read_latest_ceremony_state().await?;
    state.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    state.encrypted_shares.verify_recipients(&certs_roster)?;
    let sharing_seq = state.secret_sharing_instance.sharing_seq();
    info!(
        phase = "share read",
        sharing_seq,
        cert_seq = state.cert_seq,
        "latest ceremony and kp-shares logs verified against the current roster",
    );
    let decrypted = decrypt_kp_share(&state, &kp_cert)?;

    // 3. Bind the re-encrypted share to the proposal and sign.
    let share_id = decrypted.id;
    let request = ProvisionerRotateKpSetRequest::build_from_share(
        session_id.clone(),
        allowlist,
        &decrypted,
        &guardian_pub_key,
        new_certs_roster,
        new_params,
        &mut thread_rng(),
    )?;
    drop(decrypted);
    let signed = KpSigned::sign(request, kp_cert.clone(), None)
        .context("sign the rotation submission with the KP key")?;
    signed
        .verify_signature()
        .map_err(|e| anyhow!("re-verify the signed submission: {e}"))?;
    submission::write(submission_path, signed)?;

    info!(
        phase = "summary",
        path = %submission_path.display(),
        session_id = %session_id,
        share_id = share_id.get(),
        signer_fingerprint = %kp_cert.fingerprint(),
        sharing_seq,
        new_sharing_seq = sharing_seq + 1,
        new_num_shares = new_params.num_shares(),
        new_threshold = new_params.threshold(),
        "rotation submission written; send it to the operator",
    );
    println!(
        "KP-set rotation submission written to {}",
        submission_path.display()
    );
    println!("  session_id:     {session_id}");
    println!("  share_id:       {}", share_id.get());
    println!("  signer:         {}", kp_cert.fingerprint());
    println!("  sharing_seq:    {sharing_seq} -> {}", sharing_seq + 1);
    println!(
        "  new set:        {}-of-{}",
        new_params.threshold(),
        new_params.num_shares()
    );
    Ok(())
}
