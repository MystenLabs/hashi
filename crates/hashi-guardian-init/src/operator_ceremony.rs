// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony commands.
//!
//! `operator ceremony` drives a fresh ceremony-mode guardian through genesis BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) -> [`SetupNewKey`] -> confirm each
//! share's recipient roster matches its expected KP cert set and every
//! ciphertext targets its keyed cert (without decrypting) -> cross-check the
//! guardian's `ceremony/` audit log and `kp-shares/` recovery log -> wait for
//! every KP to confirm successful recovery.
//!
//! [`OperatorInit`]: hashi_types::guardian::OperatorInitRequest
//! [`SetupNewKey`]: hashi_types::guardian::SetupNewKeyRequest
//! [`SetupNewKeyResponse`]: hashi_types::guardian::SetupNewKeyResponse

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use tracing::info;

use crate::ceremony::CeremonyGuardian;
use crate::config::Config;

/// Run the one-time production guardian key ceremony.
///
/// See the module docs for the full step-by-step flow. Each step is logged via
/// `tracing` so the operator can follow exactly what is happening.
pub async fn run(cfg: Config) -> Result<()> {
    let guardian_s3 = hashi_guardian::resolve_s3_config(&cfg.guardian_s3).await?;
    let retention_environment = guardian_s3.retention_environment;

    info!(
        phase = "setup",
        share_count = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        certificate_count = cfg.kp_roster.cert_count(),
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        ?retention_environment,
        endpoint = %cfg.guardian_endpoint,
        sui_rpc = %cfg.hashi.sui_rpc,
        package_id = %cfg.hashi.hashi_ids.package_id,
        hashi_object_id = %cfg.hashi.hashi_ids.hashi_object_id,
        current_pcr0 = hex::encode(cfg.kp_roster.pcr_allowlist.current_build().pcr0()),
        "running guardian key ceremony",
    );

    // 1. Validate config-level sharing params up front (also re-validated by
    //    SetupNewKeyRequest::new).
    cfg.kp_roster.validate()?;

    // 2. Load + validate each KP's PGP cert set.
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
    let setup_req = SetupNewKeyRequest::new(
        certs_roster.clone(),
        cfg.kp_roster.num_shares,
        cfg.kp_roster.threshold,
    )
    .map_err(|e| anyhow!("build SetupNewKeyRequest: {e:?}"))?;

    // 3. operator_init + pin the session. This binds `signing_pub_key` (and
    //    thus the session) before we trust the SetupNewKey response we'll
    //    verify against it below.
    let mut guardian = CeremonyGuardian::init(&cfg, &guardian_s3).await?;
    ensure!(
        guardian.lifecycle == CeremonyStage::OperatorInitialized.into(),
        "guardian is not an operator-initialized ceremony enclave"
    );

    // 4. setup_new_key.
    info!(
        phase = "setup_new_key",
        n = cfg.kp_roster.num_shares,
        t = cfg.kp_roster.threshold,
        "calling SetupNewKey",
    );
    let signed_resp_pb = guardian
        .client
        .setup_new_key(setup_new_key_request_to_pb(setup_req))
        .await
        .context("SetupNewKey RPC failed")?
        .into_inner();
    let signed_resp = GuardianSignedResponse::<SetupNewKeyResponse>::try_from(signed_resp_pb)
        .map_err(|e| anyhow!("decode SignedSetupNewKeyResponse: {e:?}"))?;

    // 5. Verify the response under the pinned session's signing key,
    //    and sanity-check the shape; keep the verified BTC master pubkey.
    let response = signed_resp
        .verify_into_data(&guardian.signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e}"))?
        .response;
    info!(
        phase = "setup_new_key",
        n = cfg.kp_roster.num_shares,
        t = cfg.kp_roster.threshold,
        share_count = response.encrypted_shares.share_count(),
        ciphertext_count = response.encrypted_shares.ciphertext_count(),
        "setup_new_key response received",
    );

    let live = CeremonyState::from(response);
    live.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    info!(
        phase = "setup_new_key",
        sharing_seq = live.secret_sharing_instance.sharing_seq(),
        "verified SetupNewKeyResponse signature + shape",
    );

    // 6. Inspect each share's recipient roster and every ciphertext
    //    WITHOUT decrypting.
    info!(
        phase = "roster verify",
        share_count = live.encrypted_shares.share_count(),
        ciphertext_count = live.encrypted_shares.ciphertext_count(),
        "verifying every returned PGP-encrypted share ciphertext against the expected KP cert sets (without decrypting)",
    );
    live.encrypted_shares.verify_recipients(&certs_roster)?;
    info!(
        phase = "roster verify",
        "all returned PGP-encrypted share ciphertexts verified against expected KP certificates",
    );

    // 7. Cross-check the latest guardian ceremony/ and kp-shares/ logs, then
    //    wait for every KP's confirmation.
    guardian
        .verify_published(&live, cfg.kp_roster.num_shares, cfg.kp_roster.threshold)
        .await?;
    guardian.wait_for_confirmations().await?;

    // 8. Summary.
    info!(
        phase = "summary",
        sharing_seq = live.secret_sharing_instance.sharing_seq(),
        cert_seq = live.cert_seq,
        n = live.secret_sharing_instance.num_shares(),
        t = live.secret_sharing_instance.threshold(),
        "guardian key ceremony complete",
    );
    for commitment in live.secret_sharing_instance.commitments().iter() {
        info!(
            phase = "summary",
            share_id = commitment.id.get(),
            commitment = hex::encode(&commitment.digest),
            "share commitment",
        );
    }

    // Emit the verified pubkey on stdout for the deploy workflow to capture and
    // publish on-chain — printed only after every ceremony check above has passed.
    let btc_master_pubkey_hex = hex::encode(live.btc_master_pubkey.serialize());
    info!(
        phase = "summary",
        btc_master_pubkey = %btc_master_pubkey_hex,
        "ceremony BTC master pubkey (publish this on-chain as guardian_btc_public_key)",
    );
    println!("GUARDIAN_BTC_PUBKEY={btc_master_pubkey_hex}");

    Ok(())
}
