// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony commands.
//!
//! `operator ceremony` drives a fresh ceremony-mode guardian through genesis BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) -> [`SetupNewKey`] -> confirm each
//! share's recipient roster matches its expected KP cert set and every
//! ciphertext targets its keyed cert (without decrypting) -> cross-check the
//! guardian's `ceremony/` audit log and `kp-shares/` recovery log.
//!
//! [`OperatorInit`]: hashi_types::guardian::OperatorInitRequest
//! [`SetupNewKey`]: hashi_types::guardian::SetupNewKeyRequest
//! [`SetupNewKeyResponse`]: hashi_types::guardian::SetupNewKeyResponse

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::BuildPolicy;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tracing::info;

use crate::config::Config;
use crate::guardian_info::verified_live_guardian_info;

/// Run the one-time production guardian key ceremony.
///
/// See the module docs for the full step-by-step flow. Each step is logged via
/// `tracing` so the operator can follow exactly what is happening.
pub async fn run(cfg: Config) -> Result<()> {
    let guardian_s3 = cfg.guardian_s3.resolve().await?;
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

    // 3. Connect to the ceremony-mode guardian.
    info!(
        phase = "connect",
        endpoint = %cfg.guardian_endpoint,
        "connecting to ceremony-mode guardian",
    );
    let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
        .await
        .with_context(|| format!("connect to guardian at {}", cfg.guardian_endpoint))?;
    info!(phase = "connect", endpoint = %cfg.guardian_endpoint, "connected to guardian");

    // 4. operator_init (ceremony mode: S3 config only, no InitConfig).
    info!(
        phase = "operator_init",
        bucket = guardian_s3.bucket_name(),
        region = guardian_s3.region(),
        "calling OperatorInit (ceremony mode: S3 config only)",
    );
    let oi_req =
        operator_init_request_to_pb(OperatorInitRequest::new_ceremony_mode(guardian_s3.clone()))
            .map_err(|e| anyhow!("encode OperatorInitRequest: {e:?}"))?;
    client
        .operator_init(oi_req)
        .await
        .context("OperatorInit RPC failed")?;
    info!(
        phase = "operator_init",
        "operator_init complete; guardian S3 logger installed"
    );

    // 5. get_guardian_info -> verify attestation/PCRs and signed info -> pin the
    //    session id. This binds `signing_pub_key` (and thus the session) before
    //    we trust the SetupNewKey response we'll verify against it below.
    info!(phase = "guardian info", "calling GetGuardianInfo");
    let allowlist = cfg.kp_roster.pcr_allowlist();
    let verified = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
    ensure!(
        verified.info.lifecycle == CeremonyStage::OperatorInitialized.into(),
        "guardian is not an operator-initialized ceremony enclave"
    );
    let signing_pub_key = verified.signing_pub_key;
    let session_id = verified.session_id;
    info!(
        phase = "guardian info",
        session_id = %session_id,
        signing_pubkey = hex::encode(signing_pub_key.as_bytes()),
        "guardian info attestation and signature verified; session pinned",
    );

    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "connecting to guardian log bucket + verifying attestation against current build",
    );
    let mut reader = GuardianReader::new(&guardian_s3, allowlist)
        .await
        .context("connect to guardian log bucket")?;
    let verified_session = reader
        .get_session_info(&session_id, BuildPolicy::Current)
        .await?;
    let attested_signing_pub_key = verified_session.signing_pubkey;
    ensure!(
        attested_signing_pub_key == signing_pub_key,
        "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
    );
    info!(
        phase = "attestation pin",
        session_id = %session_id,
        "guardian S3 attestation matches gRPC signing key",
    );

    // 6. setup_new_key.
    info!(
        phase = "setup_new_key",
        n = cfg.kp_roster.num_shares,
        t = cfg.kp_roster.threshold,
        "calling SetupNewKey",
    );
    let signed_resp_pb = client
        .setup_new_key(setup_new_key_request_to_pb(setup_req))
        .await
        .context("SetupNewKey RPC failed")?
        .into_inner();
    let signed_resp = GuardianSigned::<SetupNewKeyResponse>::try_from(signed_resp_pb)
        .map_err(|e| anyhow!("decode SignedSetupNewKeyResponse: {e:?}"))?;
    info!(
        phase = "setup_new_key",
        n = cfg.kp_roster.num_shares,
        t = cfg.kp_roster.threshold,
        share_count = signed_resp.data.encrypted_shares.share_count(),
        ciphertext_count = signed_resp.data.encrypted_shares.ciphertext_count(),
        "setup_new_key response received",
    );

    // 7. Verify the response signature under the pinned session's signing key,
    //    and sanity-check the shape; keep the now-verified BTC master pubkey.
    let response = signed_resp
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e:?}"))?;
    let live = CeremonyState::from(response);
    live.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    info!(
        phase = "setup_new_key",
        sharing_seq = live.secret_sharing_instance.sharing_seq(),
        "verified SetupNewKeyResponse signature + shape",
    );

    // 8. Inspect each share's recipient roster and every ciphertext
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

    // 9. Cross-check the latest guardian ceremony/ and kp-shares/ logs.
    //    KPs will fetch the same KP share state during key-provisioner ceremony.
    info!(
        phase = "log cross-check",
        "cross-checking the latest guardian ceremony/ and kp-shares/ logs",
    );
    let logged = reader
        .read_latest_ceremony_state(BuildPolicy::Current)
        .await?
        .context("no ceremony logs found in guardian S3 bucket")?;
    logged.validate_sharing_params(cfg.kp_roster.num_shares, cfg.kp_roster.threshold)?;
    anyhow::ensure!(
        logged == live,
        "ceremony/ and kp-shares/ logs differ from the SetupNewKeyResponse"
    );
    info!(
        phase = "log cross-check",
        "ceremony/ and kp-shares/ logs match the SetupNewKeyResponse",
    );

    // 10. Summary.
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
