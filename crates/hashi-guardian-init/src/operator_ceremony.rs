// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Production guardian key ceremony commands.
//!
//! `operator ceremony` drives a fresh ceremony-mode guardian through genesis BTC key setup:
//! [`OperatorInit`] (ceremony mode, S3-only) -> [`SetupNewKey`] -> inspect each
//! returned encrypted share to confirm it is addressed to the expected KP cert
//! (without decrypting) -> cross-check the guardian's `ceremony/` audit log and
//! `shares/` recovery log.
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
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::SetupNewKeyRequest;
use hashi_types::guardian::SetupNewKeyResponse;
use hashi_types::guardian::SharesLogMessage;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::guardian::proto_conversions::setup_new_key_request_to_pb;
use hashi_types::pgp::load_certs;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tracing::info;

use crate::config::Config;
use crate::kp_roster::VerifiedCeremonyState;

/// Run the one-time production guardian key ceremony.
///
/// See the module docs for the full step-by-step flow. Each step is logged via
/// `tracing` so the operator can follow exactly what is happening.
pub async fn run(cfg: Config) -> Result<()> {
    info!(
        phase = "setup",
        num_shares = cfg.kp_roster.num_shares,
        threshold = cfg.kp_roster.threshold,
        cert_count = cfg.kp_roster.kp_pgp_cert_paths.len(),
        bucket = cfg.kp_roster.guardian_s3.bucket_name(),
        region = cfg.kp_roster.guardian_s3.region(),
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

    // 2. Load + validate each KP's PGP cert.
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
    let setup_req = SetupNewKeyRequest::new(
        certs.clone(),
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

    // 4. operator_init (ceremony mode: S3 config only, no WithdrawModeConfig).
    info!(
        phase = "operator_init",
        bucket = cfg.kp_roster.guardian_s3.bucket_name(),
        region = cfg.kp_roster.guardian_s3.region(),
        "calling OperatorInit (ceremony mode: S3 config only)",
    );
    let oi_req = operator_init_request_to_pb(OperatorInitRequest::new_ceremony_mode(
        cfg.kp_roster.guardian_s3.clone(),
    ))
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
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    let allowlist = cfg.kp_roster.pcr_allowlist();
    let verified = info_resp
        .verify(allowlist.current_build())
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e:?}"))?;
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
    let mut reader = GuardianReader::new(&cfg.kp_roster.guardian_s3, allowlist)
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
        encrypted_share_count = signed_resp.data.encrypted_shares.len(),
        "setup_new_key response received",
    );

    // 7. Verify the response signature under the pinned session's signing key,
    //    and sanity-check the response shape.
    let sharing_seq = 0u64;
    let live = signed_resp
        .verify(&signing_pub_key)
        .map_err(|e| anyhow!("verify SetupNewKeyResponse signature: {e:?}"))
        .and_then(|response| {
            VerifiedCeremonyState::from_response(
                response,
                session_id.clone(),
                sharing_seq,
                cfg.kp_roster.num_shares,
                cfg.kp_roster.threshold,
            )
        })?;
    info!(
        phase = "setup_new_key",
        session_id = %live.session_id,
        sharing_seq = live.secret_sharing_instance.sharing_seq(),
        "verified SetupNewKeyResponse signature + shape",
    );

    // 8. Inspect each encrypted share's PGP recipients WITHOUT decrypting, and
    //    confirm every share is addressed only to its expected cert.
    info!(
        phase = "roster verify",
        share_count = live.encrypted_shares.len(),
        "verifying every returned share is addressed only to its labeled KP cert (without decrypting)",
    );
    live.verify_encrypted_share_recipients(&certs)?;
    info!(
        phase = "roster verify",
        "all returned shares verified against expected KP certs",
    );

    // 9. Cross-check the latest guardian ceremony/ and shares/ logs.
    //    KPs will fetch the same shares/ object during key-provisioner ceremony.
    info!(
        phase = "log cross-check",
        "cross-checking the latest guardian ceremony/ and shares/ logs",
    );
    let logged = VerifiedCeremonyState::latest_from_s3(
        &mut reader,
        cfg.kp_roster.num_shares,
        cfg.kp_roster.threshold,
    )
    .await?;
    anyhow::ensure!(
        logged == live,
        "ceremony/ and shares/ logs differ from the SetupNewKeyResponse"
    );
    info!(
        phase = "log cross-check",
        "ceremony/ and shares/ logs match the SetupNewKeyResponse",
    );

    // 10. Summary.
    info!(
        phase = "summary",
        session_id = %live.session_id,
        sharing_seq = live.secret_sharing_instance.sharing_seq(),
        shares_key = %SharesLogMessage::object_key(
            &live.session_id,
            live.secret_sharing_instance.sharing_seq()
        ),
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

    Ok(())
}
