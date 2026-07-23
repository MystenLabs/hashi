// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::transport::Channel;

pub async fn verified_live_guardian_info(
    client: &mut GuardianServiceClient<Channel>,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_pb = client
        .get_guardian_info(pb::GetGuardianInfoRequest {})
        .await
        .context("GetGuardianInfo RPC failed")?
        .into_inner();
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    info_resp
        .verify_live(current_build)
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e}"))
}

/// The OI log captures the final pre-transition snapshot. Apart from the
/// lifecycle advancing once, it must match the live post-OI GuardianInfo.
pub fn ensure_oi_info_matches_post_init(
    oi_info: &GuardianInfo,
    live_info: &GuardianInfo,
) -> anyhow::Result<()> {
    ensure!(
        live_info.lifecycle.predecessor() == Some(oi_info.lifecycle),
        "S3 OI lifecycle {:?} is not the predecessor of live lifecycle {:?}",
        oi_info.lifecycle,
        live_info.lifecycle
    );

    let mut expected_live_info = oi_info.clone();
    expected_live_info.lifecycle = live_info.lifecycle;
    ensure!(
        &expected_live_info == live_info,
        "S3 OI GuardianInfo differs from live post-OperatorInit GuardianInfo"
    );
    Ok(())
}
