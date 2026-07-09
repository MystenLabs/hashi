// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::anyhow;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::proto as pb;
use hashi_types::proto::guardian_relay_service_client::GuardianRelayServiceClient;
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
    verify_info_response(info_pb, current_build)
}

/// Like [`verified_live_guardian_info`], but over the relay's provisioning
/// surface: `GetStandbyInfo` answers for the guardian KPs are provisioning
/// (the proxy's standby backend when one is configured, else the active
/// guardian), where the node-facing `GetGuardianInfo` always answers for the
/// active one.
pub async fn verified_standby_guardian_info(
    client: &mut GuardianRelayServiceClient<Channel>,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_pb = client
        .get_standby_info(pb::GetStandbyInfoRequest {})
        .await
        .context("GetStandbyInfo RPC failed")?
        .into_inner();
    verify_info_response(info_pb, current_build)
}

fn verify_info_response(
    info_pb: pb::GetGuardianInfoResponse,
    current_build: &BuildPcrs,
) -> anyhow::Result<VerifiedGuardianInfo> {
    let info_resp = GetGuardianInfoResponse::try_from(info_pb)
        .map_err(|e| anyhow!("decode GetGuardianInfoResponse: {e:?}"))?;
    info_resp
        .verify(current_build)
        .map_err(|e| anyhow!("verify GuardianInfo attestation/signature: {e:?}"))
}
