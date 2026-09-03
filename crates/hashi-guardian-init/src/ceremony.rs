// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The operator's side of a ceremony-mode guardian, shared by `operator
//! ceremony` and `operator rotate-kp-set`: `OperatorInit`, the session pin,
//! the log cross-check and the wait for every KP's confirmation.

use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use hashi_guardian::s3_reader::GuardianReader;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::EnclaveLifecycle;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::OperatorInitRequest;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::ResolvedS3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VerifiedGuardianInfo;
use hashi_types::guardian::proto_conversions::operator_init_request_to_pb;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tonic::Code;
use tonic::transport::Channel;
use tracing::info;
use tracing::warn;

use crate::config::Config;
use crate::guardian_info::verified_live_guardian_info;

fn is_transient_rpc_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<tonic::Status>().is_some_and(|status| {
        matches!(
            status.code(),
            Code::Cancelled | Code::DeadlineExceeded | Code::Unavailable
        )
    })
}

pub struct CeremonyGuardian {
    pub client: GuardianServiceClient<Channel>,
    pub reader: GuardianReader,
    pub session_id: SessionID,
    pub signing_pub_key: GuardianPubKey,
    pub lifecycle: EnclaveLifecycle,
    allowlist: PcrAllowlist,
}

impl CeremonyGuardian {
    /// Connect to `guardian_endpoint`, run `OperatorInit` (ceremony mode: S3
    /// config only) unless it already ran, and pin the session: the live
    /// attestation and the S3 `init/` attestation must carry the same signing
    /// key. Every later response is verified under that key.
    pub async fn init(cfg: &Config, guardian_s3: &ResolvedS3Config) -> Result<Self> {
        let allowlist = cfg.kp_roster.pcr_allowlist();
        info!(
            phase = "connect",
            endpoint = %cfg.guardian_endpoint,
            "connecting to ceremony-mode guardian",
        );
        let mut client = GuardianServiceClient::connect(cfg.guardian_endpoint.clone())
            .await
            .with_context(|| format!("connect to guardian at {}", cfg.guardian_endpoint))?;
        let preflight = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
        match preflight.info.lifecycle {
            lifecycle if lifecycle == CeremonyStage::Uninitialized.into() => {
                info!(
                    phase = "operator_init",
                    bucket = guardian_s3.bucket_name(),
                    region = guardian_s3.region(),
                    "calling OperatorInit (ceremony mode: S3 config only)",
                );
                let request = operator_init_request_to_pb(OperatorInitRequest::new_ceremony_mode(
                    guardian_s3.clone(),
                ))
                .map_err(|e| anyhow!("encode OperatorInitRequest: {e:?}"))?;
                client
                    .operator_init(request)
                    .await
                    .context("OperatorInit RPC failed")?;
                info!(
                    phase = "operator_init",
                    "operator_init complete; guardian S3 logger installed"
                );
            }
            EnclaveLifecycle::Ceremony(_) => info!(
                phase = "operator_init",
                "guardian is already operator-initialized; verifying it",
            ),
            lifecycle => {
                anyhow::bail!("guardian is not a ceremony enclave (lifecycle {lifecycle:?})")
            }
        }

        let verified = verified_live_guardian_info(&mut client, allowlist.current_build()).await?;
        ensure!(
            verified.session_id == preflight.session_id,
            "guardian session changed during OperatorInit: started {}, now {}",
            preflight.session_id,
            verified.session_id
        );
        ensure!(
            verified.info.bucket_info.as_ref() == Some(&guardian_s3.bucket_info),
            "guardian bucket info mismatch: expected {:?}, got {:?}",
            guardian_s3.bucket_info,
            verified.info.bucket_info
        );
        info!(
            phase = "guardian info",
            session_id = %verified.session_id,
            signing_pubkey = hex::encode(verified.signing_pub_key.as_bytes()),
            "guardian info attestation and signature verified; session pinned",
        );

        info!(
            phase = "attestation pin",
            session_id = %verified.session_id,
            "connecting to guardian log bucket + verifying attestation against current build",
        );
        let mut reader = GuardianReader::new(guardian_s3, allowlist.clone())
            .await
            .context("connect to guardian log bucket")?;
        let verified_session = reader
            .get_current_session_info(&verified.session_id)
            .await?;
        ensure!(
            verified_session.signing_pubkey() == &verified.signing_pub_key,
            "guardian S3 attestation signing pubkey differs from gRPC signing pubkey"
        );
        info!(
            phase = "attestation pin",
            session_id = %verified.session_id,
            "guardian S3 attestation matches gRPC signing key",
        );

        Ok(Self {
            client,
            reader,
            session_id: verified.session_id,
            signing_pub_key: verified.signing_pub_key,
            lifecycle: verified.info.lifecycle,
            allowlist,
        })
    }

    /// The live guardian info, required to still be the pinned session.
    pub async fn live_info(&mut self) -> Result<VerifiedGuardianInfo> {
        let status =
            verified_live_guardian_info(&mut self.client, self.allowlist.current_build()).await?;
        ensure!(
            status.session_id == self.session_id && status.signing_pub_key == self.signing_pub_key,
            "ceremony guardian session changed"
        );
        Ok(status)
    }

    /// Require the latest `ceremony/` + `kp-shares/` logs, written by the
    /// current build, to equal the state the guardian returned. KPs read the
    /// same logs during `key-provisioner ceremony`.
    pub async fn verify_published(
        &mut self,
        live: &CeremonyState,
        expected_n: usize,
        expected_t: usize,
    ) -> Result<()> {
        info!(
            phase = "log cross-check",
            "cross-checking the latest guardian ceremony/ and kp-shares/ logs",
        );
        let logged = self
            .reader
            .read_latest_ceremony_state_from_current_build()
            .await?;
        logged.validate_sharing_params(expected_n, expected_t)?;
        ensure!(
            logged == *live,
            "ceremony/ and kp-shares/ logs differ from the guardian's response"
        );
        info!(
            phase = "log cross-check",
            "ceremony/ and kp-shares/ logs match the guardian's response",
        );
        Ok(())
    }

    /// Block until every dealt KP has confirmed and the guardian reports
    /// `Completed`.
    pub async fn wait_for_confirmations(&mut self) -> Result<()> {
        info!(
            phase = "KP confirmations",
            "ceremony state published; waiting for every key provisioner to run key-provisioner ceremony",
        );
        loop {
            let status = match self.live_info().await {
                Ok(status) => status,
                Err(error) if is_transient_rpc_error(&error) => {
                    warn!(
                        phase = "KP confirmations",
                        error = %format!("{error:#}"),
                        "transient guardian status failure; retrying",
                    );
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match status.info.lifecycle {
                lifecycle if lifecycle == CeremonyStage::Completed.into() => break,
                lifecycle
                    if lifecycle == CeremonyStage::AwaitingKeyProvisionerConfirmations.into() =>
                {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                lifecycle => anyhow::bail!(
                    "ceremony guardian entered unexpected lifecycle {lifecycle:?} while waiting for KP confirmations"
                ),
            }
        }
        info!(
            phase = "KP confirmations",
            "every key provisioner confirmed successful ceremony recovery",
        );
        Ok(())
    }
}
