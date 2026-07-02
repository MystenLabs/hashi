// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The provisioning relay: the out-of-enclave half of `single_provisioner_init`.
//!
//! A key provisioner verifies the guardian's attestation directly, builds its
//! HPKE-encrypted share, and submits it here one share at a time. The relay
//! accumulates distinct shares for the guardian's current session and, once it
//! holds a threshold-many, submits them in a single batch `ProvisionerInit` to
//! the enclave. It never sees share plaintext (shares are encrypted to the
//! enclave session key), so it is liveness-only: it can stall provisioning but
//! cannot read a share or forge a key.
//!
//! The accumulation logic lives in [`Accumulator`] (pure, unit-tested); the gRPC
//! method is thin glue that reads the backend's live session/threshold and
//! drives the accumulator under a `tokio` mutex (which also serializes the batch
//! submission so at most one `ProvisionerInit` is in flight).

use std::collections::BTreeMap;
use std::sync::Arc;

use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::proto;
use hashi_types::proto::guardian_relay_service_server::GuardianRelayService;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tokio::sync::Mutex;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;
use tracing::warn;

/// Distinct-share accumulator for one guardian session. Reset whenever the
/// backend session changes (buffered shares are encrypted to the old session's
/// key and are useless against the new one).
#[derive(Default)]
struct Accumulator {
    session_id: Option<String>,
    shares: BTreeMap<u32, proto::GuardianEncryptedShare>,
    completed: bool,
}

impl Accumulator {
    /// Adopt `live` as the current session, clearing any buffer left from a
    /// previous session.
    fn sync_session(&mut self, live: &str) {
        if self.session_id.as_deref() != Some(live) {
            self.session_id = Some(live.to_string());
            self.shares.clear();
            self.completed = false;
        }
    }

    fn insert(&mut self, id: u32, share: proto::GuardianEncryptedShare) {
        self.shares.insert(id, share);
    }

    fn have(&self) -> usize {
        self.shares.len()
    }

    fn batch(&self) -> Vec<proto::GuardianEncryptedShare> {
        self.shares.values().cloned().collect()
    }

    fn clear_shares(&mut self) {
        self.shares.clear();
    }
}

/// Live backend state the relay needs, read from `GetGuardianInfo`.
struct BackendStatus {
    session_id: String,
    /// `None` until the operator has run `operator provision` (no
    /// `secret_sharing_instance` ⇒ the provisioning threshold is unknown).
    threshold: Option<usize>,
    provisioned: bool,
}

#[derive(Clone)]
pub struct Relay {
    client: GuardianServiceClient<Channel>,
    accumulator: Arc<Mutex<Accumulator>>,
}

impl Relay {
    pub fn new(channel: Channel) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            accumulator: Arc::new(Mutex::new(Accumulator::default())),
        }
    }

    /// Read the backend guardian's live session, provisioning threshold, and
    /// whether it is already provisioned. Verifies the signed info's signature
    /// (self-consistency) but not the Nitro attestation — the KP already
    /// anchored attestation before submitting, and the relay is liveness-only.
    async fn backend_status(&self) -> Result<BackendStatus, Status> {
        let pb = self
            .client
            .clone()
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await?
            .into_inner();
        let resp = GetGuardianInfoResponse::try_from(pb)
            .map_err(|e| Status::internal(format!("decode backend GuardianInfo: {e:?}")))?;
        let verified = resp
            .verify_signed_info_without_attestation()
            .map_err(|e| Status::internal(format!("verify backend GuardianInfo: {e:?}")))?;
        Ok(BackendStatus {
            session_id: verified.session_id,
            threshold: verified
                .info
                .secret_sharing_instance
                .as_ref()
                .map(|i| i.threshold()),
            provisioned: verified.info.enclave_btc_pubkey.is_some(),
        })
    }
}

fn done() -> Response<proto::SingleProvisionerInitResponse> {
    Response::new(proto::SingleProvisionerInitResponse {
        have: 0,
        need: 0,
        completed: true,
    })
}

fn progress(have: usize, need: usize) -> Response<proto::SingleProvisionerInitResponse> {
    Response::new(proto::SingleProvisionerInitResponse {
        have: have as u32,
        need: need as u32,
        completed: false,
    })
}

fn share_id(share: &proto::GuardianEncryptedShare) -> Option<u32> {
    share.id.as_ref().and_then(|id| id.id)
}

#[tonic::async_trait]
impl GuardianRelayService for Relay {
    async fn single_provisioner_init(
        &self,
        request: Request<proto::SingleProvisionerInitRequest>,
    ) -> Result<Response<proto::SingleProvisionerInitResponse>, Status> {
        let req = request.into_inner();
        let share = req
            .encrypted_share
            .ok_or_else(|| Status::invalid_argument("missing encrypted_share"))?;
        let id = share_id(&share)
            .ok_or_else(|| Status::invalid_argument("encrypted_share is missing its share id"))?;

        let status = self.backend_status().await?;

        // Already provisioned (by this relay, a prior relay, or an out-of-band
        // operator): idempotent success, nothing to accumulate.
        if status.provisioned {
            return Ok(done());
        }
        // The share is HPKE-encrypted to the session the KP pinned; if the
        // backend has since restarted into a new session, the share is useless.
        if req.expected_session_id != status.session_id {
            return Err(Status::failed_precondition(format!(
                "session mismatch: KP pinned {}, backend live session is {} \
                 (guardian restarted? re-run the provision flow)",
                req.expected_session_id, status.session_id
            )));
        }
        let threshold = status.threshold.ok_or_else(|| {
            Status::failed_precondition(
                "guardian has no secret_sharing_instance yet; run `operator provision` first",
            )
        })?;

        // Hold the accumulator across the possible batch submission so at most
        // one ProvisionerInit is ever in flight.
        let mut acc = self.accumulator.lock().await;
        acc.sync_session(&status.session_id);
        if acc.completed {
            return Ok(done());
        }
        acc.insert(id, share);
        let have = acc.have();
        info!(
            share_id = id,
            have,
            threshold,
            session = %status.session_id,
            "relay accepted a provisioner share",
        );
        if have < threshold {
            return Ok(progress(have, threshold));
        }

        // Threshold reached: submit every buffered share in one batch.
        let encrypted_shares = acc.batch();
        match self
            .client
            .clone()
            .provisioner_init(proto::ProvisionerInitRequest { encrypted_shares })
            .await
        {
            Ok(_) => {
                acc.completed = true;
                info!(
                    session = %status.session_id,
                    shares = have,
                    "relay submitted batch ProvisionerInit; guardian provisioned",
                );
                Ok(done())
            }
            Err(e) => {
                // A racing batch (or an out-of-band ProvisionerInit) may have
                // provisioned the guardian between our status read and here;
                // re-check before surfacing an error.
                match self.backend_status().await {
                    Ok(s) if s.provisioned => {
                        acc.completed = true;
                        Ok(done())
                    }
                    _ => {
                        // A genuine failure — e.g. one share won't decrypt (a KP
                        // bound the wrong state_hash). The batch is all-or-nothing
                        // and the relay can't tell which share is bad, so drop the
                        // whole buffer and let the KPs resubmit a clean set.
                        warn!(
                            error = %e,
                            "batch ProvisionerInit failed; clearing the share buffer for resubmission",
                        );
                        acc.clear_shares();
                        Err(Status::internal(format!(
                            "guardian ProvisionerInit failed: {e}"
                        )))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(id: u32) -> proto::GuardianEncryptedShare {
        proto::GuardianEncryptedShare {
            id: Some(proto::GuardianShareId { id: Some(id) }),
            ciphertext: None,
        }
    }

    #[test]
    fn dedupes_shares_by_id() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, share(1));
        acc.insert(1, share(1)); // same KP resubmits
        acc.insert(2, share(2));
        assert_eq!(acc.have(), 2);
        assert_eq!(acc.batch().len(), 2);
    }

    #[test]
    fn session_change_clears_buffer() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, share(1));
        acc.insert(2, share(2));
        acc.completed = true;
        // The backend restarted into a new session; old shares are useless.
        acc.sync_session("sess-b");
        assert_eq!(acc.have(), 0);
        assert!(!acc.completed);
        assert_eq!(acc.session_id.as_deref(), Some("sess-b"));
    }

    #[test]
    fn same_session_preserves_buffer() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, share(1));
        acc.sync_session("sess-a"); // repeated submit, same session
        assert_eq!(acc.have(), 1);
    }

    #[test]
    fn clear_shares_empties_buffer_but_keeps_session() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, share(1));
        acc.clear_shares();
        assert_eq!(acc.have(), 0);
        assert_eq!(acc.session_id.as_deref(), Some("sess-a"));
    }
}
