// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The provisioning relay: the out-of-enclave half of `single_provisioner_init`.
//!
//! Key provisioners submit HPKE-encrypted shares one at a time; the relay
//! accumulates distinct shares for the guardian's current session and, once it
//! holds a threshold-many, submits them in one batch `ProvisionerInit`. Shares
//! are encrypted to the enclave session key, so the relay is liveness-only: it
//! can stall provisioning but cannot read a share or forge a key.
//!
//! `Accumulator` holds the (pure, unit-tested) accumulation logic; a `tokio`
//! mutex serializes it and keeps at most one `ProvisionerInit` in flight.

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
    /// Adopt `live` as the current session, clearing any stale buffer.
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
    /// `num_shares`/`threshold` are `Some` together, and only once `operator
    /// provision` has created the `secret_sharing_instance`.
    num_shares: Option<usize>,
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

    /// Backend's live session, provisioning threshold, and provisioned flag.
    /// Verifies the signed info's signature but not the Nitro attestation — the KP
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
        let sharing = verified.info.secret_sharing_instance.as_ref();
        let num_shares = sharing.map(|i| i.num_shares());
        let threshold = sharing.map(|i| i.threshold());
        let provisioned = verified.info.enclave_btc_pubkey.is_some();
        Ok(BackendStatus {
            session_id: verified.session_id,
            num_shares,
            threshold,
            provisioned,
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

// Cheap input hygiene — the guardian re-verifies each share. A real KP's id is
// 1-indexed, so anything outside [1, num_shares] is malformed.
fn check_share_id(id: u32, num_shares: usize) -> Result<(), Status> {
    if id == 0 || id as usize > num_shares {
        return Err(Status::invalid_argument(format!(
            "share id {id} out of range [1, {num_shares}]"
        )));
    }
    Ok(())
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

        // Hold the accumulator across the status read + batch submit so a racing
        // session change can't wipe a half-filled buffer, and only one runs at a time.
        let mut acc = self.accumulator.lock().await;

        let status = self.backend_status().await?;

        // Already provisioned (by us, a prior relay, or out-of-band): idempotent success.
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
        let (num_shares, threshold) =
            match (status.num_shares, status.threshold) {
                (Some(n), Some(t)) => (n, t),
                _ => return Err(Status::failed_precondition(
                    "guardian has no secret_sharing_instance yet; run `operator provision` first",
                )),
            };
        check_share_id(id, num_shares)?;
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
                // A racing batch or out-of-band ProvisionerInit may have provisioned
                // the guardian since our status read; re-check before erroring.
                match self.backend_status().await {
                    Ok(s) if s.provisioned => {
                        acc.completed = true;
                        Ok(done())
                    }
                    _ => {
                        // Genuine failure (e.g. a share won't decrypt). The batch is
                        // all-or-nothing and we can't tell which share is bad, so drop
                        // the whole buffer and let the KPs resubmit a clean set.
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

    #[test]
    fn share_id_bounds() {
        assert!(check_share_id(1, 3).is_ok());
        assert!(check_share_id(3, 3).is_ok());
        assert!(check_share_id(0, 3).is_err());
        assert!(check_share_id(4, 3).is_err());
    }
}
