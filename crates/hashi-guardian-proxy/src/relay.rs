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
//! Submissions authenticate against the ceremony's committed roster — the
//! recipient fingerprints of the latest S3 share log ([`crate::roster`]) — so
//! the set that can reach the accumulator is exactly the set holding shares.
//!
//! `Accumulator` holds the (pure, unit-tested) accumulation logic; a `tokio`
//! mutex serializes it and keeps at most one `ProvisionerInit` in flight.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use hashi_types::guardian::proto_conversions::pb_to_guardian_encrypted_share;
use hashi_types::guardian::relay_submission_signed_bytes;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::pgp::verify_detached_signature;
use hashi_types::pgp::Fingerprint;
use hashi_types::pgp::PgpPublicCert;
use hashi_types::proto;
use hashi_types::proto::guardian_relay_service_server::GuardianRelayService;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;
use tracing::warn;

use crate::roster::latest_kp_roster;
use crate::widlog::LogStore;

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

/// The committed roster changes only at ceremonies/rotations; a short TTL
/// bounds S3 reads under submission spam without staleness that matters.
const ROSTER_TTL: Duration = Duration::from_secs(60);

/// TTL-cached view of the S3-committed KP roster. The mutex is held across the
/// fetch, so concurrent misses collapse into one S3 read.
struct RosterCache<L> {
    store: L,
    cached: Mutex<Option<(Instant, Arc<Vec<Fingerprint>>)>>,
}

impl<L: LogStore> RosterCache<L> {
    fn new(store: L) -> Self {
        Self {
            store,
            cached: Mutex::new(None),
        }
    }

    async fn get(&self) -> Result<Arc<Vec<Fingerprint>>, Status> {
        let mut cached = self.cached.lock().await;
        if let Some((at, roster)) = cached.as_ref() {
            if at.elapsed() < ROSTER_TTL {
                return Ok(roster.clone());
            }
        }
        match latest_kp_roster(&self.store).await {
            Ok(Some(roster)) => {
                let roster = Arc::new(roster);
                *cached = Some((Instant::now(), roster.clone()));
                Ok(roster)
            }
            // No ceremony has committed a share set yet: fail closed, uncached
            // (so the first ceremony is authorized the moment its log lands).
            Ok(None) => Err(Status::failed_precondition(
                "no KP share log in the guardian bucket; run the key ceremony first",
            )),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "KP roster read failed");
                Err(Status::unavailable("KP roster unavailable; retry"))
            }
        }
    }
}

#[derive(Clone)]
pub struct Relay<L> {
    client: GuardianServiceClient<Channel>,
    accumulator: Arc<Mutex<Accumulator>>,
    roster: Arc<RosterCache<L>>,
}

impl<L: LogStore> Relay<L> {
    pub fn new(channel: Channel, roster_store: L) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            accumulator: Arc::new(Mutex::new(Accumulator::default())),
            roster: Arc::new(RosterCache::new(roster_store)),
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

/// Authenticate the signature side of a submission: the signer's detached
/// signature must cover these exact (session, share) bytes under the presented
/// cert. Returns the signer's fingerprint for the roster check. A DoS guard
/// only — the enclave still verifies every share against the commitments.
fn verify_kp_signature(
    expected_session_id: &str,
    signer_cert: &str,
    kp_signature: &str,
    share: &proto::GuardianEncryptedShare,
) -> Result<Fingerprint, Status> {
    if signer_cert.is_empty() || kp_signature.is_empty() {
        return Err(Status::unauthenticated(
            "submission is missing signer_cert or kp_signature",
        ));
    }
    let cert = PgpPublicCert::new(signer_cert.to_string())
        .map_err(|e| Status::unauthenticated(format!("invalid signer_cert: {e}")))?;
    let domain_share = pb_to_guardian_encrypted_share(share.clone())
        .map_err(|e| Status::invalid_argument(format!("malformed encrypted_share: {e:?}")))?;
    let signed_bytes = relay_submission_signed_bytes(expected_session_id, &domain_share);
    verify_detached_signature(&signed_bytes, kp_signature, &cert)
        .map_err(|e| Status::unauthenticated(format!("KP signature verification failed: {e}")))?;
    Ok(cert.fingerprint())
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
impl<L: LogStore> GuardianRelayService for Relay<L> {
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

        // Verify the signature before the roster read, the lock, or any
        // backend read: junk submissions cost local CPU only.
        let fingerprint = verify_kp_signature(
            &req.expected_session_id,
            &req.signer_cert,
            &req.kp_signature,
            &share,
        )?;
        let roster = self.roster.get().await?;
        if !roster.contains(&fingerprint) {
            return Err(Status::permission_denied(format!(
                "signer {fingerprint} is not in the guardian's committed KP roster"
            )));
        }

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
    use crate::widlog::test_store::MemStore;
    use hashi_types::guardian::proto_conversions::guardian_encrypted_share_to_pb;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::ShareID;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use std::sync::atomic::Ordering;

    fn share(id: u32) -> proto::GuardianEncryptedShare {
        proto::GuardianEncryptedShare {
            id: Some(proto::GuardianShareId { id: Some(id) }),
            ciphertext: None,
        }
    }

    /// A domain share with a dummy ciphertext, and its proto form.
    fn signed_share(id: u16) -> (GuardianEncryptedShare, proto::GuardianEncryptedShare) {
        let domain = GuardianEncryptedShare {
            id: ShareID::new(id).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![1, 2, 3],
                aes_ciphertext: vec![4, 5, 6],
            },
        };
        let pb = guardian_encrypted_share_to_pb(domain.clone());
        (domain, pb)
    }

    /// A minimal share-log record labeling one recipient, in the exact JSON
    /// shape the roster reader parses.
    fn shares_record_for(fp_hex: &str) -> (String, Vec<u8>) {
        let record = serde_json::json!({
            "session_id": "s",
            "timestamp_ms": 0,
            "message": { "Shares": { "sharing_seq": 0, "encrypted_shares": [
                { "id": 1, "recipient_fingerprint": fp_hex, "armored_ciphertext": "" }
            ]}},
            "signature": null,
        });
        let key = "shares/00000000000000000000-s.json".to_string();
        (key, serde_json::to_vec(&record).unwrap())
    }

    #[test]
    fn verify_kp_signature_gates_on_the_exact_submission() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored.clone()).unwrap();
        let session = "sess-a";

        let (domain_share, pb_share) = signed_share(1);
        let signed_bytes = relay_submission_signed_bytes(session, &domain_share);
        let good_sig = sign_detached_in_process(&secret_armored, &signed_bytes);

        // A valid signature over the exact submission passes and yields the
        // signer's fingerprint for the roster check.
        let fp = verify_kp_signature(session, &cert_armored, &good_sig, &pb_share).unwrap();
        assert_eq!(fp, cert.fingerprint());

        let (_, other_share) = signed_share(2);
        assert!(
            verify_kp_signature(session, &cert_armored, &good_sig, &other_share).is_err(),
            "signature bound to another share must be rejected"
        );

        assert!(
            verify_kp_signature(session, &cert_armored, "", &pb_share).is_err(),
            "missing signature must be rejected"
        );

        let other_bytes = relay_submission_signed_bytes("other-session", &domain_share);
        let stale_sig = sign_detached_in_process(&secret_armored, &other_bytes);
        assert!(
            verify_kp_signature(session, &cert_armored, &stale_sig, &pb_share).is_err(),
            "signature bound to another session must be rejected"
        );
    }

    #[tokio::test]
    async fn roster_cache_reads_membership_from_the_share_log() {
        let (cert_armored, _) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let store = MemStore::default();
        let (key, bytes) = shares_record_for(&cert.fingerprint().to_hex());
        store.insert(key, bytes);

        let roster = RosterCache::new(store).get().await.unwrap();
        assert!(roster.contains(&cert.fingerprint()));
        assert_eq!(roster.len(), 1);
    }

    #[tokio::test]
    async fn roster_cache_serves_the_cached_roster_within_the_ttl() {
        let store = MemStore::default();
        let (key, bytes) = shares_record_for("AAAABBBBCCCCDDDDEEEE11112222333344445555");
        store.insert(key, bytes);
        let cache = RosterCache::new(store);

        let first = cache.get().await.unwrap();
        // The store now fails hard; a fresh read would error, the cache must not.
        cache.store.fail_lists.store(true, Ordering::SeqCst);
        let second = cache.get().await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn missing_share_log_fails_closed() {
        let err = RosterCache::new(MemStore::default())
            .get()
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn roster_store_failure_is_unavailable_and_unclassified() {
        let store = MemStore::default();
        store.fail_lists.store(true, Ordering::SeqCst);
        let err = RosterCache::new(store).get().await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        // The node classifies guardian errors by substring; this must stay in
        // its retriable bucket.
        assert!(!err.message().contains("seq mismatch"));
        assert!(!err.message().contains("Rate limit exceeded"));
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
