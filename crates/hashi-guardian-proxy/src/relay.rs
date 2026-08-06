// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The provisioning relay: the out-of-enclave half of `single_provisioner_init`.
//!
//! Key provisioners submit signed, HPKE-encrypted shares one at a time; the relay
//! pre-verifies and accumulates distinct submissions for the guardian's current
//! session and, once it holds a threshold-many, forwards them unchanged in one
//! batch `ProvisionerInit`. The enclave re-verifies every signature, so the relay
//! is liveness-only: it can stall provisioning but cannot read a share or forge
//! a key.
//!
//! `Accumulator` holds the (pure, unit-tested) accumulation logic; a `tokio`
//! mutex serializes it and keeps at most one `ProvisionerInit` in flight.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::roster::RosterCache;
use crate::widlog::LogStore;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::SingleProvisionerInitRequest;
use hashi_types::pgp::Fingerprint;
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
    submissions: BTreeMap<u32, proto::SignedSingleProvisionerInitRequest>,
    completed: bool,
}

impl Accumulator {
    /// Adopt `live` as the current session, clearing any stale buffer.
    fn sync_session(&mut self, live: &str) {
        if self.session_id.as_deref() != Some(live) {
            self.session_id = Some(live.to_string());
            self.submissions.clear();
            self.completed = false;
        }
    }

    fn insert(&mut self, id: u32, submission: proto::SignedSingleProvisionerInitRequest) {
        self.submissions.insert(id, submission);
    }

    fn have(&self) -> usize {
        self.submissions.len()
    }

    fn batch(&self) -> Vec<proto::SignedSingleProvisionerInitRequest> {
        self.submissions.values().cloned().collect()
    }

    fn clear_submissions(&mut self) {
        self.submissions.clear();
    }
}

/// Live backend state the relay needs, read from `GetGuardianInfo`.
struct BackendStatus {
    session_id: String,
    /// `num_shares`/`threshold` are `Some` together after `operator provision`
    /// and until activation clears the initialization state. The relay needs
    /// them only while `provisioned` is false.
    num_shares: Option<usize>,
    threshold: Option<usize>,
    config_hash: Option<[u8; 32]>,
    genesis_state_hash: Option<[u8; 32]>,
    provisioned: bool,
}

#[derive(Clone)]
pub struct Relay<L> {
    client: GuardianServiceClient<Channel>,
    accumulator: Arc<Mutex<Accumulator>>,
    roster: Arc<RosterCache<L>>,
}

impl<L: LogStore> Relay<L> {
    pub fn new(channel: Channel, roster: Arc<RosterCache<L>>) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            accumulator: Arc::new(Mutex::new(Accumulator::default())),
            roster,
        }
    }

    /// Pre-authenticate a submission: its detached signature must cover these
    /// exact (session, config, share) bytes, and the signer's cert must be in
    /// the ceremony's committed roster. Signature first because it needs no
    /// I/O — a submission that isn't internally consistent never costs an S3
    /// roster read. DoS guard only; the enclave re-verifies authoritatively.
    async fn verify_kp_submission<'a>(
        &self,
        signed_request: &'a KpSigned<SingleProvisionerInitRequest>,
    ) -> Result<&'a SingleProvisionerInitRequest, Status> {
        let request = signed_request
            .verify_signature()
            .map_err(|error| Status::unauthenticated(error.to_string()))?;
        // The ceremony's committed roster, not deploy config: a rotation
        // re-deals shares without a proxy redeploy.
        check_rostered(
            &signed_request.signer_fingerprint(),
            &self.authorized_kps().await?,
        )?;
        Ok(request)
    }

    /// The ceremony's committed roster, mapped onto the relay's failure modes:
    /// no share log yet is a definitive "not ready", a read error is transient.
    async fn authorized_kps(&self) -> Result<Arc<Vec<Fingerprint>>, Status> {
        match self.roster.get().await {
            Ok(Some(roster)) => Ok(roster),
            Ok(None) => Err(Status::failed_precondition(
                "no KP share log in the guardian bucket; run the key ceremony first",
            )),
            Err(e) => {
                warn!(error = %format!("{e:#}"), "KP roster read failed");
                Err(Status::unavailable("KP roster unavailable; retry"))
            }
        }
    }

    /// Backend's self-reported session, provisioning threshold, and provisioned flag.
    /// The relay is liveness-only, so it does not verify the signature or attestation.
    async fn backend_status(&self) -> Result<BackendStatus, Status> {
        let pb = self
            .client
            .clone()
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await?
            .into_inner();
        let resp = GetGuardianInfoResponse::try_from(pb)
            .map_err(|e| Status::internal(format!("decode backend GuardianInfo: {e:?}")))?;
        let (info, signing_pub_key) = resp.into_info_unchecked();
        let session_id = SessionID::from_signing_pubkey(&signing_pub_key);
        let sharing = info.secret_sharing_instance.as_ref();
        let num_shares = sharing.map(|i| i.num_shares());
        let threshold = sharing.map(|i| i.threshold());
        let config_hash = info.config_hash;
        let genesis_state_hash = info.genesis_state_hash;
        let provisioned = info.enclave_btc_pubkey.is_some();
        Ok(BackendStatus {
            session_id: session_id.into(),
            num_shares,
            threshold,
            config_hash,
            genesis_state_hash,
            provisioned,
        })
    }
}

fn check_rostered(fingerprint: &Fingerprint, roster: &[Fingerprint]) -> Result<(), Status> {
    if roster.contains(fingerprint) {
        return Ok(());
    }
    Err(Status::permission_denied(format!(
        "signer {fingerprint} is not in the relay's authorized KP roster"
    )))
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
        request: Request<proto::SignedSingleProvisionerInitRequest>,
    ) -> Result<Response<proto::SingleProvisionerInitResponse>, Status> {
        let submission = request.into_inner();
        let signed_request = KpSigned::<SingleProvisionerInitRequest>::try_from(submission.clone())
            .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))?;

        // Authenticate before the lock or any backend read: junk submissions
        // can't poison the batch, hold the mutex, or cost enclave round-trips.
        let verified_request = self.verify_kp_submission(&signed_request).await?;
        let expected_session_id = verified_request.expected_session_id().to_string();
        let expected_config_hash = *verified_request.expected_config_hash();
        let expected_genesis_state_hash = verified_request.expected_genesis_state_hash();
        let id = u32::from(verified_request.encrypted_share().id.get());

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
        if expected_session_id != status.session_id {
            return Err(Status::failed_precondition(format!(
                "session mismatch: KP pinned {}, backend live session is {} \
                 (guardian restarted? re-run the provision flow)",
                expected_session_id, status.session_id
            )));
        }
        let live_config_hash = status.config_hash.ok_or_else(|| {
            Status::failed_precondition(
                "guardian has no config_hash yet; run `operator provision` first",
            )
        })?;
        if expected_config_hash != live_config_hash {
            return Err(Status::failed_precondition(format!(
                "config hash mismatch: KP pinned {}, backend live config is {}",
                hex::encode(expected_config_hash),
                hex::encode(live_config_hash),
            )));
        }
        if expected_genesis_state_hash != status.genesis_state_hash {
            return Err(Status::failed_precondition(format!(
                "genesis state hash mismatch: KP pinned {:?}, backend live genesis state is {:?}",
                expected_genesis_state_hash.map(hex::encode),
                status.genesis_state_hash.map(hex::encode),
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
        acc.insert(id, submission);
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
        let submissions = acc.batch();
        match self
            .client
            .clone()
            .provisioner_init(proto::ProvisionerInitRequest { submissions })
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
                            "batch ProvisionerInit failed; clearing the submission buffer for resubmission",
                        );
                        acc.clear_submissions();
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
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::KpSigned;
    use hashi_types::guardian::ShareID;
    use hashi_types::guardian::SingleProvisionerInitRequest;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;

    use crate::widlog::test_store::MemStore;
    use std::sync::atomic::Ordering;

    /// A relay whose backend is never dialled — enough to exercise the roster
    /// mapping, which happens before any backend call.
    fn relay_with_roster(store: MemStore) -> Relay<MemStore> {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        Relay::new(channel, Arc::new(RosterCache::new(store)))
    }

    fn submission(id: u32) -> proto::SignedSingleProvisionerInitRequest {
        proto::SignedSingleProvisionerInitRequest {
            encrypted_share: Some(proto::GuardianEncryptedShare {
                id: Some(proto::GuardianShareId { id: Some(id) }),
                ciphertext: None,
            }),
            expected_session_id: "sess-a".into(),
            signer_cert: "cert".into(),
            kp_signature: "signature".into(),
            expected_config_hash: Some(vec![7u8; 32].into()),
            expected_genesis_state_hash: None,
        }
    }

    /// A domain share with a dummy ciphertext.
    fn signed_share(id: u16) -> GuardianEncryptedShare {
        GuardianEncryptedShare {
            id: ShareID::new(id).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![1, 2, 3],
                aes_ciphertext: vec![4, 5, 6],
            },
        }
    }

    /// The store holds no share log, so anything that reaches the roster read
    /// answers FailedPrecondition — an Unauthenticated verdict is proof the
    /// signature was checked first, before any S3 read.
    #[tokio::test]
    async fn bad_signatures_are_rejected_before_the_roster_read() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let relay = relay_with_roster(MemStore::default());

        let request = |session: &str, share_id: u16| {
            SingleProvisionerInitRequest::new(
                session.to_string().into(),
                [7u8; 32],
                None,
                signed_share(share_id),
            )
        };
        let sign = |req: &SingleProvisionerInitRequest| {
            sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(req))
        };
        let good_sig = sign(&request("sess-a", 1));

        for (case, signed) in [
            (
                "signature bound to another share",
                KpSigned::from_parts(request("sess-a", 2), cert.clone(), good_sig.clone()),
            ),
            (
                "signature bound to another session",
                KpSigned::from_parts(
                    request("sess-a", 1),
                    cert.clone(),
                    sign(&request("other-session", 1)),
                ),
            ),
            (
                "missing signature",
                KpSigned::from_parts(request("sess-a", 1), cert.clone(), String::new()),
            ),
        ] {
            let err = relay.verify_kp_submission(&signed).await.unwrap_err();
            assert_eq!(err.code(), tonic::Code::Unauthenticated, "{case}");
        }

        // A signature over the exact submission gets past, on to the roster read.
        let signed = KpSigned::from_parts(request("sess-a", 1), cert, good_sig);
        let err = relay.verify_kp_submission(&signed).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[test]
    fn roster_membership_is_by_fingerprint_value() {
        let cert = PgpPublicCert::new(mock_pgp_keypair().0).unwrap();
        let fingerprint = cert.fingerprint();
        check_rostered(&fingerprint, std::slice::from_ref(&fingerprint)).unwrap();

        // Share-log labels are bare hex, so case must not matter.
        let lowercase: Fingerprint = fingerprint.to_hex().to_lowercase().parse().unwrap();
        check_rostered(&fingerprint, &[lowercase]).unwrap();

        let err = check_rostered(&fingerprint, &[]).unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn roster_store_failure_is_unavailable_and_unclassified() {
        let store = MemStore::default();
        store.fail_lists.store(true, Ordering::SeqCst);
        let err = relay_with_roster(store).authorized_kps().await.unwrap_err();
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
        acc.insert(1, submission(1));
        acc.insert(1, submission(1)); // same KP resubmits
        acc.insert(2, submission(2));
        assert_eq!(acc.have(), 2);
        assert_eq!(acc.batch().len(), 2);
    }

    #[test]
    fn session_change_clears_buffer() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, submission(1));
        acc.insert(2, submission(2));
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
        acc.insert(1, submission(1));
        acc.sync_session("sess-a"); // repeated submit, same session
        assert_eq!(acc.have(), 1);
    }

    #[test]
    fn clear_submissions_empties_buffer_but_keeps_session() {
        let mut acc = Accumulator::default();
        acc.sync_session("sess-a");
        acc.insert(1, submission(1));
        acc.clear_submissions();
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
