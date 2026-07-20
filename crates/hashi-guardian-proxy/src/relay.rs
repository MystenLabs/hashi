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

use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianError;
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
pub struct Relay {
    client: GuardianServiceClient<Channel>,
    accumulator: Arc<Mutex<Accumulator>>,
    /// Fingerprints of the KPs allowed to submit shares (the ceremony roster,
    /// via deploy config). Empty rejects every submission — fail closed.
    authorized_kp_fingerprints: Vec<Fingerprint>,
}

impl Relay {
    pub fn new(channel: Channel, authorized_kp_fingerprints: Vec<Fingerprint>) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            accumulator: Arc::new(Mutex::new(Accumulator::default())),
            authorized_kp_fingerprints,
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

/// Pre-authenticate a submission: the signer's cert must be in the configured
/// relay roster and its detached signature must cover these exact
/// (session, config, share) bytes. This is only a DoS guard; the enclave repeats
/// signature verification authoritatively.
fn verify_kp_submission(
    signed_request: &KpSigned<SingleProvisionerInitRequest>,
    authorized_kp_fingerprints: &[Fingerprint],
) -> Result<(), Status> {
    let fingerprint = signed_request.signer_fingerprint();
    if !authorized_kp_fingerprints.contains(&fingerprint) {
        return Err(Status::permission_denied(format!(
            "signer {fingerprint} is not in the relay's authorized KP roster"
        )));
    }
    signed_request
        .verify_signature()
        .map_err(kp_signature_error_status)
}

fn kp_signature_error_status(error: GuardianError) -> Status {
    match error {
        GuardianError::InvalidInputs(msg) => Status::unauthenticated(msg),
        other => Status::unauthenticated(other.to_string()),
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
        request: Request<proto::SignedSingleProvisionerInitRequest>,
    ) -> Result<Response<proto::SingleProvisionerInitResponse>, Status> {
        // No roster configured (proxy deployed before its ceremony): fail closed.
        if self.authorized_kp_fingerprints.is_empty() {
            return Err(Status::failed_precondition(
                "relay has no authorized KP roster configured; \
                 set AUTHORIZED_KP_FINGERPRINTS on the proxy",
            ));
        }

        let submission = request.into_inner();
        let signed_request = KpSigned::<SingleProvisionerInitRequest>::try_from(submission.clone())
            .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))?;

        // Authenticate before the lock or any backend read: junk submissions
        // can't poison the batch, hold the mutex, or cost enclave round-trips.
        verify_kp_submission(&signed_request, &self.authorized_kp_fingerprints)?;
        let expected_session_id = signed_request.data.expected_session_id().to_string();
        let expected_config_hash = *signed_request.data.expected_config_hash();
        let expected_genesis_state_hash = signed_request.data.expected_genesis_state_hash();
        let id = u32::from(signed_request.data.encrypted_share().id.get());

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

    #[test]
    fn verify_kp_submission_gates_on_roster_and_signature() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored.clone()).unwrap();
        let roster = vec![cert.fingerprint()];
        let session = "sess-a";

        let domain_share = signed_share(1);
        let config_hash = [7u8; 32];
        let request = SingleProvisionerInitRequest::new(
            session.to_string().into(),
            config_hash,
            None,
            domain_share.clone(),
        );
        let signed_bytes = KpSigned::signed_bytes(&request);
        let good_sig = sign_detached_in_process(&secret_armored, &signed_bytes);
        let signed_request = KpSigned {
            data: request.clone(),
            signer_cert: cert.clone(),
            signature: good_sig.clone(),
        };

        // A rostered signer with a valid signature over the exact submission passes.
        verify_kp_submission(&signed_request, &roster).unwrap();

        // A roster entry parsed from config text (lowercase bare hex) matches too.
        let from_config: Fingerprint = cert.fingerprint().to_hex().to_lowercase().parse().unwrap();
        verify_kp_submission(&signed_request, &[from_config]).unwrap();

        let other_share = signed_share(2);
        let other_request = SingleProvisionerInitRequest::new(
            session.to_string().into(),
            config_hash,
            None,
            other_share,
        );
        let signed_other_share = KpSigned {
            data: other_request,
            signer_cert: cert.clone(),
            signature: good_sig.clone(),
        };
        assert!(
            verify_kp_submission(&signed_other_share, &roster).is_err(),
            "signature bound to another share must be rejected"
        );

        assert!(
            verify_kp_submission(&signed_request, &[]).is_err(),
            "non-rostered signer must be rejected"
        );

        let missing_signature = KpSigned {
            data: request.clone(),
            signer_cert: cert.clone(),
            signature: String::new(),
        };
        assert!(
            verify_kp_submission(&missing_signature, &roster).is_err(),
            "missing signature must be rejected"
        );

        let other_session_request = SingleProvisionerInitRequest::new(
            "other-session".into(),
            config_hash,
            None,
            domain_share,
        );
        let other_bytes = KpSigned::signed_bytes(&other_session_request);
        let stale_sig = sign_detached_in_process(&secret_armored, &other_bytes);
        let stale_request = KpSigned {
            data: request,
            signer_cert: cert,
            signature: stale_sig,
        };
        assert!(
            verify_kp_submission(&stale_request, &roster).is_err(),
            "signature bound to another session must be rejected"
        );
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
