// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Forwards the node/KP-facing `GuardianService` RPCs to the enclave guardian
//! and rejects the operator surface with `PERMISSION_DENIED`: the proxy is
//! internet-facing and `OperatorInit` is one-shot and unauthenticated, so
//! exposing it would let anyone wedge the guardian. KP-signed RPCs are
//! forwarded after a signature and roster check. Wrapped by
//! [`crate::cache::CachingGuardianGrpc`] to cache `StandardWithdrawal`.

use std::sync::Arc;

use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::KpSigningIntent;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianService;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::roster::RosterCache;
use crate::widlog::LogStore;

/// Holds a plain [`Channel`] rather than the node's boxed transport: the generated
/// server trait requires `Send + Sync + 'static`, and `BoxCloneService` is not `Sync`.
#[derive(Clone)]
pub struct Forwarding<L> {
    client: GuardianServiceClient<Channel>,
    /// Shared with the relay: one gate admits every KP-signed RPC, and a cert
    /// rotation drops the cached roster for both.
    roster: Arc<RosterCache<L>>,
}

impl<L: LogStore> Forwarding<L> {
    pub fn new(channel: Channel, roster: Arc<RosterCache<L>>) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            roster,
        }
    }

    /// Admission control only: the enclave repeats both checks. Signature
    /// first because it needs no roster read.
    async fn admit<T, P>(&self, request: &P) -> Result<(), Status>
    where
        T: KpSigningIntent,
        P: Clone,
        KpSigned<T>: TryFrom<P, Error = GuardianError>,
    {
        let signer = verify_kp_signature::<T, P>(request)?.signer_fingerprint();
        self.roster.authorize(&signer).await
    }
}

fn denied(rpc: &str) -> Status {
    Status::permission_denied(format!(
        "{rpc} is not served by the guardian proxy; operator calls reach the \
         guardian directly and KP shares use SingleProvisionerInit"
    ))
}

fn verify_kp_signature<T, P>(request: &P) -> Result<KpSigned<T>, Status>
where
    T: KpSigningIntent,
    P: Clone,
    KpSigned<T>: TryFrom<P, Error = GuardianError>,
{
    let signed_request = KpSigned::<T>::try_from(request.clone())
        .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))?;
    signed_request
        .verify_signature()
        .map_err(|e| Status::unauthenticated(e.to_string()))?;
    Ok(signed_request)
}

// Each method clones the cheap channel-backed client and forwards the whole
// `Request<T>` so client deadlines/metadata propagate.
#[tonic::async_trait]
impl<L: LogStore> GuardianService for Forwarding<L> {
    async fn get_guardian_info(
        &self,
        request: Request<proto::GetGuardianInfoRequest>,
    ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
        self.client.clone().get_guardian_info(request).await
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        self.client.clone().standard_withdrawal(request).await
    }

    async fn update_committee(
        &self,
        request: Request<proto::SignedCommitteeTransition>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        self.client.clone().update_committee(request).await
    }

    async fn update_committee_chain(
        &self,
        request: Request<proto::UpdateCommitteeChainRequest>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        self.client.clone().update_committee_chain(request).await
    }

    async fn provisioner_rotate_cert(
        &self,
        request: Request<proto::SignedProvisionerRotateCertRequest>,
    ) -> Result<Response<proto::SignedProvisionerRotateCertResponse>, Status> {
        self.admit::<ProvisionerRotateCertRequest, _>(request.get_ref())
            .await?;
        let response = self.client.clone().provisioner_rotate_cert(request).await?;
        // The enclave has committed the replacement cert to the share log, so
        // drop the cached roster: otherwise the new cert is rejected until the
        // TTL lapses.
        self.roster.invalidate().await;
        Ok(response)
    }

    // Safe to expose: the enclave binds each confirmation to its session, the
    // ceremony digest and the dealt roster.
    async fn confirm_ceremony(
        &self,
        request: Request<proto::SignedCeremonyConfirmationRequest>,
    ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
        self.admit::<CeremonyConfirmationRequest, _>(request.get_ref())
            .await?;
        self.client.clone().confirm_ceremony(request).await
    }

    // --- Rejected: operator surface ---

    async fn operator_init(
        &self,
        _request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        Err(denied("OperatorInit"))
    }

    async fn setup_new_key(
        &self,
        _request: Request<proto::SetupNewKeyRequest>,
    ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        Err(denied("SetupNewKey"))
    }

    async fn provisioner_init(
        &self,
        _request: Request<proto::BatchProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        Err(denied("ProvisionerInit (use SingleProvisionerInit)"))
    }

    async fn operator_activate(
        &self,
        _request: Request<proto::OperatorActivateRequest>,
    ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
        Err(denied("OperatorActivate"))
    }

    async fn rotate_kp_set(
        &self,
        _request: Request<proto::BatchProvisionerRotateKpSetRequest>,
    ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
        Err(denied("RotateKpSet"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachingGuardianGrpc;
    use crate::roster::test_utils::seed_roster;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::ShareID;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;
    use hashi_types::proto::guardian_service_server::GuardianServiceServer;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    #[derive(Clone, Default)]
    struct StubGuardian {
        standard_withdrawal_calls: Arc<AtomicUsize>,
        get_guardian_info_calls: Arc<AtomicUsize>,
        confirm_ceremony_calls: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn standard_withdrawal(
            &self,
            _: Request<proto::SignedStandardWithdrawalRequest>,
        ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
            self.standard_withdrawal_calls
                .fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(proto::SignedStandardWithdrawalResponse {
                data: Some(proto::StandardWithdrawalResponseData {
                    enclave_signatures: vec![vec![7u8; 64].into()],
                }),
                timestamp_ms: Some(1),
                signature: Some(vec![9u8; 64].into()),
            }))
        }

        async fn get_guardian_info(
            &self,
            _: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            self.get_guardian_info_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(proto::GetGuardianInfoResponse::default()))
        }

        async fn setup_new_key(
            &self,
            _: Request<proto::SetupNewKeyRequest>,
        ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
        async fn confirm_ceremony(
            &self,
            _: Request<proto::SignedCeremonyConfirmationRequest>,
        ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
            self.confirm_ceremony_calls.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(proto::CeremonyConfirmationResponse {
                have: Some(1),
                need: Some(3),
                completed: Some(false),
            }))
        }
        async fn operator_init(
            &self,
            _: Request<proto::OperatorInitRequest>,
        ) -> Result<Response<proto::OperatorInitResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
        async fn provisioner_init(
            &self,
            _: Request<proto::BatchProvisionerInitRequest>,
        ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
        async fn provisioner_rotate_cert(
            &self,
            _: Request<proto::SignedProvisionerRotateCertRequest>,
        ) -> Result<Response<proto::SignedProvisionerRotateCertResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn operator_activate(
            &self,
            _: Request<proto::OperatorActivateRequest>,
        ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
        async fn update_committee(
            &self,
            _: Request<proto::SignedCommitteeTransition>,
        ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn update_committee_chain(
            &self,
            _: Request<proto::UpdateCommitteeChainRequest>,
        ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn rotate_kp_set(
            &self,
            _: Request<proto::BatchProvisionerRotateKpSetRequest>,
        ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
    }

    fn mock_request(wid: [u8; 32], seq: u64) -> Request<proto::SignedStandardWithdrawalRequest> {
        Request::new(proto::SignedStandardWithdrawalRequest {
            data: Some(proto::StandardWithdrawalRequestData {
                wid: Some(wid.to_vec().into()),
                utxos: None,
                timestamp_secs: Some(100),
                seq: Some(seq),
            }),
            committee_signature: None,
        })
    }

    type StubStore = crate::widlog::test_store::MemStore;

    async fn spawn_stub_proxy(
        store: StubStore,
    ) -> (
        StubGuardian,
        CachingGuardianGrpc<Forwarding<StubStore>, StubStore>,
    ) {
        let stub = StubGuardian::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = GuardianServiceServer::new(stub.clone());
        tokio::spawn(async move {
            Server::builder()
                .add_service(server)
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        // Let the spawned server start serving HTTP/2 before the first call.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect_lazy();
        let cache = CachingGuardianGrpc::new(
            Forwarding::new(channel, Arc::new(RosterCache::new(store))),
            StubStore::default(),
            bitcoin::Network::Regtest,
            std::sync::Arc::new(crate::metrics::ProxyMetrics::new()),
        );
        (stub, cache)
    }

    #[tokio::test]
    async fn forwards_and_caches_over_real_grpc() {
        let (stub, proxy) = spawn_stub_proxy(StubStore::default()).await;

        // First withdrawal forwards to the stub; a same-wid retry at a bumped
        // seq replays the cached response without re-calling the stub.
        let r1 = proxy
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap()
            .into_inner();
        let r2 = proxy
            .standard_withdrawal(mock_request([0x11; 32], 1))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stub.standard_withdrawal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(r1, r2);

        // A non-withdrawal node RPC passes through to the stub.
        proxy
            .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
            .await
            .unwrap();
        assert_eq!(stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);
    }

    fn signed_confirmation(
        cert: &PgpPublicCert,
        secret_armored: &str,
    ) -> proto::SignedCeremonyConfirmationRequest {
        let domain = CeremonyConfirmationRequest::new("session".into(), [3u8; 32]);
        let signature = sign_detached_in_process(secret_armored, &KpSigned::signed_bytes(&domain));
        proto::SignedCeremonyConfirmationRequest::from(KpSigned::from_parts(
            domain,
            cert.clone(),
            signature,
        ))
    }

    #[tokio::test]
    async fn forwards_a_rostered_ceremony_confirmation() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let store = StubStore::default();
        seed_roster(&store, 0, &[&cert.fingerprint().to_hex()]);
        let (stub, proxy) = spawn_stub_proxy(store).await;

        let status = proxy
            .confirm_ceremony(Request::new(signed_confirmation(&cert, &secret_armored)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.have, Some(1));
        assert_eq!(stub.confirm_ceremony_calls.load(Ordering::SeqCst), 1);

        // A corrupt confirmation is refused before the backend sees it.
        let err = proxy
            .confirm_ceremony(Request::new(
                proto::SignedCeremonyConfirmationRequest::default(),
            ))
            .await
            .expect_err("an unsigned confirmation must not be forwarded");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(stub.confirm_ceremony_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_an_unrostered_ceremony_confirmation() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let store = StubStore::default();
        seed_roster(&store, 0, &["AAAABBBBCCCCDDDDEEEE11112222333344445555"]);
        let (stub, proxy) = spawn_stub_proxy(store).await;

        let err = proxy
            .confirm_ceremony(Request::new(signed_confirmation(&cert, &secret_armored)))
            .await
            .expect_err("a signer outside the roster must not be forwarded");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(stub.confirm_ceremony_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn verifies_ceremony_confirmation_signature_before_forwarding() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored).unwrap();
        let mut request = signed_confirmation(&cert, &secret_armored);
        verify_kp_signature::<CeremonyConfirmationRequest, _>(&request).unwrap();

        request.expected_session_id.push('0');
        let err = verify_kp_signature::<CeremonyConfirmationRequest, _>(&request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // The stub `unimplemented!()`s the rejected RPCs, so a forwarded call would panic
    // the server rather than return `PERMISSION_DENIED` — proof the proxy short-circuits.
    #[tokio::test]
    async fn rejects_operator_rpcs() {
        let (_stub, proxy) = spawn_stub_proxy(StubStore::default()).await;

        let denied = proxy
            .operator_init(Request::new(proto::OperatorInitRequest::default()))
            .await
            .expect_err("operator_init must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .operator_activate(Request::new(proto::OperatorActivateRequest::default()))
            .await
            .expect_err("operator_activate must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .provisioner_init(Request::new(proto::BatchProvisionerInitRequest::default()))
            .await
            .expect_err("provisioner_init must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .setup_new_key(Request::new(proto::SetupNewKeyRequest::default()))
            .await
            .expect_err("setup_new_key must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .rotate_kp_set(Request::new(
                proto::BatchProvisionerRotateKpSetRequest::default(),
            ))
            .await
            .expect_err("rotate_kp_set must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn verifies_provisioner_rotate_cert_signature_before_forwarding() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored.clone()).unwrap();
        let domain = ProvisionerRotateCertRequest::from_encrypted_share_for_testing(
            "session".into(),
            0,
            cert.clone(),
            GuardianEncryptedShare {
                id: ShareID::new(1).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![1, 2, 3],
                    aes_ciphertext: vec![4, 5, 6],
                },
            },
        );
        let signature = sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(&domain));
        let mut request = proto::SignedProvisionerRotateCertRequest::from(KpSigned::from_parts(
            domain, cert, signature,
        ));

        verify_kp_signature::<ProvisionerRotateCertRequest, _>(&request).unwrap();

        request
            .new_kp_pgp_cert_bundle
            .as_mut()
            .unwrap()
            .sig_attestation_pem = Some(b"tampered".to_vec().into());
        let err = verify_kp_signature::<ProvisionerRotateCertRequest, _>(&request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
