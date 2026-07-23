// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Forwards the node/KP-facing `GuardianService` RPCs to the enclave guardian
//! and rejects the operator/ceremony surface with `PERMISSION_DENIED`: the proxy
//! is internet-facing and `OperatorInit` is one-shot and unauthenticated, so
//! exposing it would let anyone wedge the guardian. Wrapped by
//! [`crate::cache::CachingGuardianGrpc`] to cache `StandardWithdrawal`.

use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianService;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

/// Holds a plain [`Channel`] rather than the node's boxed transport: the generated
/// server trait requires `Send + Sync + 'static`, and `BoxCloneService` is not `Sync`.
#[derive(Clone)]
pub struct Forwarding {
    client: GuardianServiceClient<Channel>,
}

impl Forwarding {
    pub fn new(channel: Channel) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
        }
    }
}

fn denied(rpc: &str) -> Status {
    Status::permission_denied(format!(
        "{rpc} is not served by the guardian proxy; operator/ceremony calls reach the \
         guardian directly and KP shares use SingleProvisionerInit"
    ))
}

fn verify_provisioner_rotate_cert_signature(
    request: &proto::SignedProvisionerRotateCertRequest,
) -> Result<(), Status> {
    let signed_request = KpSigned::<ProvisionerRotateCertRequest>::try_from(request.clone())
        .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))?;
    signed_request
        .verify()
        .map_err(|error| Status::unauthenticated(error.to_string()))?;
    Ok(())
}

// Each method clones the cheap channel-backed client and forwards the whole
// `Request<T>` so client deadlines/metadata propagate.
#[tonic::async_trait]
impl GuardianService for Forwarding {
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
        // Admission control only: reject unsigned or corrupt traffic before an
        // enclave round-trip. The enclave repeats verification and authorizes
        // the signer against the latest encrypted-share roster.
        // TODO: Once proxy authorization uses the S3-backed roster, check the
        // signer here and invalidate the cached roster after a successful
        // rotation so the next request observes the replacement cert.
        verify_provisioner_rotate_cert_signature(request.get_ref())?;
        self.client.clone().provisioner_rotate_cert(request).await
    }

    // --- Rejected: operator/ceremony surface ---

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
        _request: Request<proto::ProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        Err(denied("ProvisionerInit (use SingleProvisionerInit)"))
    }

    async fn operator_activate(
        &self,
        _request: Request<proto::OperatorActivateRequest>,
    ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
        Err(denied("OperatorActivate"))
    }

    async fn rotate_kps(
        &self,
        _request: Request<proto::RotateKpsRequest>,
    ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
        Err(denied("RotateKps"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachingGuardianGrpc;
    use hashi_types::guardian::proto_conversions::guardian_encrypted_share_to_pb;
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
        async fn operator_init(
            &self,
            _: Request<proto::OperatorInitRequest>,
        ) -> Result<Response<proto::OperatorInitResponse>, Status> {
            unimplemented!("a real guardian would serve this; the proxy must never reach it")
        }
        async fn provisioner_init(
            &self,
            _: Request<proto::ProvisionerInitRequest>,
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
        async fn rotate_kps(
            &self,
            _: Request<proto::RotateKpsRequest>,
        ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
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

    async fn spawn_stub_proxy() -> (
        StubGuardian,
        CachingGuardianGrpc<Forwarding, crate::widlog::test_store::MemStore>,
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
            Forwarding::new(channel),
            crate::widlog::test_store::MemStore::default(),
            bitcoin::Network::Regtest,
            std::sync::Arc::new(crate::metrics::ProxyMetrics::new()),
        );
        (stub, cache)
    }

    #[tokio::test]
    async fn forwards_and_caches_over_real_grpc() {
        let (stub, proxy) = spawn_stub_proxy().await;

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

    // The stub `unimplemented!()`s the rejected RPCs, so a forwarded call would panic
    // the server rather than return `PERMISSION_DENIED` — proof the proxy short-circuits.
    #[tokio::test]
    async fn rejects_operator_and_ceremony_rpcs() {
        let (_stub, proxy) = spawn_stub_proxy().await;

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
            .provisioner_init(Request::new(proto::ProvisionerInitRequest::default()))
            .await
            .expect_err("provisioner_init must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .setup_new_key(Request::new(proto::SetupNewKeyRequest::default()))
            .await
            .expect_err("setup_new_key must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);

        let denied = proxy
            .rotate_kps(Request::new(proto::RotateKpsRequest::default()))
            .await
            .expect_err("rotate_kps must be denied");
        assert_eq!(denied.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn verifies_provisioner_rotate_cert_signature_before_forwarding() {
        let (cert_armored, secret_armored) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(cert_armored.clone()).unwrap();
        let mut request = proto::SignedProvisionerRotateCertRequest {
            new_kp_pgp_cert: cert_armored.clone(),
            encrypted_share: Some(guardian_encrypted_share_to_pb(GuardianEncryptedShare {
                id: ShareID::new(1).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![1, 2, 3],
                    aes_ciphertext: vec![4, 5, 6],
                },
            })),
            expected_session_id: "session".into(),
            signer_cert: cert_armored,
            kp_signature: "placeholder".into(),
            expected_cert_seq: Some(0),
            target_kp_pgp_fingerprint: cert.fingerprint().to_hex(),
        };
        let domain = KpSigned::<ProvisionerRotateCertRequest>::try_from(request.clone()).unwrap();
        request.kp_signature =
            sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(&domain.data));

        verify_provisioner_rotate_cert_signature(&request).unwrap();

        request.target_kp_pgp_fingerprint.push('0');
        let err = verify_provisioner_rotate_cert_signature(&request).unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
