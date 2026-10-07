// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Forwards the node/KP-facing `GuardianService` RPCs to the enclave guardian
//! and rejects the operator surface with `PERMISSION_DENIED`: the proxy is
//! internet-facing and `OperatorInit` is one-shot and unauthenticated, so
//! exposing it would let anyone wedge the guardian. KP-signed RPCs are
//! forwarded after a signature and roster check; `ConfirmCeremony` goes to the
//! ceremony guardian, which is the relay's backend. Wrapped by
//! [`crate::node::cache::CachingGuardianGrpc`] to cache `StandardWithdrawal` and
//! `GetGuardianInfo`.

use std::sync::Arc;

use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianService;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::kp;
use crate::kp::roster::RosterCache;
use crate::log_store::LogStore;

/// Holds a plain [`Channel`] rather than the node's boxed transport: the generated
/// server trait requires `Send + Sync + 'static`, and `BoxCloneService` is not `Sync`.
#[derive(Clone)]
pub struct Forwarding<L> {
    client: GuardianServiceClient<Channel>,
    /// The guardian KPs are provisioning, same as the relay's: the standby
    /// when one is configured, else the active guardian.
    ceremony_client: GuardianServiceClient<Channel>,
    /// Shared with the relay: one gate admits every KP-signed RPC, and a cert
    /// rotation drops the cached roster for both.
    roster: Arc<RosterCache<L>>,
}

impl<L: LogStore> Forwarding<L> {
    pub fn new(channel: Channel, ceremony_channel: Channel, roster: Arc<RosterCache<L>>) -> Self {
        Self {
            client: GuardianServiceClient::new(channel),
            ceremony_client: GuardianServiceClient::new(ceremony_channel),
            roster,
        }
    }
}

fn denied(rpc: &str) -> Status {
    Status::permission_denied(format!(
        "{rpc} is not served by the guardian proxy; operator calls reach the \
         guardian directly and KP shares use SingleProvisionerInit"
    ))
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

    async fn get_attested_guardian_info(
        &self,
        request: Request<proto::GetAttestedGuardianInfoRequest>,
    ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
        self.client
            .clone()
            .get_attested_guardian_info(request)
            .await
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
        let signed = kp::parse::<ProvisionerRotateCertRequest, _>(request.get_ref())?;
        kp::admit(&self.roster, &signed).await?;
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
        let signed = kp::parse::<CeremonyConfirmationRequest, _>(request.get_ref())?;
        kp::admit_confirmation(&self.roster, &signed).await?;
        self.ceremony_client.clone().confirm_ceremony(request).await
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
pub(crate) mod test_utils {
    use super::*;
    use hashi_types::proto::guardian_service_server::GuardianServiceServer;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    #[derive(Clone, Default)]
    pub(crate) struct StubGuardian {
        pub(crate) standard_withdrawal_calls: Arc<AtomicUsize>,
        pub(crate) get_guardian_info_calls: Arc<AtomicUsize>,
        pub(crate) get_attested_guardian_info_calls: Arc<AtomicUsize>,
        pub(crate) confirm_ceremony_calls: Arc<AtomicUsize>,
        /// Served by `GetGuardianInfo`; the default response when unset.
        pub(crate) info: Arc<std::sync::Mutex<Option<proto::GetGuardianInfoResponse>>>,
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_attested_guardian_info(
            &self,
            request: Request<proto::GetAttestedGuardianInfoRequest>,
        ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
            assert_eq!(
                request.metadata().get("x-attestation-test").unwrap(),
                "forwarded"
            );
            let call = self
                .get_attested_guardian_info_calls
                .fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(proto::GetAttestedGuardianInfoResponse {
                attestation: Some(vec![call as u8].into()),
                ..Default::default()
            }))
        }

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
            let info = self.info.lock().unwrap().clone();
            Ok(Response::new(info.unwrap_or_default()))
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

    pub(crate) async fn spawn_stub() -> (StubGuardian, tonic::transport::Channel) {
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
        (stub, channel)
    }

    pub(crate) fn mock_request(
        wid: [u8; 32],
        seq: u64,
    ) -> Request<proto::SignedStandardWithdrawalRequest> {
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
}

#[cfg(test)]
mod tests {
    use super::test_utils::*;
    use super::*;
    use crate::node::cache::CachingGuardianGrpc;
    use crate::node::widlog::test_utils::withdrawal_log_json;
    use crate::node::widlog::WidLogIndex;
    use hashi_types::guardian::now_timestamp_ms;
    use hashi_types::guardian::StandardWithdrawalResponse;
    use hashi_types::guardian::WithdrawalID;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    type StubStore = crate::log_store::test_store::MemStore;

    async fn proxy_over(
        active: tonic::transport::Channel,
        ceremony: tonic::transport::Channel,
        store: StubStore,
    ) -> CachingGuardianGrpc<Forwarding<StubStore>, StubStore> {
        let metrics = Arc::new(crate::metrics::ProxyMetrics::new());
        CachingGuardianGrpc::new(
            Forwarding::new(active, ceremony, Arc::new(RosterCache::new(store))),
            WidLogIndex::ready_for_tests(StubStore::default(), metrics.clone()).await,
            metrics,
        )
    }

    /// A proxy whose active and ceremony guardian are the same stub.
    async fn spawn_stub_proxy(
        store: StubStore,
    ) -> (
        StubGuardian,
        CachingGuardianGrpc<Forwarding<StubStore>, StubStore>,
    ) {
        let (stub, channel) = spawn_stub().await;
        (stub, proxy_over(channel.clone(), channel, store).await)
    }

    #[tokio::test]
    async fn forwards_and_replays_over_real_grpc() {
        let (stub, proxy) = spawn_stub_proxy(StubStore::default()).await;

        // The first withdrawal forwards to the stub. The enclave writes the
        // withdrawal log, so a same-wid retry at a bumped seq replays it
        // without a second call to the stub.
        proxy
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap();
        let (key, bytes) = withdrawal_log_json(
            WithdrawalID::new([0x11; 32]),
            0,
            now_timestamp_ms(),
            StandardWithdrawalResponse {
                enclave_signatures: vec![],
            },
        );
        proxy.widlog().store().insert(key, bytes);
        let r2 = proxy
            .standard_withdrawal(mock_request([0x11; 32], 1))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(stub.standard_withdrawal_calls.load(Ordering::SeqCst), 1);
        assert!(r2.data.unwrap().enclave_signatures.is_empty());

        // A non-withdrawal node RPC passes through to the stub.
        proxy
            .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
            .await
            .unwrap();
        assert_eq!(stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn attested_info_bypasses_cache_and_preserves_metadata() {
        let (stub, proxy) = spawn_stub_proxy(StubStore::default()).await;
        for expected in 0..3u8 {
            proxy
                .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
                .await
                .unwrap();
            let mut request = Request::new(proto::GetAttestedGuardianInfoRequest {});
            request
                .metadata_mut()
                .insert("x-attestation-test", "forwarded".parse().unwrap());
            let response = proxy
                .get_attested_guardian_info(request)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.attestation.unwrap().as_ref(), &[expected]);
        }
        assert_eq!(
            stub.get_attested_guardian_info_calls.load(Ordering::SeqCst),
            3
        );
        assert_eq!(stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejects_unsigned_ceremony_confirmation_before_forwarding() {
        let (stub, proxy) = spawn_stub_proxy(StubStore::default()).await;

        let err = proxy
            .confirm_ceremony(Request::new(
                proto::SignedCeremonyConfirmationRequest::default(),
            ))
            .await
            .expect_err("a missing signer attestation must not be forwarded");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(stub.confirm_ceremony_calls.load(Ordering::SeqCst), 0);
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
}
