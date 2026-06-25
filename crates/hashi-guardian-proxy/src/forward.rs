// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Adapts a tonic *client* to the enclave guardian into the gRPC *server*
//! trait, forwarding every RPC unchanged. Wrapped by
//! [`crate::cache::CachingGuardianGrpc`] so `StandardWithdrawal` responses are
//! cached out-of-enclave; all other RPCs are pure passthrough.

use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use hashi_types::proto::guardian_service_server::GuardianService;
use tonic::transport::Channel;
use tonic::Request;
use tonic::Response;
use tonic::Status;

/// Forwards all eight `GuardianService` RPCs to a remote enclave guardian.
///
/// Holds a plain [`Channel`] (cheap to clone, `Send + Sync + 'static`) rather
/// than the node's boxed transport — the generated server trait requires
/// `Send + Sync + 'static`, and `BoxCloneService` is not `Sync`.
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

// Each method clones the channel-backed client (the generated client takes
// `&mut self`; cloning a `Channel` is a cheap handle copy) and forwards the
// whole `Request<T>`, so client deadlines/metadata propagate. Transport errors
// surface as `Status` and pass straight through.
#[tonic::async_trait]
impl GuardianService for Forwarding {
    async fn get_guardian_info(
        &self,
        request: Request<proto::GetGuardianInfoRequest>,
    ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
        self.client.clone().get_guardian_info(request).await
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        self.client.clone().setup_new_key(request).await
    }

    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        self.client.clone().operator_init(request).await
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::ProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        self.client.clone().provisioner_init(request).await
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

    async fn rotate_kps(
        &self,
        request: Request<proto::RotateKpsRequest>,
    ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
        self.client.clone().rotate_kps(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::CachingGuardianGrpc;
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
            unimplemented!("not exercised by tests")
        }
        async fn operator_init(
            &self,
            _: Request<proto::OperatorInitRequest>,
        ) -> Result<Response<proto::OperatorInitResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn provisioner_init(
            &self,
            _: Request<proto::ProvisionerInitRequest>,
        ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
            unimplemented!("not exercised by tests")
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
            unimplemented!("not exercised by tests")
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

    /// End-to-end over a real gRPC hop: `Forwarding` reaches the stub guardian,
    /// and the `CachingGuardianGrpc` wrapper makes a same-wid retry idempotent
    /// while passing other RPCs straight through.
    #[tokio::test]
    async fn forwards_and_caches_over_real_grpc() {
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
        let proxy = CachingGuardianGrpc::new(Forwarding::new(channel));

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

        // A non-withdrawal RPC passes through to the stub.
        proxy
            .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
            .await
            .unwrap();
        assert_eq!(stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);
    }
}
