// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Temporary in-process response cache for the guardian's `StandardWithdrawal`
//! RPC. Lives on the throwaway `siddharth/guardian-response-cache` branch and is
//! not intended for merge — the Nitro design pulls this layer out into an
//! out-of-enclave proxy.
//!
//! Hashi today has no recovery path when guardian returns "seq mismatch": any
//! transient gRPC failure that advances guardian's `next_seq` before hashi
//! observes the response leaves the wid permanently stuck. Caching the response
//! keyed by `(wid, seq)` lets a same-seq retry hit the cache and recover; a
//! bumped-seq retry (after a hashi restart that re-bootstraps the local limiter
//! from guardian) correctly misses and re-issues the upstream call, keeping the
//! guardian and local limiter in lock-step.

use hashi_types::guardian::WithdrawalID;
use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;

struct CacheEntry {
    seq: u64,
    response: proto::SignedStandardWithdrawalResponse,
}

pub struct CachingGuardianGrpc<S> {
    inner: S,
    cache: Arc<Mutex<HashMap<WithdrawalID, CacheEntry>>>,
}

impl<S> CachingGuardianGrpc<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn try_hit(
        &self,
        wid: &WithdrawalID,
        seq: u64,
    ) -> Option<proto::SignedStandardWithdrawalResponse> {
        self.cache
            .lock()
            .await
            .get(wid)
            .filter(|entry| entry.seq == seq)
            .map(|entry| entry.response.clone())
    }

    async fn store(
        &self,
        wid: WithdrawalID,
        seq: u64,
        response: proto::SignedStandardWithdrawalResponse,
    ) {
        self.cache
            .lock()
            .await
            .insert(wid, CacheEntry { seq, response });
    }
}

fn extract_wid_and_seq(
    req: &proto::SignedStandardWithdrawalRequest,
) -> Option<(WithdrawalID, u64)> {
    let data = req.data.as_ref()?;
    let wid_bytes = data.wid.as_ref()?;
    let seq = data.seq?;
    let wid = WithdrawalID::from_bytes(wid_bytes.as_ref()).ok()?;
    Some((wid, seq))
}

#[tonic::async_trait]
impl<S> GuardianService for CachingGuardianGrpc<S>
where
    S: GuardianService,
{
    async fn get_guardian_info(
        &self,
        request: Request<proto::GetGuardianInfoRequest>,
    ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
        self.inner.get_guardian_info(request).await
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        self.inner.setup_new_key(request).await
    }

    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        self.inner.operator_init(request).await
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::ProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        self.inner.provisioner_init(request).await
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        let key = extract_wid_and_seq(request.get_ref());

        if let Some((wid, seq)) = key {
            if let Some(cached) = self.try_hit(&wid, seq).await {
                info!(%wid, seq, "Cache hit; returning stored StandardWithdrawal response");
                return Ok(Response::new(cached));
            }
        }

        let response_inner = self.inner.standard_withdrawal(request).await?.into_inner();

        if let Some((wid, seq)) = key {
            self.store(wid, seq, response_inner.clone()).await;
            info!(%wid, seq, "Stored StandardWithdrawal response in cache");
        }

        Ok(Response::new(response_inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    type ResponseFn =
        dyn Fn() -> Result<proto::SignedStandardWithdrawalResponse, Status> + Send + Sync;

    struct StubGuardian {
        call_count: Arc<AtomicUsize>,
        result: Arc<ResponseFn>,
    }

    impl StubGuardian {
        fn ok() -> (Self, Arc<AtomicUsize>) {
            let call_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: call_count.clone(),
                    result: Arc::new(|| Ok(mock_response())),
                },
                call_count,
            )
        }

        fn err() -> (Self, Arc<AtomicUsize>) {
            let call_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: call_count.clone(),
                    result: Arc::new(|| Err(Status::failed_precondition("simulated"))),
                },
                call_count,
            )
        }
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_guardian_info(
            &self,
            _: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            unimplemented!("not exercised by tests")
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
        async fn standard_withdrawal(
            &self,
            _: Request<proto::SignedStandardWithdrawalRequest>,
        ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            (self.result)().map(Response::new)
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

    fn mock_response() -> proto::SignedStandardWithdrawalResponse {
        proto::SignedStandardWithdrawalResponse {
            data: Some(proto::StandardWithdrawalResponseData {
                enclave_signatures: vec![vec![0u8; 64].into()],
            }),
            timestamp_ms: Some(123),
            signature: Some(vec![1u8; 64].into()),
        }
    }

    #[tokio::test]
    async fn same_wid_and_seq_hits_cache_after_first_call() {
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::new(stub);

        let r1 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap()
            .into_inner();
        let r2 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "second call should hit cache"
        );
        assert_eq!(r1, r2);
    }

    #[tokio::test]
    async fn bumped_seq_for_same_wid_misses_and_re_forwards() {
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::new(stub);

        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        cache
            .standard_withdrawal(mock_request([0xaa; 32], 1))
            .await
            .unwrap();

        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "different seq must not be served from cache"
        );
    }

    #[tokio::test]
    async fn errors_are_not_cached() {
        let (stub, count) = StubGuardian::err();
        let cache = CachingGuardianGrpc::new(stub);

        let r1 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;
        let r2 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;

        assert_eq!(count.load(Ordering::SeqCst), 2, "errors should re-forward");
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn missing_wid_falls_through_to_inner() {
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::new(stub);

        let req = Request::new(proto::SignedStandardWithdrawalRequest {
            data: Some(proto::StandardWithdrawalRequestData {
                wid: None,
                utxos: None,
                timestamp_secs: Some(100),
                seq: Some(0),
            }),
            committee_signature: None,
        });

        let _ = cache.standard_withdrawal(req).await;
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn distinct_wids_are_cached_independently() {
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::new(stub);

        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        cache
            .standard_withdrawal(mock_request([0xbb; 32], 0))
            .await
            .unwrap();
        // Each wid is fresh, so both forward.
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // Re-hit both — should be served from cache now.
        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        cache
            .standard_withdrawal(mock_request([0xbb; 32], 0))
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2, "both retries should hit");
    }
}
