// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wid-keyed response cache for the guardian's `StandardWithdrawal` RPC. Lives in
//! the out-of-enclave proxy so it can be hardened or swapped independently of the
//! signing oracle (the enclave now serves the bare `GuardianService`).
//!
//! Keyed by `wid`, not `(wid, seq)`: the guardian debits the limiter and advances
//! `next_seq` when it signs, before hashi has the signed event on-chain. If hashi
//! retries the same wid at a bumped seq (its limiter mirror reconciled forward
//! while the event was still pending), re-consuming would drain the bucket for a
//! withdrawal that was already signed. Replaying by `wid` avoids that — safe
//! because a committed wid's inputs/outputs are immutable (only signatures
//! change), so the response is stable and carries no seq.
//!
//! In-memory and bounded (LRU, `CACHE_CAPACITY` entries): a wid lost to eviction
//! or a proxy restart re-consumes the enclave limiter on its next retry — same as
//! the old in-enclave behaviour, so no regression. A durable backend (e.g.
//! DynamoDB) is a future option this extraction enables.

use hashi_types::guardian::WithdrawalID;
use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;

// One entry per withdrawal would leak forever; 10k far exceeds the rate-limited
// in-flight working set, so a hot wid always outlives its retry window.
const CACHE_CAPACITY: usize = 10_000;

struct CacheEntry {
    /// The seq the guardian consumed this wid at. Kept for observability only —
    /// the cache is keyed by `wid`, so lookups ignore the requester's seq.
    consumed_seq: u64,
    response: proto::SignedStandardWithdrawalResponse,
}

pub struct CachingGuardianGrpc<S> {
    inner: S,
    cache: Mutex<LruCache<WithdrawalID, CacheEntry>>,
}

impl<S> CachingGuardianGrpc<S> {
    pub fn new(inner: S) -> Self {
        Self::with_capacity(
            inner,
            NonZeroUsize::new(CACHE_CAPACITY).expect("CACHE_CAPACITY > 0"),
        )
    }

    fn with_capacity(inner: S, capacity: NonZeroUsize) -> Self {
        Self {
            inner,
            cache: Mutex::new(LruCache::new(capacity)),
        }
    }

    // The critical section never spans an `.await`, so a sync `std::sync::Mutex`
    // is the right tool and keeps the handler future `Send`. Panics abort the
    // process (see `abort_on_panic` in main), so a poisoned lock is unreachable.
    fn try_hit(
        &self,
        wid: &WithdrawalID,
    ) -> Option<(u64, proto::SignedStandardWithdrawalResponse)> {
        let mut cache = self.cache.lock().expect("cache mutex poisoned");
        cache
            .get(wid)
            .map(|entry| (entry.consumed_seq, entry.response.clone()))
    }

    fn store(
        &self,
        wid: WithdrawalID,
        consumed_seq: u64,
        response: proto::SignedStandardWithdrawalResponse,
    ) {
        self.cache.lock().expect("cache mutex poisoned").put(
            wid,
            CacheEntry {
                consumed_seq,
                response,
            },
        );
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

    async fn operator_activate(
        &self,
        request: Request<proto::OperatorActivateRequest>,
    ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
        self.inner.operator_activate(request).await
    }

    async fn standard_withdrawal(
        &self,
        request: Request<proto::SignedStandardWithdrawalRequest>,
    ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
        let key = extract_wid_and_seq(request.get_ref());

        if let Some((wid, seq)) = key {
            if let Some((consumed_seq, cached)) = self.try_hit(&wid) {
                info!(
                    %wid,
                    requested_seq = seq,
                    consumed_seq,
                    "Cache hit; replaying stored StandardWithdrawal response (idempotent by wid)"
                );
                return Ok(Response::new(cached));
            }
        }

        let response_inner = self.inner.standard_withdrawal(request).await?.into_inner();

        if let Some((wid, seq)) = key {
            self.store(wid, seq, response_inner.clone());
            info!(%wid, seq, "Stored StandardWithdrawal response in cache");
        }

        Ok(Response::new(response_inner))
    }

    async fn update_committee(
        &self,
        request: Request<proto::SignedCommitteeTransition>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        self.inner.update_committee(request).await
    }

    async fn update_committee_chain(
        &self,
        request: Request<proto::UpdateCommitteeChainRequest>,
    ) -> Result<Response<proto::UpdateCommitteeResponse>, Status> {
        self.inner.update_committee_chain(request).await
    }

    async fn rotate_kps(
        &self,
        request: Request<proto::RotateKpsRequest>,
    ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
        self.inner.rotate_kps(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

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
        async fn operator_activate(
            &self,
            _: Request<proto::OperatorActivateRequest>,
        ) -> Result<Response<proto::OperatorActivateResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn standard_withdrawal(
            &self,
            _: Request<proto::SignedStandardWithdrawalRequest>,
        ) -> Result<Response<proto::SignedStandardWithdrawalResponse>, Status> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            (self.result)().map(Response::new)
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
    async fn bumped_seq_for_same_wid_is_idempotent() {
        // A retry of the same wid at a *different* seq (e.g. the local limiter
        // mirror reconciled forward to the guardian's advanced next_seq) must
        // replay the cached response without re-consuming the guardian limiter —
        // otherwise the bucket drains for a withdrawal that was already signed.
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::new(stub);

        let r1 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap()
            .into_inner();
        let r2 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 1))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "same wid at a bumped seq must hit the cache, not re-consume"
        );
        assert_eq!(r1, r2, "bumped-seq retry must replay the same response");
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

    #[tokio::test]
    async fn evicts_lru_entry_when_over_capacity() {
        let (stub, count) = StubGuardian::ok();
        let cache = CachingGuardianGrpc::with_capacity(stub, NonZeroUsize::new(2).unwrap());

        // Three distinct wids into a capacity-2 cache evicts the first (LRU).
        for wid in [[0xa1; 32], [0xb2; 32], [0xc3; 32]] {
            cache
                .standard_withdrawal(mock_request(wid, 0))
                .await
                .unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 3);

        // The evicted wid misses and re-forwards; a still-cached wid keeps hitting.
        cache
            .standard_withdrawal(mock_request([0xa1; 32], 0))
            .await
            .unwrap();
        assert_eq!(
            count.load(Ordering::SeqCst),
            4,
            "evicted wid must re-forward"
        );
        cache
            .standard_withdrawal(mock_request([0xc3; 32], 0))
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 4, "cached wid must still hit");
    }
}
