// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Temporary in-process response cache for the guardian's `StandardWithdrawal`
//! RPC. Lives on the throwaway `siddharth/guardian-response-cache` branch and is
//! not intended for merge — the Nitro design pulls this layer out into an
//! out-of-enclave proxy, which must preserve the idempotency below.
//!
//! The guardian debits the bucket and advances `next_seq` when it processes a
//! `StandardWithdrawal`, before hashi has durably signed the withdrawal on-chain.
//! If hashi retries the same withdrawal at a *different* seq — e.g. its local
//! limiter mirror reconciled forward to the guardian's advanced `next_seq` while
//! the signed event was still pending — re-consuming would drain the bucket and
//! burn a seq for a withdrawal that was already signed.
//!
//! So the cache is keyed by `wid`, not `(wid, seq)`: a withdrawal consumes the
//! limiter once, and any retry (at any seq) replays the stored response without
//! re-consuming. Safe because a `wid`'s `WithdrawalTransaction` has immutable
//! inputs/outputs once committed (only signatures change), so its enclave
//! signatures are stable, and the response carries no seq.

use hashi_types::guardian::WithdrawalID;
use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use std::collections::HashMap;
use std::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;

struct CacheEntry {
    /// The seq the guardian consumed this wid at. Kept for observability only —
    /// the cache is keyed by `wid`, so lookups ignore the requester's seq.
    consumed_seq: u64,
    response: proto::SignedStandardWithdrawalResponse,
}

pub struct CachingGuardianGrpc<S> {
    inner: S,
    cache: Mutex<HashMap<WithdrawalID, CacheEntry>>,
}

impl<S> CachingGuardianGrpc<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }

    // The critical section never spans an `.await`, so a sync `std::sync::Mutex`
    // is the right tool and keeps the handler future `Send`. Panics abort the
    // process (see `abort_on_panic` in main), so a poisoned lock is unreachable.
    fn try_hit(
        &self,
        wid: &WithdrawalID,
    ) -> Option<(u64, proto::SignedStandardWithdrawalResponse)> {
        self.cache
            .lock()
            .expect("cache mutex poisoned")
            .get(wid)
            .map(|entry| (entry.consumed_seq, entry.response.clone()))
    }

    fn store(
        &self,
        wid: WithdrawalID,
        consumed_seq: u64,
        response: proto::SignedStandardWithdrawalResponse,
    ) {
        self.cache.lock().expect("cache mutex poisoned").insert(
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
}
