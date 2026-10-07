// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Idempotent `StandardWithdrawal` for the guardian. The proxy answers a
//! request from the wid index over the S3 withdrawal log of the guardian
//! ([`crate::node::widlog`]) when the wid is already signed. Otherwise it
//! forwards the request to the enclave.
//!
//! The key is `wid`, not `(wid, seq)`. The guardian debits the limiter and
//! advances `next_seq` when it signs, before hashi has the signed event
//! on-chain. If hashi retries the same wid at a bumped seq, a second
//! consumption drains the bucket for a withdrawal that is already signed.
//! A replay by `wid` prevents that. This is safe because the inputs and
//! outputs of a committed wid do not change, so the response is stable.
//!
//! When the index cannot answer, the proxy fails closed with `UNAVAILABLE`.
//! It cannot tell "never signed" from "signed but unreadable", and a blind
//! forward of the second case signs the withdrawal again and debits the
//! limiter twice. If the enclave wrote a withdrawal log and then lost the S3
//! ack, the proxy still replays it. The node then reconciles its limiter
//! mirror to the guardian seq (`hashi/src/guardian_limiter.rs`). The cost is
//! one limiter under-count for one withdrawal.
//!
//! `GetGuardianInfo` is answered from [`crate::guardian_info`].

use crate::guardian_info::GuardianInfoCache;
use crate::log_store::LogStore;
use crate::metrics;
use crate::metrics::ProxyMetrics;
use crate::node::widlog::WidLogError;
use crate::node::widlog::WidLogIndex;
use hashi_types::guardian::time::now_timestamp_secs;
use hashi_types::guardian::WithdrawalID;
use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use std::sync::Arc;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::error;
use tracing::info;

/// The fail-closed error when the index cannot answer. Do not use the words
/// "seq mismatch" or "Rate limit exceeded". The node sorts guardian errors by
/// those substrings, and this error must stay retriable (`leader/guardian.rs`).
pub const WID_CACHE_UNAVAILABLE_MSG: &str = "wid cache unavailable; retry";

fn unavailable() -> Status {
    Status::unavailable(WID_CACHE_UNAVAILABLE_MSG)
}

pub struct CachingGuardianGrpc<S, L> {
    inner: Arc<S>,
    widlog: Arc<WidLogIndex<L>>,
    metrics: Arc<ProxyMetrics>,
    /// Invalidated by each forwarded withdrawal. A leader that reads after
    /// its finalize must see the new seq.
    info_cache: GuardianInfoCache<S>,
}

impl<S, L> CachingGuardianGrpc<S, L> {
    pub fn new(inner: S, widlog: Arc<WidLogIndex<L>>, metrics: Arc<ProxyMetrics>) -> Self {
        let inner = Arc::new(inner);
        let info_cache = GuardianInfoCache::new(inner.clone());
        Self {
            inner,
            widlog,
            metrics,
            info_cache,
        }
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
impl<S, L> GuardianService for CachingGuardianGrpc<S, L>
where
    S: GuardianService,
    L: LogStore,
{
    async fn get_guardian_info(
        &self,
        _request: Request<proto::GetGuardianInfoRequest>,
    ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
        self.info_cache.get().await.map(Response::new)
    }

    async fn get_attested_guardian_info(
        &self,
        request: Request<proto::GetAttestedGuardianInfoRequest>,
    ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
        self.inner.get_attested_guardian_info(request).await
    }

    async fn setup_new_key(
        &self,
        request: Request<proto::SetupNewKeyRequest>,
    ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
        self.inner.setup_new_key(request).await
    }

    async fn confirm_ceremony(
        &self,
        request: Request<proto::SignedCeremonyConfirmationRequest>,
    ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
        self.inner.confirm_ceremony(request).await
    }

    async fn operator_init(
        &self,
        request: Request<proto::OperatorInitRequest>,
    ) -> Result<Response<proto::OperatorInitResponse>, Status> {
        self.inner.operator_init(request).await
    }

    async fn provisioner_init(
        &self,
        request: Request<proto::BatchProvisionerInitRequest>,
    ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
        self.inner.provisioner_init(request).await
    }

    async fn provisioner_rotate_cert(
        &self,
        request: Request<proto::SignedProvisionerRotateCertRequest>,
    ) -> Result<Response<proto::SignedProvisionerRotateCertResponse>, Status> {
        self.inner.provisioner_rotate_cert(request).await
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
        let Some((wid, seq)) = extract_wid_and_seq(request.get_ref()) else {
            // No wid to key on. Let the enclave produce the precise rejection.
            return self.inner.standard_withdrawal(request).await;
        };

        let now = now_timestamp_secs();
        match self.widlog.lookup(&wid, now).await {
            Ok(Some(hit)) => {
                self.metrics.outcome(metrics::OUTCOME_HIT);
                info!(
                    %wid,
                    requested_seq = seq,
                    consumed_seq = hit.consumed_seq,
                    "Replaying the StandardWithdrawal response from the guardian's S3 log (idempotent by wid)."
                );
                return Ok(Response::new(hit.response));
            }
            Ok(None) => {}
            Err(WidLogError(e)) => {
                self.metrics.outcome(metrics::OUTCOME_UNAVAILABLE_LOG_STORE);
                error!(%wid, requested_seq = seq, error = %e, "Wid log unavailable; refusing to forward blind.");
                return Err(unavailable());
            }
        }

        self.metrics.outcome(metrics::OUTCOME_FORWARDED);
        let response_inner = self.inner.standard_withdrawal(request).await?.into_inner();

        self.info_cache.invalidate();
        info!(%wid, seq, "Forwarded the StandardWithdrawal to the enclave.");

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

    async fn rotate_kp_set(
        &self,
        request: Request<proto::BatchProvisionerRotateKpSetRequest>,
    ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
        self.inner.rotate_kp_set(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_store::test_store::MemStore;
    use crate::node::widlog::test_utils::withdrawal_log_json;
    use hashi_types::guardian::time::now_timestamp_ms;
    use hashi_types::guardian::StandardWithdrawalResponse;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    type ResponseFn =
        dyn Fn() -> Result<proto::SignedStandardWithdrawalResponse, Status> + Send + Sync;

    struct StubGuardian {
        call_count: Arc<AtomicUsize>,
        result: Arc<ResponseFn>,
        info: Option<proto::GetGuardianInfoResponse>,
        info_calls: Arc<AtomicUsize>,
        info_delay: Duration,
    }

    impl StubGuardian {
        fn ok() -> (Self, Arc<AtomicUsize>) {
            let call_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: call_count.clone(),
                    result: Arc::new(|| Ok(mock_response())),
                    info: None,
                    info_calls: Arc::default(),
                    info_delay: Duration::ZERO,
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
                    info: None,
                    info_calls: Arc::default(),
                    info_delay: Duration::ZERO,
                },
                call_count,
            )
        }

        fn with_info(mut self, info: proto::GetGuardianInfoResponse) -> Self {
            self.info = Some(info);
            self
        }

        fn with_info_delay(mut self, delay: Duration) -> Self {
            self.info_delay = delay;
            self
        }
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_attested_guardian_info(
            &self,
            _: Request<proto::GetAttestedGuardianInfoRequest>,
        ) -> Result<Response<proto::GetAttestedGuardianInfoResponse>, Status> {
            unimplemented!("ordinary info must not request attestation")
        }

        async fn get_guardian_info(
            &self,
            _request: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            self.info_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.info_delay).await;
            match &self.info {
                Some(info) => Ok(Response::new(info.clone())),
                None => Err(Status::unavailable("no stub info configured")),
            }
        }
        async fn setup_new_key(
            &self,
            _: Request<proto::SetupNewKeyRequest>,
        ) -> Result<Response<proto::SignedSetupNewKeyResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
        async fn confirm_ceremony(
            &self,
            _: Request<proto::SignedCeremonyConfirmationRequest>,
        ) -> Result<Response<proto::CeremonyConfirmationResponse>, Status> {
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
            _: Request<proto::BatchProvisionerInitRequest>,
        ) -> Result<Response<proto::ProvisionerInitResponse>, Status> {
            unimplemented!("not exercised by tests")
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
            Ok(Response::new(proto::UpdateCommitteeResponse {
                current_committee_epoch: Some(0),
            }))
        }
        async fn rotate_kp_set(
            &self,
            _: Request<proto::BatchProvisionerRotateKpSetRequest>,
        ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
    }

    fn test_metrics() -> Arc<ProxyMetrics> {
        Arc::new(ProxyMetrics::new())
    }

    /// A cache whose index has tailed the store to the current hour.
    async fn cache_over(
        stub: StubGuardian,
        store: MemStore,
    ) -> CachingGuardianGrpc<StubGuardian, MemStore> {
        let metrics = test_metrics();
        let widlog = WidLogIndex::ready_for_tests(store, metrics.clone()).await;
        CachingGuardianGrpc::new(stub, widlog, metrics)
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

    /// A withdrawal log that the enclave wrote for `wid` in the current hour.
    fn fresh_withdrawal_log(wid: [u8; 32], seq: u64) -> (String, Vec<u8>) {
        withdrawal_log_json(
            WithdrawalID::new(wid),
            seq,
            now_timestamp_ms(),
            StandardWithdrawalResponse {
                enclave_signatures: vec![],
            },
        )
    }

    /// The enclave writes the withdrawal log before it returns the response.
    fn enclave_wrote(cache: &CachingGuardianGrpc<StubGuardian, MemStore>, wid: [u8; 32], seq: u64) {
        let (key, bytes) = fresh_withdrawal_log(wid, seq);
        cache.widlog.log().insert(key, bytes);
    }

    /// The response that a replay builds from the log of `fresh_withdrawal_log`.
    fn assert_replayed(response: &proto::SignedStandardWithdrawalResponse) {
        assert!(response
            .data
            .as_ref()
            .unwrap()
            .enclave_signatures
            .is_empty());
        assert_eq!(response.signature, Some(vec![0u8; 64].into()));
    }

    #[tokio::test]
    async fn same_wid_and_seq_replays_the_log_after_first_call() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default()).await;

        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        enclave_wrote(&cache, [0xaa; 32], 0);
        let r2 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "second call must not forward"
        );
        assert_replayed(&r2);
    }

    #[tokio::test]
    async fn bumped_seq_for_same_wid_is_idempotent() {
        // A retry of the same wid at a different seq must replay the cached
        // response. A second consumption drains the bucket for a withdrawal
        // that is already signed.
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default()).await;

        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        enclave_wrote(&cache, [0xaa; 32], 0);
        let r2 = cache
            .standard_withdrawal(mock_request([0xaa; 32], 1))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "same wid at a bumped seq must replay, not re-consume"
        );
        assert_replayed(&r2);
    }

    fn info_request() -> Request<proto::GetGuardianInfoRequest> {
        Request::new(proto::GetGuardianInfoRequest {})
    }

    #[tokio::test(start_paused = true)]
    async fn guardian_info_fetched_before_a_withdrawal_is_refetched() {
        let (stub, _) = StubGuardian::ok();
        let stub = stub
            .with_info(proto::GetGuardianInfoResponse::default())
            .with_info_delay(Duration::from_millis(100));
        let info_calls = stub.info_calls.clone();
        let cache = Arc::new(cache_over(stub, MemStore::default()).await);

        // A withdrawal is signed while the first fetch is in flight.
        let in_flight = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get_guardian_info(info_request()).await }
        });
        while info_calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        cache
            .standard_withdrawal(mock_request([0x11; 32], 0))
            .await
            .unwrap();
        in_flight.await.unwrap().unwrap();

        cache.get_guardian_info(info_request()).await.unwrap();
        assert_eq!(info_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn log_replays_do_not_refetch_guardian_info() {
        let (stub, _) = StubGuardian::ok();
        let stub = stub.with_info(proto::GetGuardianInfoResponse::default());
        let info_calls = stub.info_calls.clone();
        let store = MemStore::default();
        let (key, bytes) = fresh_withdrawal_log([0xcd; 32], 7);
        store.insert(key, bytes);
        let cache = cache_over(stub, store).await;

        cache.get_guardian_info(info_request()).await.unwrap();
        cache
            .standard_withdrawal(mock_request([0xcd; 32], 8))
            .await
            .unwrap();
        cache.get_guardian_info(info_request()).await.unwrap();
        assert_eq!(info_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn committee_updates_do_not_refetch_guardian_info() {
        let (stub, _) = StubGuardian::ok();
        let stub = stub.with_info(proto::GetGuardianInfoResponse::default());
        let info_calls = stub.info_calls.clone();
        let cache = cache_over(stub, MemStore::default()).await;

        cache.get_guardian_info(info_request()).await.unwrap();
        // The guardian answers an empty chain Ok, whoever sends it.
        cache
            .update_committee_chain(Request::new(proto::UpdateCommitteeChainRequest::default()))
            .await
            .unwrap();
        cache.get_guardian_info(info_request()).await.unwrap();
        assert_eq!(info_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn errors_are_not_cached() {
        let (stub, count) = StubGuardian::err();
        let cache = cache_over(stub, MemStore::default()).await;

        let r1 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;
        let r2 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;

        assert_eq!(count.load(Ordering::SeqCst), 2, "errors should re-forward");
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn missing_wid_falls_through_to_inner() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default()).await;

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
    async fn distinct_wids_are_indexed_independently() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default()).await;

        cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .unwrap();
        enclave_wrote(&cache, [0xaa; 32], 0);
        cache
            .standard_withdrawal(mock_request([0xbb; 32], 0))
            .await
            .unwrap();
        enclave_wrote(&cache, [0xbb; 32], 1);
        // Each wid is new, so both forward.
        assert_eq!(count.load(Ordering::SeqCst), 2);

        // Hit both again. The log serves them now.
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
    async fn log_store_failure_fails_closed_without_forwarding() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default()).await;
        cache.widlog.log().fail_lists.store(true, Ordering::SeqCst);

        let status = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .expect_err("must fail closed");

        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(count.load(Ordering::SeqCst), 0, "must not forward blind");
        // The node classifies guardian errors by these substrings. The
        // fail-closed error must land in its retriable bucket.
        assert!(!status.message().contains("seq mismatch"));
        assert!(!status.message().contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn withdrawal_log_is_replayed_without_forwarding() {
        let (stub, count) = StubGuardian::ok();
        let store = MemStore::default();
        let (key, bytes) = fresh_withdrawal_log([0xcd; 32], 7);
        store.insert(key, bytes);
        let cache = cache_over(stub, store).await;

        let replayed = cache
            .standard_withdrawal(mock_request([0xcd; 32], 8))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(count.load(Ordering::SeqCst), 0, "served from the log");
        assert!(replayed.data.is_some());
        assert_eq!(replayed.signature.as_ref().unwrap().len(), 64);

        // The retry is an index hit: same response, still no forward.
        let again = cache
            .standard_withdrawal(mock_request([0xcd; 32], 8))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(replayed, again);
    }

    /// A new proxy instance serves a wid whose withdrawal log is older than the
    /// instance. It does not touch the enclave. Run it against the local MinIO:
    ///
    /// ```text
    /// GUARDIAN_LOG_BUCKET=hashi-guardian-dev GUARDIAN_LOG_REGION=us-east-1 \
    /// AWS_ENDPOINT_URL_S3=http://127.0.0.1:19000 \
    /// AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
    /// cargo nextest run -p hashi-guardian-proxy --run-ignored all s3_log_replay
    /// ```
    #[tokio::test]
    #[ignore = "needs a live MinIO/S3: set GUARDIAN_LOG_BUCKET/GUARDIAN_LOG_REGION (+ AWS_* env)"]
    async fn s3_log_replay_survives_proxy_restarts() {
        let bucket = std::env::var("GUARDIAN_LOG_BUCKET").expect("GUARDIAN_LOG_BUCKET");
        let region = std::env::var("GUARDIAN_LOG_REGION").expect("GUARDIAN_LOG_REGION");

        // Unique wid for each run: logs persist across runs in a real bucket.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let mut wid = [0x5a_u8; 32];
        wid[..4].copy_from_slice(&nanos.to_be_bytes());
        let (record_key, record_bytes) = fresh_withdrawal_log(wid, 7);

        // Write the withdrawal log as the enclave does (plain put; the proxy is
        // read-only on the bucket).
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;
        let mut builder = aws_sdk_s3::config::Builder::from(&aws_config);
        if std::env::var_os("AWS_ENDPOINT_URL_S3").is_some() {
            builder = builder.force_path_style(true);
        }
        let s3 = aws_sdk_s3::Client::from_conf(builder.build());
        s3.put_object()
            .bucket(&bucket)
            .key(&record_key)
            .body(record_bytes.into())
            .send()
            .await
            .expect("write the withdrawal log");

        // A new proxy instance: empty index, real S3LogStore.
        let store = crate::log_store::S3LogStore::connect(bucket, region).await;
        store.probe().await.expect("bucket must be readable");
        let (stub, count) = StubGuardian::ok();
        let metrics = test_metrics();
        let widlog = WidLogIndex::ready_for_tests(store, metrics.clone()).await;
        let cache = CachingGuardianGrpc::new(stub, widlog, metrics);

        let replayed = cache
            .standard_withdrawal(mock_request(wid, 8))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "must be served from the S3 log, not the enclave"
        );
        assert!(replayed.data.is_some());
    }
}
