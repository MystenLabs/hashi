// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wid-keyed response cache for the guardian's `StandardWithdrawal` RPC: an
//! in-process LRU in front of the guardian's own S3 withdrawal log
//! ([`crate::widlog`]) as the durable, read-only tier.
//!
//! Keyed by `wid`, not `(wid, seq)`: the guardian debits the limiter and
//! advances `next_seq` when it signs, before hashi has the signed event
//! on-chain. If hashi retries the same wid at a bumped seq (its limiter mirror
//! reconciled forward while the event was still pending), re-consuming would
//! drain the bucket for a withdrawal that was already signed. Replaying by
//! `wid` avoids that — safe because a committed wid's inputs/outputs are
//! immutable (only signatures change), so the response is stable.
//!
//! The enclave persists every signed withdrawal before releasing it, so the
//! proxy has nothing durable of its own to lose. On a log hit it verifies the
//! record's signatures spend the incoming request, then replays them (see
//! `replay_from_log`); it does not reason about the limiter `seq`, which is the
//! guardian's to own — the node's mirror self-heals any divergence
//! (`hashi/src/guardian_limiter.rs`). When the log can't answer, the proxy
//! fails closed with `UNAVAILABLE` rather than forwarding blind — it cannot
//! distinguish "never signed" from "signed but unreadable", and forwarding the
//! latter re-signs a withdrawal the guardian already durably signed, the
//! double-debit the cache exists to prevent.

use crate::metrics;
use crate::metrics::ProxyMetrics;
use crate::widlog::find_success_record;
use crate::widlog::FoundSuccess;
use crate::widlog::LogStore;
use crate::widlog::WidLogError;
use bitcoin::Network;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::BitcoinSignature;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::bitcoin::BTC_LIB;
use hashi_types::guardian::proto_conversions::pb_to_signed_standard_withdrawal_request_wire;
use hashi_types::guardian::AddressValidation;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::WithdrawalID;
use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::error;
use tracing::info;

// One entry per withdrawal would leak forever; 10k far exceeds the rate-limited
// in-flight working set, so a hot wid always outlives its retry window.
const CACHE_CAPACITY: usize = 10_000;

/// Fail-closed error surfaced when the durable tier can't answer. Kept clear of
/// "seq mismatch" and "Rate limit exceeded": the node classifies guardian
/// errors by those substrings (`crates/hashi/src/leader/guardian.rs`) and this
/// one must land in its retriable bucket.
pub const WID_CACHE_UNAVAILABLE_MSG: &str = "wid cache unavailable; retry";

fn unavailable() -> Status {
    Status::unavailable(WID_CACHE_UNAVAILABLE_MSG)
}

struct CacheEntry {
    /// The seq the guardian consumed this wid at. Kept for observability only —
    /// the cache is keyed by `wid`, so lookups ignore the requester's seq.
    consumed_seq: u64,
    response: proto::SignedStandardWithdrawalResponse,
}

pub struct CachingGuardianGrpc<S, L> {
    inner: S,
    l1: Mutex<LruCache<WithdrawalID, CacheEntry>>,
    log: L,
    /// Network the guardian validates requests against; needed to recompute
    /// sighashes when verifying a log replay.
    network: Network,
    metrics: Arc<ProxyMetrics>,
}

impl<S, L> CachingGuardianGrpc<S, L> {
    pub fn new(inner: S, log: L, network: Network, metrics: Arc<ProxyMetrics>) -> Self {
        Self::with_capacity(
            inner,
            log,
            network,
            metrics,
            NonZeroUsize::new(CACHE_CAPACITY).expect("CACHE_CAPACITY > 0"),
        )
    }

    fn with_capacity(
        inner: S,
        log: L,
        network: Network,
        metrics: Arc<ProxyMetrics>,
        capacity: NonZeroUsize,
    ) -> Self {
        Self {
            inner,
            l1: Mutex::new(LruCache::new(capacity)),
            log,
            network,
            metrics,
        }
    }

    // The critical section never spans an `.await`, so a sync `std::sync::Mutex`
    // is the right tool and keeps the handler future `Send`. Panics abort the
    // process (see `abort_on_panic` in main), so a poisoned lock is unreachable.
    fn try_hit(
        &self,
        wid: &WithdrawalID,
    ) -> Option<(u64, proto::SignedStandardWithdrawalResponse)> {
        let mut cache = self.l1.lock().expect("cache mutex poisoned");
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
        self.l1.lock().expect("cache mutex poisoned").put(
            wid,
            CacheEntry {
                consumed_seq,
                response,
            },
        );
    }
}

impl<S, L> CachingGuardianGrpc<S, L>
where
    S: GuardianService,
    L: LogStore,
{
    /// Serve a wid from the guardian's S3 withdrawal log. `Ok(None)` means
    /// "definitively not in the log: forward"; `Err` is the fail-closed path.
    async fn replay_from_log(
        &self,
        wid: &WithdrawalID,
        requested_seq: u64,
        request: &proto::SignedStandardWithdrawalRequest,
    ) -> Result<Option<proto::SignedStandardWithdrawalResponse>, Status> {
        let found = match find_success_record(&self.log, wid, requested_seq, &self.metrics).await {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(None),
            Err(WidLogError::CapExceeded) => {
                self.metrics.outcome(metrics::OUTCOME_UNAVAILABLE_SCAN_CAP);
                error!(%wid, requested_seq, "Wid log scan hit its LIST cap; refusing to forward blind.");
                return Err(unavailable());
            }
            Err(WidLogError::Store(e)) => {
                self.metrics.outcome(metrics::OUTCOME_UNAVAILABLE_LOG_STORE);
                error!(%wid, requested_seq, error = %e, "Wid log unavailable; refusing to forward blind.");
                return Err(unavailable());
            }
        };

        // Idempotency is by wid; the proxy does not gate on the limiter `seq`.
        // A record the enclave signed but never committed (a lost-ack S3 write
        // it then reverted) still replays here: the node's requested seq stays
        // pinned to its mirror, and its stall reconcile snaps that mirror back
        // to the guardian's authoritative seq (`hashi/src/guardian_limiter.rs`),
        // so a served orphan self-heals — at worst a bounded one-withdrawal
        // limiter under-count, which is the guardian's to close, not the proxy's.
        //
        // Integrity gate: never hand the node signatures that don't spend its
        // transaction. Needs the guardian's live BTC key + master G (the enclave
        // key rotates per instance, so it can't be cached across rotations).
        let info = match self.guardian_info().await {
            Ok(info) => info,
            Err(e) => {
                self.metrics
                    .outcome(metrics::OUTCOME_UNAVAILABLE_GUARDIAN_INFO);
                error!(%wid, error = %e, "Cannot fetch guardian info to verify a log replay.");
                return Err(unavailable());
            }
        };
        let (Some(enclave_btc_pubkey), Some(master_g)) =
            (info.enclave_btc_pubkey, info.mpc_master_g)
        else {
            self.metrics
                .outcome(metrics::OUTCOME_UNAVAILABLE_GUARDIAN_INFO);
            error!(%wid, "Guardian info lacks BTC pubkey / master G; cannot verify a log replay.");
            return Err(unavailable());
        };

        if let Err(e) = verify_recorded_signatures(
            request,
            &found.response.enclave_signatures,
            &enclave_btc_pubkey,
            &master_g,
            self.network,
        ) {
            self.metrics
                .outcome(metrics::OUTCOME_UNAVAILABLE_VERIFY_FAILED);
            error!(
                %wid,
                error = %e,
                "Log record signatures do not verify; possible bucket tampering or version skew."
            );
            return Err(unavailable());
        }

        let response = synthesize_response(&found);
        self.store(*wid, found.consumed_seq, response.clone());
        self.metrics.outcome(metrics::OUTCOME_S3_HIT);
        info!(
            %wid,
            requested_seq,
            consumed_seq = found.consumed_seq,
            "Replaying StandardWithdrawal response from the guardian's S3 log (idempotent by wid)."
        );
        Ok(Some(response))
    }

    async fn guardian_info(&self) -> anyhow::Result<GuardianInfo> {
        let info_pb = self
            .inner
            .get_guardian_info(Request::new(proto::GetGuardianInfoRequest::default()))
            .await
            .map_err(|s| anyhow::anyhow!("get_guardian_info: {s}"))?
            .into_inner();
        let response = GetGuardianInfoResponse::try_from(info_pb)
            .map_err(|e| anyhow::anyhow!("parse guardian info: {e:?}"))?;
        // The proxy talks to the enclave over its own direct channel; like the
        // node, it does not re-verify the info envelope (worst case is liveness).
        let (info, _) = response.into_info_unchecked();
        Ok(info)
    }
}

/// Verify recorded BTC signatures against the sighashes of the *incoming*
/// request (the same immutable tx as the recorded one, by the wid invariant).
fn verify_recorded_signatures(
    request: &proto::SignedStandardWithdrawalRequest,
    signatures: &[BitcoinSignature],
    enclave_btc_pubkey: &BitcoinPubkey,
    master_g: &HashiMasterG,
    network: Network,
) -> anyhow::Result<()> {
    let wire = pb_to_signed_standard_withdrawal_request_wire(request.clone())
        .map_err(|e| anyhow::anyhow!("parse request: {e:?}"))?;
    let signed = HashiSigned::<StandardWithdrawalRequest>::validate_addr(wire, network)
        .map_err(|e| anyhow::anyhow!("validate request: {e:?}"))?;
    let (messages, _txid) = signed
        .message()
        .utxos()
        .signing_messages_and_txid(enclave_btc_pubkey, master_g);
    anyhow::ensure!(
        messages.len() == signatures.len(),
        "record has {} signatures for {} inputs",
        signatures.len(),
        messages.len()
    );
    for (i, (message, signature)) in messages.iter().zip(signatures).enumerate() {
        BTC_LIB
            .verify_schnorr(&signature.signature, message, enclave_btc_pubkey)
            .map_err(|e| anyhow::anyhow!("input {i}: {e}"))?;
    }
    Ok(())
}

fn synthesize_response(found: &FoundSuccess) -> proto::SignedStandardWithdrawalResponse {
    proto::SignedStandardWithdrawalResponse {
        data: Some(proto::StandardWithdrawalResponseData {
            enclave_signatures: found
                .response
                .enclave_signatures
                .iter()
                .map(|sig| sig.to_vec().into())
                .collect(),
        }),
        timestamp_ms: Some(found.timestamp_ms),
        // The record predates the response envelope (the enclave signs it after
        // the S3 write). Nodes require a 64-byte value but never verify it
        // (`into_data_unchecked`), so zeros can't pass for a real signature.
        signature: Some(vec![0u8; 64].into()),
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
            // No wid to key on; let the enclave produce the precise rejection.
            return self.inner.standard_withdrawal(request).await;
        };

        if let Some((consumed_seq, cached)) = self.try_hit(&wid) {
            self.metrics.outcome(metrics::OUTCOME_L1_HIT);
            info!(
                %wid,
                requested_seq = seq,
                consumed_seq,
                "Cache hit; replaying stored StandardWithdrawal response (idempotent by wid)."
            );
            return Ok(Response::new(cached));
        }

        if let Some(replayed) = self.replay_from_log(&wid, seq, request.get_ref()).await? {
            return Ok(Response::new(replayed));
        }

        self.metrics.outcome(metrics::OUTCOME_FORWARDED);
        let response_inner = self.inner.standard_withdrawal(request).await?.into_inner();

        self.store(wid, seq, response_inner.clone());
        info!(%wid, seq, "Stored StandardWithdrawal response in cache");

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
    use crate::widlog::test_store::success_record_json;
    use crate::widlog::test_store::MemStore;
    use hashi_types::bitcoin::create_btc_keypair_for_test;
    use hashi_types::bitcoin::hashi_master_g_from_btc_xonly_for_test;
    use hashi_types::bitcoin::sign_btc_tx;
    use hashi_types::guardian::proto_conversions::get_guardian_info_response_to_pb;
    use hashi_types::guardian::proto_conversions::signed_standard_withdrawal_request_to_pb;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::GuardianSigned;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::NitroAttestation;
    use hashi_types::guardian::StandardWithdrawalResponse;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    type ResponseFn =
        dyn Fn() -> Result<proto::SignedStandardWithdrawalResponse, Status> + Send + Sync;

    struct StubGuardian {
        call_count: Arc<AtomicUsize>,
        result: Arc<ResponseFn>,
        info: Option<proto::GetGuardianInfoResponse>,
    }

    impl StubGuardian {
        fn ok() -> (Self, Arc<AtomicUsize>) {
            let call_count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    call_count: call_count.clone(),
                    result: Arc::new(|| Ok(mock_response())),
                    info: None,
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
                },
                call_count,
            )
        }

        fn with_info(mut self, info: proto::GetGuardianInfoResponse) -> Self {
            self.info = Some(info);
            self
        }
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_guardian_info(
            &self,
            _: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
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
            unimplemented!("not exercised by tests")
        }
        async fn rotate_kps(
            &self,
            _: Request<proto::RotateKpsRequest>,
        ) -> Result<Response<proto::SignedRotateKpsResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
    }

    fn test_metrics() -> Arc<ProxyMetrics> {
        Arc::new(ProxyMetrics::new())
    }

    fn cache_over(
        stub: StubGuardian,
        store: MemStore,
    ) -> CachingGuardianGrpc<StubGuardian, MemStore> {
        CachingGuardianGrpc::new(stub, store, Network::Regtest, test_metrics())
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

    /// A signed GetGuardianInfoResponse pb carrying the given keys + next_seq.
    fn stub_info_pb(
        enclave_btc_pubkey: BitcoinPubkey,
        master_g: HashiMasterG,
        next_seq: u64,
    ) -> proto::GetGuardianInfoResponse {
        let signing_key = GuardianSignKeyPair::from([7u8; 32]);
        let info = GuardianInfo {
            lifecycle: hashi_types::guardian::WithdrawStage::Activated.into(),
            secret_sharing_instance: None,
            bucket_info: None,
            encryption_pubkey: vec![0u8; 32],
            config_hash: None,
            genesis_state_hash: None,
            untrusted_git_revision: "test".to_string(),
            enclave_btc_pubkey: Some(enclave_btc_pubkey),
            limiter_state: Some(LimiterState {
                num_tokens_available: 0,
                last_updated_at: 0,
                next_seq,
            }),
            limiter_config: None,
            current_committee_epoch: None,
            mpc_master_g: Some(master_g),
        };
        let signed_info = GuardianSigned::new(info, &signing_key, 1);
        let domain = GetGuardianInfoResponse::new(
            NitroAttestation::new(vec![1, 2, 3]),
            signing_key.verification_key(),
            signed_info,
        );
        get_guardian_info_response_to_pb(domain)
    }

    /// A real request + a genuinely-signed Success record for it: the request pb
    /// the node would send, and the log record whose signatures verify against
    /// (enclave keypair, master G) over that request's sighashes.
    struct ReplayFixture {
        request: proto::SignedStandardWithdrawalRequest,
        record_key: String,
        record_bytes: Vec<u8>,
        enclave_btc_pubkey: BitcoinPubkey,
        master_g: HashiMasterG,
        consumed_seq: u64,
    }

    fn replay_fixture(seq: u64) -> ReplayFixture {
        let wid = WithdrawalID::new([0xcd; 32]);
        let signed_request =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);

        let enclave_kp = create_btc_keypair_for_test(&[8u8; 32]);
        let enclave_btc_pubkey = enclave_kp.x_only_public_key().0;
        let master_g = hashi_master_g_from_btc_xonly_for_test(
            &create_btc_keypair_for_test(&[6u8; 32])
                .x_only_public_key()
                .0,
        );

        let (messages, _txid) = signed_request
            .message()
            .utxos()
            .signing_messages_and_txid(&enclave_btc_pubkey, &master_g);
        let response = StandardWithdrawalResponse {
            enclave_signatures: sign_btc_tx(&messages, &enclave_kp),
        };

        let request = signed_standard_withdrawal_request_to_pb(&signed_request);
        let (record_key, record_bytes) = success_record_json(wid, seq, 1_700_000_000_000, response);
        ReplayFixture {
            request,
            record_key,
            record_bytes,
            enclave_btc_pubkey,
            master_g,
            consumed_seq: seq,
        }
    }

    #[tokio::test]
    async fn same_wid_and_seq_hits_cache_after_first_call() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default());

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
        let cache = cache_over(stub, MemStore::default());

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
        let cache = cache_over(stub, MemStore::default());

        let r1 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;
        let r2 = cache.standard_withdrawal(mock_request([0xaa; 32], 0)).await;

        assert_eq!(count.load(Ordering::SeqCst), 2, "errors should re-forward");
        assert!(r1.is_err() && r2.is_err());
    }

    #[tokio::test]
    async fn missing_wid_falls_through_to_inner() {
        let (stub, count) = StubGuardian::ok();
        let cache = cache_over(stub, MemStore::default());

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
        let cache = cache_over(stub, MemStore::default());

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
        let cache = CachingGuardianGrpc::with_capacity(
            stub,
            MemStore::default(),
            Network::Regtest,
            test_metrics(),
            NonZeroUsize::new(2).unwrap(),
        );

        // Three distinct wids into a capacity-2 cache evicts the first (LRU).
        for wid in [[0xa1; 32], [0xb2; 32], [0xc3; 32]] {
            cache
                .standard_withdrawal(mock_request(wid, 0))
                .await
                .unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 3);

        // The evicted wid misses L1 and the (empty) log, and re-forwards; a
        // still-cached wid keeps hitting.
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

    #[tokio::test]
    async fn log_store_failure_fails_closed_without_forwarding() {
        let (stub, count) = StubGuardian::ok();
        let store = MemStore::default();
        store.fail_lists.store(true, Ordering::SeqCst);
        let cache = cache_over(stub, store);

        let status = cache
            .standard_withdrawal(mock_request([0xaa; 32], 0))
            .await
            .expect_err("must fail closed");

        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(count.load(Ordering::SeqCst), 0, "must not forward blind");
        // The node classifies guardian errors by these substrings; the
        // fail-closed error must land in its retriable bucket.
        assert!(!status.message().contains("seq mismatch"));
        assert!(!status.message().contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn log_replay_serves_verified_record_and_populates_l1() {
        let fixture = replay_fixture(7);
        let (stub, count) = StubGuardian::ok();
        let stub = stub.with_info(stub_info_pb(
            fixture.enclave_btc_pubkey,
            fixture.master_g,
            // next_seq is carried in guardian info but no longer gated on.
            fixture.consumed_seq + 1,
        ));
        let store = MemStore::default();
        store.insert(fixture.record_key.clone(), fixture.record_bytes.clone());
        let cache = cache_over(stub, store);

        let replayed = cache
            .standard_withdrawal(Request::new(fixture.request.clone()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(count.load(Ordering::SeqCst), 0, "served from the log");
        let sigs = &replayed.data.as_ref().unwrap().enclave_signatures;
        assert!(!sigs.is_empty());
        assert_eq!(replayed.signature.as_ref().unwrap().len(), 64);

        // Second retry is an L1 hit — same response, still no forward.
        let again = cache
            .standard_withdrawal(Request::new(fixture.request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(replayed, again);
    }

    #[tokio::test]
    async fn record_at_or_above_next_seq_is_still_served_by_wid() {
        // A record whose seq is not below the guardian's next_seq (e.g. a
        // lost-ack S3 write the enclave reverted) still carries signatures the
        // enclave really produced, so the proxy replays it by wid rather than
        // forwarding. The proxy owns no seq logic; the node's stall reconcile
        // self-heals any divergence (hashi/src/guardian_limiter.rs). Contrast
        // the removed committed-gate, which forwarded here and re-signed.
        let fixture = replay_fixture(7);
        let (stub, count) = StubGuardian::ok();
        let stub = stub.with_info(stub_info_pb(
            fixture.enclave_btc_pubkey,
            fixture.master_g,
            fixture.consumed_seq, // next_seq == the record's seq
        ));
        let store = MemStore::default();
        store.insert(fixture.record_key.clone(), fixture.record_bytes.clone());
        let cache = cache_over(stub, store);

        let replayed = cache
            .standard_withdrawal(Request::new(fixture.request.clone()))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "served from the log by wid, not forwarded"
        );
        assert!(!replayed
            .data
            .as_ref()
            .unwrap()
            .enclave_signatures
            .is_empty());
    }

    #[tokio::test]
    async fn unverifiable_record_fails_closed() {
        // Same record, but the guardian reports a different BTC key: the
        // recorded signatures no longer verify — poisoned record or version
        // skew — and the proxy must neither serve NOR forward.
        let fixture = replay_fixture(7);
        let wrong_key = create_btc_keypair_for_test(&[42u8; 32])
            .x_only_public_key()
            .0;
        let (stub, count) = StubGuardian::ok();
        let stub = stub.with_info(stub_info_pb(
            wrong_key,
            fixture.master_g,
            fixture.consumed_seq + 1,
        ));
        let store = MemStore::default();
        store.insert(fixture.record_key.clone(), fixture.record_bytes.clone());
        let cache = cache_over(stub, store);

        let status = cache
            .standard_withdrawal(Request::new(fixture.request.clone()))
            .await
            .expect_err("must fail closed");

        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn guardian_info_failure_fails_closed() {
        // A record exists but the enclave can't be asked for its BTC key: the
        // integrity gate can't run, so the proxy fails closed.
        let fixture = replay_fixture(7);
        let (stub, count) = StubGuardian::ok(); // no .with_info(..)
        let store = MemStore::default();
        store.insert(fixture.record_key.clone(), fixture.record_bytes.clone());
        let cache = cache_over(stub, store);

        let status = cache
            .standard_withdrawal(Request::new(fixture.request.clone()))
            .await
            .expect_err("must fail closed");

        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    /// A fresh proxy instance (empty L1) serves a wid whose record predates it,
    /// without touching the enclave. Against the local replica's MinIO:
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

        // Unique wid per run: records persist across runs in a real bucket, and
        // a stale record for a reused wid would carry signatures over a stale
        // mock transaction.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let mut wid_bytes = [0x5a_u8; 32];
        wid_bytes[..4].copy_from_slice(&nanos.to_be_bytes());
        let wid = WithdrawalID::new(wid_bytes);

        let signed_request =
            StandardWithdrawalRequest::mock_signed_for_testing_with_wid(Network::Regtest, wid);
        let enclave_kp = create_btc_keypair_for_test(&[8u8; 32]);
        let enclave_btc_pubkey = enclave_kp.x_only_public_key().0;
        let master_g = hashi_master_g_from_btc_xonly_for_test(
            &create_btc_keypair_for_test(&[6u8; 32])
                .x_only_public_key()
                .0,
        );
        let (messages, _txid) = signed_request
            .message()
            .utxos()
            .signing_messages_and_txid(&enclave_btc_pubkey, &master_g);
        let response = StandardWithdrawalResponse {
            enclave_signatures: sign_btc_tx(&messages, &enclave_kp),
        };
        let request = signed_standard_withdrawal_request_to_pb(&signed_request);
        let (record_key, record_bytes) = success_record_json(wid, 7, 1_700_000_000_000, response);

        // Write the record the way the enclave would have (plain put; the proxy
        // itself is read-only on the bucket).
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
            .expect("write the success record");

        // A brand-new proxy instance: empty L1, real S3LogStore.
        let store = crate::widlog::S3LogStore::connect(bucket, region).await;
        store.probe().await.expect("bucket must be readable");
        let (stub, count) = StubGuardian::ok();
        let stub = stub.with_info(stub_info_pb(enclave_btc_pubkey, master_g, 8));
        let cache = CachingGuardianGrpc::new(stub, store, Network::Regtest, test_metrics());

        let replayed = cache
            .standard_withdrawal(Request::new(request))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "must be served from the S3 log, not the enclave"
        );
        assert!(!replayed.data.unwrap().enclave_signatures.is_empty());
    }
}
