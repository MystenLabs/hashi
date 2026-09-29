// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The single-flight cache for ordinary gRPC `GetGuardianInfo` requests.
//! Attested queries bypass this cache and always reach the enclave.

use hashi_types::proto;
use hashi_types::proto::guardian_service_server::GuardianService;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::Request;
use tonic::Status;

const TTL: Duration = Duration::from_secs(1);

struct CachedInfo {
    at: Instant,
    /// The generation when the fetch started.
    generation: u64,
    response: proto::GetGuardianInfoResponse,
}

pub struct GuardianInfoCache<S> {
    guardian: Arc<S>,
    cached: Arc<Mutex<Option<CachedInfo>>>,
    generation: AtomicU64,
}

impl<S> GuardianInfoCache<S> {
    pub fn new(guardian: Arc<S>) -> Self {
        Self {
            guardian,
            cached: Arc::new(Mutex::new(None)),
            generation: AtomicU64::new(0),
        }
    }

    /// Info fetched before this call is never served, even by a fetch still in
    /// flight.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

impl<S: GuardianService> GuardianInfoCache<S> {
    /// The fetch holds the lock, so a burst shares one successful backend call. It
    /// runs detached with a fresh request: a caller can't cancel it or pass its
    /// deadline on.
    pub async fn get(&self) -> Result<proto::GetGuardianInfoResponse, Status> {
        let mut cached = self.cached.clone().lock_owned().await;
        let generation = self.generation.load(Ordering::SeqCst);
        if let Some(entry) = cached
            .as_ref()
            .filter(|entry| entry.generation == generation && entry.at.elapsed() < TTL)
        {
            return Ok(entry.response.clone());
        }
        let guardian = self.guardian.clone();
        tokio::spawn(async move {
            let response = guardian
                .get_guardian_info(Request::new(proto::GetGuardianInfoRequest {}))
                .await?
                .into_inner();
            *cached = Some(CachedInfo {
                at: Instant::now(),
                generation,
                response: response.clone(),
            });
            Ok(response)
        })
        .await
        .expect("guardian info fetch task failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tonic::Response;

    #[derive(Default)]
    struct StubGuardian {
        info: Option<proto::GetGuardianInfoResponse>,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl StubGuardian {
        fn answering_after(delay: Duration) -> Self {
            Self {
                info: Some(proto::GetGuardianInfoResponse::default()),
                delay,
                calls: Arc::default(),
            }
        }
    }

    #[tonic::async_trait]
    impl GuardianService for StubGuardian {
        async fn get_attested_guardian_info(
            &self,
            _: Request<proto::GetAttestedGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            unimplemented!("ordinary info must not request attestation")
        }

        async fn get_guardian_info(
            &self,
            _request: Request<proto::GetGuardianInfoRequest>,
        ) -> Result<Response<proto::GetGuardianInfoResponse>, Status> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
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
        async fn rotate_kp_set(
            &self,
            _: Request<proto::BatchProvisionerRotateKpSetRequest>,
        ) -> Result<Response<proto::SignedRotateKpSetResponse>, Status> {
            unimplemented!("not exercised by tests")
        }
    }

    fn cache_over(stub: StubGuardian) -> (Arc<GuardianInfoCache<StubGuardian>>, Arc<AtomicUsize>) {
        let calls = stub.calls.clone();
        (Arc::new(GuardianInfoCache::new(Arc::new(stub))), calls)
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_shares_one_backend_call_per_ttl() {
        // Slow enough that the burst overlaps the fetch.
        let (cache, calls) = cache_over(StubGuardian::answering_after(Duration::from_millis(100)));

        let (a, b, c) = tokio::join!(cache.get(), cache.get(), cache.get());
        assert!(a.is_ok() && b.is_ok() && c.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(TTL).await;
        cache.get().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn the_fetch_outlives_a_caller_that_gives_up() {
        let (cache, calls) = cache_over(StubGuardian::answering_after(Duration::from_millis(100)));

        assert!(tokio::time::timeout(Duration::from_millis(10), cache.get())
            .await
            .is_err());

        // The fetch still completes and fills the cache for the next caller.
        cache.get().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn invalidate_discards_a_fetch_in_flight() {
        let (cache, calls) = cache_over(StubGuardian::answering_after(Duration::from_millis(100)));

        let in_flight = tokio::spawn({
            let cache = cache.clone();
            async move { cache.get().await }
        });
        while calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        cache.invalidate();
        in_flight.await.unwrap().unwrap();

        cache.get().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn errors_are_not_cached() {
        let (cache, calls) = cache_over(StubGuardian::default());

        cache.get().await.unwrap_err();
        cache.get().await.unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
