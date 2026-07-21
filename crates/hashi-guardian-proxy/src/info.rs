// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only HTTP surface for the proxy: `GET /info` (a curated JSON projection
//! of the enclave's signed `GetGuardianInfo`) and `GET /health` (proxy
//! liveness), with permissive CORS. It lets browser/`fetch` clients like the
//! hashi-ts-sdk read the withdrawal rate-limiter state that the gRPC surface
//! only exposes to nodes. `u64`s serialize as strings (JSON/JS `2^53`), and
//! `limiter`/`btcPubkey`/`committeeEpoch` are `null` until the guardian is
//! provisioned. The S3 bucket and KP shares are deliberately not exposed.
//!
//! `/info` is public and polled by every SDK client, so it fronts the enclave
//! with a single-slot TTL cache and single-flight refresh: a burst of hits
//! collapses to at most one `GetGuardianInfo` per TTL, and while the enclave is
//! briefly unreachable the last good view is served (its age is visible via
//! `signedAtMs`) rather than erroring.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use axum::extract::State;
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::Json;
use axum::Router;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use serde::Serialize;
use serde_json::json;
use tonic::transport::Channel;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;
use tracing::error;

/// Curated, read-only projection of `GuardianInfo` served at `GET /info`.
/// Pubkeys are hex; `signed_at_ms` is a freshness signal.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GuardianInfoView {
    limiter: Option<LimiterView>,
    git_revision: String,
    committee_epoch: Option<String>,
    btc_pubkey: Option<String>,
    signing_pub_key: String,
    signed_at_ms: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LimiterView {
    state: LimiterStateView,
    config: LimiterConfigView,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LimiterStateView {
    num_tokens_available_sats: String,
    last_updated_at_secs: String,
    next_seq: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LimiterConfigView {
    refill_rate_sats_per_sec: String,
    max_bucket_capacity_sats: String,
}

/// Why an `/info` refresh could not produce a fresh view. Kept transport-shaped
/// so the source stays decoupled from the HTTP response contract.
enum InfoError {
    /// The enclave gRPC call failed (unreachable / deadline / transport).
    Unreachable(String),
    /// The response could not be converted to the guardian domain type.
    Invalid(String),
}

impl InfoError {
    fn into_response(self) -> Response {
        match self {
            InfoError::Unreachable(detail) => unavailable("guardian_unreachable", &detail),
            InfoError::Invalid(detail) => unavailable("guardian_info_invalid", &detail),
        }
    }
}

/// Source of a fresh [`GuardianInfoView`]. A trait so the cache can be tested
/// without a live enclave or a signed response to verify against.
#[tonic::async_trait]
trait InfoSource: Send + Sync + 'static {
    async fn fetch(&self) -> Result<GuardianInfoView, InfoError>;
}

/// [`InfoSource`] backed by the enclave's gRPC `GetGuardianInfo`, verifying and
/// projecting the signed response.
struct GrpcInfoSource {
    client: GuardianServiceClient<Channel>,
}

#[tonic::async_trait]
impl InfoSource for GrpcInfoSource {
    async fn fetch(&self) -> Result<GuardianInfoView, InfoError> {
        let raw = self
            .client
            .clone()
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await
            .map_err(|status| InfoError::Unreachable(status.to_string()))?
            .into_inner();

        // Read the signing timestamp off the raw proto; the domain conversion drops it.
        let signed_at_ms = raw.signed_info.as_ref().and_then(|s| s.timestamp_ms);
        let response = GetGuardianInfoResponse::try_from(raw).map_err(|e| {
            error!(error = ?e, "GetGuardianInfo could not be decoded for /info");
            InfoError::Invalid(format!("{e:?}"))
        })?;
        let (info, signing_pub_key) = response.into_info_unchecked();
        Ok(project(&info, &signing_pub_key, signed_at_ms))
    }
}

/// The `/info` cache: the last projected view plus a refresh lock. Reads take
/// the fast path off `slot`; a miss elects one refresher via `refresh` so a
/// burst of public hits collapses to a single backend call.
struct InfoCache {
    slot: Mutex<Option<(Instant, GuardianInfoView)>>,
    refresh: tokio::sync::Mutex<()>,
}

/// Backend source plus its single-slot TTL cache, so a burst of public `/info`
/// hits collapses to at most one `GetGuardianInfo` per `ttl`.
#[derive(Clone)]
pub struct InfoState {
    source: Arc<dyn InfoSource>,
    cache: Arc<InfoCache>,
    ttl: Duration,
}

impl InfoState {
    pub fn new(client: GuardianServiceClient<Channel>, ttl: Duration) -> Self {
        Self::with_source(Arc::new(GrpcInfoSource { client }), ttl)
    }

    fn with_source(source: Arc<dyn InfoSource>, ttl: Duration) -> Self {
        Self {
            source,
            cache: Arc::new(InfoCache {
                slot: Mutex::new(None),
                refresh: tokio::sync::Mutex::new(()),
            }),
            ttl,
        }
    }

    /// Serve `/info`: a fresh cached view, otherwise one single-flighted
    /// refresh whose result (or, if the enclave is down, the last good view) is
    /// shared with every concurrent caller.
    async fn serve(&self) -> Response {
        if let Some(view) = self.fresh() {
            return Json(view).into_response();
        }

        // Elect a single refresher. Concurrent callers serve the last good view
        // rather than pile onto the enclave; on a cold cache (nothing to serve)
        // they instead wait for that one refresh.
        let refreshed = match self.cache.refresh.try_lock() {
            Ok(_leader) => self.refresh_locked().await,
            Err(_) => match self.last_good() {
                Some(view) => return Json(view).into_response(),
                None => {
                    let _leader = self.cache.refresh.lock().await;
                    self.refresh_locked().await
                }
            },
        };

        match refreshed {
            Ok(view) => Json(view).into_response(),
            // Enclave unreachable: the last good view (its age is visible via
            // `signedAtMs`) beats a hard error for an advisory route.
            Err(err) => self
                .last_good()
                .map(|view| Json(view).into_response())
                .unwrap_or_else(|| err.into_response()),
        }
    }

    /// Refresh from the backend. Call with `refresh` held; re-checks the cache
    /// first so callers that queued behind the leader reuse its fetch.
    async fn refresh_locked(&self) -> Result<GuardianInfoView, InfoError> {
        if let Some(view) = self.fresh() {
            return Ok(view);
        }
        let view = self.source.fetch().await?;
        self.store(view.clone());
        Ok(view)
    }

    /// The cached view if it is still within its TTL.
    fn fresh(&self) -> Option<GuardianInfoView> {
        let slot = self.cache.slot.lock().expect("info cache mutex poisoned");
        slot.as_ref()
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, view)| view.clone())
    }

    /// The last successfully fetched view regardless of age.
    fn last_good(&self) -> Option<GuardianInfoView> {
        self.cache
            .slot
            .lock()
            .expect("info cache mutex poisoned")
            .as_ref()
            .map(|(_, view)| view.clone())
    }

    fn store(&self, view: GuardianInfoView) {
        *self.cache.slot.lock().expect("info cache mutex poisoned") = Some((Instant::now(), view));
    }
}

/// Router for the HTTP status surface, with permissive CORS (public read-only
/// data, so any origin; no credentials).
pub fn router(state: InfoState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::OPTIONS])
        .allow_headers(Any);
    Router::new()
        .route("/info", get(get_info))
        .route("/health", get(health))
        .layer(cors)
        .with_state(state)
}

/// Proxy liveness only — never gated on the enclave, so an enclave hiccup can't
/// deregister the target and take `/info` dark.
async fn health() -> StatusCode {
    StatusCode::OK
}

async fn get_info(State(state): State<InfoState>) -> Response {
    state.serve().await
}

fn unavailable(error: &str, detail: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": error, "detail": detail })),
    )
        .into_response()
}

fn project(
    info: &GuardianInfo,
    signing_pub_key: &GuardianPubKey,
    signed_at_ms: Option<u64>,
) -> GuardianInfoView {
    GuardianInfoView {
        limiter: limiter_view(info.limiter_state, info.limiter_config),
        git_revision: info.untrusted_git_revision.clone(),
        committee_epoch: info.current_committee_epoch.map(|e| e.to_string()),
        btc_pubkey: info
            .enclave_btc_pubkey
            .as_ref()
            .map(|pk| hex::encode(pk.serialize())),
        signing_pub_key: hex::encode(signing_pub_key.as_bytes()),
        signed_at_ms: signed_at_ms.map(|t| t.to_string()),
    }
}

/// Reported only when both halves are present — a half-initialized limiter is
/// useless, so the client sees `limiter` as a single nullable object.
fn limiter_view(state: Option<LimiterState>, config: Option<LimiterConfig>) -> Option<LimiterView> {
    let (state, config) = (state?, config?);
    Some(LimiterView {
        state: LimiterStateView {
            num_tokens_available_sats: state.num_tokens_available.to_string(),
            last_updated_at_secs: state.last_updated_at.to_string(),
            next_seq: state.next_seq.to_string(),
        },
        config: LimiterConfigView {
            refill_rate_sats_per_sec: config.refill_rate.to_string(),
            max_bucket_capacity_sats: config.max_bucket_capacity.to_string(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    fn limiter_state() -> LimiterState {
        LimiterState {
            num_tokens_available: 12_345,
            last_updated_at: 1_720_000_000,
            next_seq: 42,
        }
    }

    fn limiter_config() -> LimiterConfig {
        LimiterConfig {
            refill_rate: 1_000,
            max_bucket_capacity: 2_000_000,
        }
    }

    #[test]
    fn limiter_view_requires_both_state_and_config() {
        assert!(limiter_view(None, None).is_none());
        assert!(limiter_view(Some(limiter_state()), None).is_none());
        assert!(limiter_view(None, Some(limiter_config())).is_none());
        assert!(limiter_view(Some(limiter_state()), Some(limiter_config())).is_some());
    }

    #[test]
    fn info_view_serializes_to_the_public_contract() {
        // Fully-initialized guardian: nested limiter, u64s as strings, camelCase.
        let view = GuardianInfoView {
            limiter: limiter_view(Some(limiter_state()), Some(limiter_config())),
            git_revision: "abc123".to_string(),
            committee_epoch: Some("7".to_string()),
            btc_pubkey: Some("deadbeef".to_string()),
            signing_pub_key: "feedface".to_string(),
            signed_at_ms: Some("1720000000123".to_string()),
        };
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({
                "limiter": {
                    "state": {
                        "numTokensAvailableSats": "12345",
                        "lastUpdatedAtSecs": "1720000000",
                        "nextSeq": "42",
                    },
                    "config": {
                        "refillRateSatsPerSec": "1000",
                        "maxBucketCapacitySats": "2000000",
                    },
                },
                "gitRevision": "abc123",
                "committeeEpoch": "7",
                "btcPubkey": "deadbeef",
                "signingPubKey": "feedface",
                "signedAtMs": "1720000000123",
            })
        );
    }

    #[test]
    fn uninitialized_info_view_emits_explicit_nulls() {
        // Pre-provisioning: limiter/committee/btc are absent but the keys stay
        // present as `null` so the client schema is stable.
        let view = GuardianInfoView {
            limiter: None,
            git_revision: "abc123".to_string(),
            committee_epoch: None,
            btc_pubkey: None,
            signing_pub_key: "feedface".to_string(),
            signed_at_ms: None,
        };
        assert_eq!(
            serde_json::to_value(&view).unwrap(),
            json!({
                "limiter": null,
                "gitRevision": "abc123",
                "committeeEpoch": null,
                "btcPubkey": null,
                "signingPubKey": "feedface",
                "signedAtMs": null,
            })
        );
    }

    fn sample_view() -> GuardianInfoView {
        GuardianInfoView {
            limiter: limiter_view(Some(limiter_state()), Some(limiter_config())),
            git_revision: "abc123".to_string(),
            committee_epoch: Some("7".to_string()),
            btc_pubkey: Some("deadbeef".to_string()),
            signing_pub_key: "feedface".to_string(),
            signed_at_ms: Some("1720000000123".to_string()),
        }
    }

    /// Test source: counts calls, can be flipped `down`, and can delay each
    /// fetch to widen the window a concurrent burst races in.
    #[derive(Clone)]
    struct FakeSource {
        view: GuardianInfoView,
        calls: Arc<AtomicUsize>,
        down: Arc<AtomicBool>,
        delay: Duration,
    }

    impl FakeSource {
        fn new(delay: Duration) -> Self {
            Self {
                view: sample_view(),
                calls: Arc::new(AtomicUsize::new(0)),
                down: Arc::new(AtomicBool::new(false)),
                delay,
            }
        }
    }

    #[tonic::async_trait]
    impl InfoSource for FakeSource {
        async fn fetch(&self) -> Result<GuardianInfoView, InfoError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.down.load(Ordering::SeqCst) {
                Err(InfoError::Unreachable("fake guardian down".to_string()))
            } else {
                Ok(self.view.clone())
            }
        }
    }

    fn state_with(fake: &FakeSource, ttl: Duration) -> InfoState {
        InfoState::with_source(Arc::new(fake.clone()), ttl)
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn concurrent_misses_collapse_to_a_single_fetch() {
        // Six cold-cache hits arrive while the one leader is still fetching; the
        // rest must reuse its result, not each call the enclave.
        let fake = FakeSource::new(Duration::from_millis(200));
        let state = state_with(&fake, Duration::from_secs(10));

        let responses = tokio::join!(
            state.serve(),
            state.serve(),
            state.serve(),
            state.serve(),
            state.serve(),
            state.serve(),
        );
        for resp in [
            responses.0,
            responses.1,
            responses.2,
            responses.3,
            responses.4,
            responses.5,
        ] {
            assert_eq!(resp.status(), StatusCode::OK);
        }
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "a burst must collapse to one GetGuardianInfo"
        );
    }

    #[tokio::test]
    async fn caches_within_ttl_then_refetches_after_expiry() {
        let fake = FakeSource::new(Duration::ZERO);
        let state = state_with(&fake, Duration::from_millis(60));

        state.serve().await;
        state.serve().await;
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "a second hit within the TTL serves from cache"
        );

        tokio::time::sleep(Duration::from_millis(90)).await;
        state.serve().await;
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            2,
            "a hit past the TTL refetches"
        );
    }

    #[tokio::test]
    async fn serves_stale_view_when_the_enclave_is_briefly_unreachable() {
        let fake = FakeSource::new(Duration::ZERO);
        let state = state_with(&fake, Duration::from_millis(60));

        state.serve().await; // prime the cache while the backend is up
        fake.down.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(90)).await; // let it go stale

        let resp = state.serve().await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a stale-but-good view beats a hard error"
        );
        assert_eq!(
            body_json(resp).await,
            serde_json::to_value(sample_view()).unwrap()
        );
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            2,
            "it still attempted a refresh"
        );
    }

    #[tokio::test]
    async fn returns_503_when_unreachable_and_the_cache_is_cold() {
        let fake = FakeSource::new(Duration::ZERO);
        fake.down.store(true, Ordering::SeqCst);
        let state = state_with(&fake, Duration::from_secs(1));

        let resp = state.serve().await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
