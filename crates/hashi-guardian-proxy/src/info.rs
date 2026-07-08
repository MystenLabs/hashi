// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Read-only HTTP surface for the proxy: `GET /info` (a curated JSON projection
//! of the enclave's signed `GetGuardianInfo`) and `GET /health` (proxy
//! liveness), with permissive CORS. It lets browser/`fetch` clients like the
//! hashi-ts-sdk read the withdrawal rate-limiter state that the gRPC surface
//! only exposes to nodes. `u64`s serialize as strings (JSON/JS `2^53`), and
//! `limiter`/`btcPubkey`/`committeeEpoch` are `null` until the guardian is
//! provisioned. The S3 bucket and KP shares are deliberately not exposed.

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
use hashi_types::guardian::LimiterConfig;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::VerifiedGuardianInfo;
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

/// gRPC client to the enclave plus a single-slot TTL cache, so a burst of public
/// `/info` hits collapses to at most one (uncached) `GetGuardianInfo` per `ttl`.
#[derive(Clone)]
pub struct InfoState {
    client: GuardianServiceClient<Channel>,
    cache: Arc<Mutex<Option<(Instant, GuardianInfoView)>>>,
    ttl: Duration,
}

impl InfoState {
    pub fn new(client: GuardianServiceClient<Channel>, ttl: Duration) -> Self {
        Self {
            client,
            cache: Arc::new(Mutex::new(None)),
            ttl,
        }
    }

    fn cached(&self) -> Option<GuardianInfoView> {
        let guard = self.cache.lock().expect("info cache mutex poisoned");
        guard
            .as_ref()
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, view)| view.clone())
    }

    fn store(&self, view: GuardianInfoView) {
        *self.cache.lock().expect("info cache mutex poisoned") = Some((Instant::now(), view));
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
    if let Some(view) = state.cached() {
        return Json(view).into_response();
    }

    // Fetch outside the lock so the handler stays `Send`; a few racing misses
    // each hitting the enclave on a cold cache is harmless.
    let raw = match state
        .client
        .clone()
        .get_guardian_info(proto::GetGuardianInfoRequest {})
        .await
    {
        Ok(resp) => resp.into_inner(),
        Err(status) => return unavailable("guardian_unreachable", &status.to_string()),
    };

    // Read the signing timestamp off the raw proto; the domain conversion drops it.
    let signed_at_ms = raw.signed_info.as_ref().and_then(|s| s.timestamp_ms);
    let verified = match GetGuardianInfoResponse::try_from(raw)
        .and_then(|resp| resp.verify_signed_info_without_attestation())
    {
        Ok(verified) => verified,
        Err(e) => {
            error!(error = ?e, "GetGuardianInfo could not be decoded/verified for /info");
            return unavailable("guardian_info_invalid", &format!("{e:?}"));
        }
    };

    let view = project(&verified, signed_at_ms);
    state.store(view.clone());
    Json(view).into_response()
}

fn unavailable(error: &str, detail: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": error, "detail": detail })),
    )
        .into_response()
}

fn project(verified: &VerifiedGuardianInfo, signed_at_ms: Option<u64>) -> GuardianInfoView {
    let info = &verified.info;
    GuardianInfoView {
        limiter: limiter_view(info.limiter_state, info.limiter_config),
        git_revision: info.untrusted_git_revision.clone(),
        committee_epoch: info.current_committee_epoch.map(|e| e.to_string()),
        btc_pubkey: info
            .enclave_btc_pubkey
            .as_ref()
            .map(|pk| hex::encode(pk.serialize())),
        signing_pub_key: hex::encode(verified.signing_pub_key.as_bytes()),
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
}
