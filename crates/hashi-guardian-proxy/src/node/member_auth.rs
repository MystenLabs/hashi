// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The gate in front of every route: node RPCs are served only to members of
//! the current or pending committee, proven by a [`MemberAuth`] signed with
//! their registered TLS key. It mirrors the node's `require_known_validator`,
//! with the proof in a header because TLS ends at the load balancer.

use std::sync::Arc;

use axum::extract::Request;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use hashi_types::guardian::member_auth::MemberAuth;
use hashi_types::guardian::member_auth::MEMBER_AUTH_METADATA_KEY;
use hashi_types::guardian::now_timestamp_ms;
use hashi_types::proto::guardian_relay_service_server;
use hashi_types::proto::guardian_service_server;
use sui_sdk_types::Address;
use tonic::metadata::MetadataMap;
use tonic::metadata::GRPC_CONTENT_TYPE;
use tonic::Status;

use crate::metrics::ProxyMetrics;
use crate::node::members::MemberAllowlist;

pub struct MemberGate {
    allowlist: Arc<MemberAllowlist>,
    metrics: Arc<ProxyMetrics>,
}

impl MemberGate {
    pub fn new(allowlist: Arc<MemberAllowlist>, metrics: Arc<ProxyMetrics>) -> Self {
        Self { allowlist, metrics }
    }

    /// The membership lookup runs before the signature check, so a token for
    /// an unknown key costs a hash lookup rather than a verification.
    fn admit(&self, request: &Request) -> Result<Address, Refusal> {
        let metadata = MetadataMap::from_headers(request.headers().clone());
        let value = metadata
            .get_bin(MEMBER_AUTH_METADATA_KEY)
            .ok_or(Refusal::MissingAuth)?;
        let auth = value
            .to_bytes()
            .ok()
            .and_then(|bytes| MemberAuth::from_bytes(&bytes).ok())
            .ok_or(Refusal::MalformedAuth)?;
        if !auth.is_fresh(now_timestamp_ms()) {
            return Err(Refusal::StaleAuth);
        }
        let snapshot = self
            .allowlist
            .current()
            .ok_or(Refusal::AllowlistUnavailable)?;
        let member = *snapshot
            .members
            .get(&auth.tls_public_key)
            .ok_or(Refusal::NotMember)?;
        if !auth.verify_signature(snapshot.hashi_object_id, request.uri().path()) {
            return Err(Refusal::BadSignature);
        }
        Ok(member)
    }
}

pub async fn require_committee_member(
    State(gate): State<Arc<MemberGate>>,
    mut request: Request,
    next: Next,
) -> Response {
    if is_public(request.uri().path()) {
        return next.run(request).await;
    }
    match gate.admit(&request) {
        Ok(member) => {
            request.headers_mut().remove(MEMBER_AUTH_METADATA_KEY);
            request.extensions_mut().insert(member);
            next.run(request).await
        }
        Err(refusal) => {
            gate.metrics
                .member_refused
                .with_label_values(&[refusal.reason()])
                .inc();
            refuse(&request, refusal)
        }
    }
}

/// What anyone may call: status and health checks, guardian info, and the KP
/// RPCs, which carry their own signatures.
fn is_public(path: &str) -> bool {
    if matches!(path, "/info" | "/health") {
        return true;
    }
    let Some((service, method)) = path.strip_prefix('/').and_then(|path| path.split_once('/'))
    else {
        return false;
    };
    match service {
        guardian_relay_service_server::SERVICE_NAME
        | tonic_health::pb::health_server::SERVICE_NAME => true,
        guardian_service_server::SERVICE_NAME => matches!(
            method,
            "GetGuardianInfo" | "ConfirmCeremony" | "ProvisionerRotateCert"
        ),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    MissingAuth,
    MalformedAuth,
    StaleAuth,
    AllowlistUnavailable,
    NotMember,
    BadSignature,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::MissingAuth => "missing_auth",
            Self::MalformedAuth => "malformed_auth",
            Self::StaleAuth => "stale_auth",
            Self::AllowlistUnavailable => "allowlist_unavailable",
            Self::NotMember => "not_member",
            Self::BadSignature => "bad_signature",
        }
    }

    fn status(self) -> Status {
        match self {
            Self::MissingAuth => Status::unauthenticated(
                "only committee members may call this RPC; member auth is missing",
            ),
            Self::MalformedAuth => Status::unauthenticated("malformed member auth"),
            Self::StaleAuth => {
                Status::unauthenticated("member auth timestamp is outside the allowed clock skew")
            }
            Self::BadSignature => Status::unauthenticated("invalid member auth signature"),
            Self::NotMember => {
                Status::permission_denied("caller is not in the current or pending committee")
            }
            Self::AllowlistUnavailable => {
                Status::unavailable("committee member allowlist unavailable; retry")
            }
        }
    }
}

fn refuse(request: &Request, refusal: Refusal) -> Response {
    let status = refusal.status();
    let is_grpc = request
        .headers()
        .get(CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(GRPC_CONTENT_TYPE.as_bytes()));
    if is_grpc {
        status.into_http()
    } else {
        (StatusCode::FORBIDDEN, status.message().to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::members::test_utils::snapshot;
    use axum::body::Body;
    use hashi_types::guardian::member_auth::MEMBER_AUTH_MAX_SKEW_MS;
    use tonic::metadata::MetadataValue;

    const WITHDRAWAL: &str = "/sui.hashi.v1alpha.GuardianService/StandardWithdrawal";

    fn member_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
    }

    fn hashi_id() -> Address {
        Address::new([7; 32])
    }

    fn validator() -> Address {
        Address::new([2; 32])
    }

    fn gate_with_member() -> MemberGate {
        let metrics = Arc::new(ProxyMetrics::new());
        let allowlist = Arc::new(MemberAllowlist::new(metrics.clone()));
        allowlist.store(snapshot(hashi_id(), &[(&member_key(), validator())]));
        MemberGate::new(allowlist, metrics)
    }

    fn request_with(path: &str, auth: Option<Vec<u8>>) -> Request {
        let mut request = Request::builder()
            .uri(path)
            .header(CONTENT_TYPE, "application/grpc")
            .body(Body::empty())
            .unwrap();
        if let Some(bytes) = auth {
            let mut metadata = MetadataMap::new();
            metadata.insert_bin(MEMBER_AUTH_METADATA_KEY, MetadataValue::from_bytes(&bytes));
            request.headers_mut().extend(metadata.into_headers());
        }
        request
    }

    fn signed(key: &ed25519_dalek::SigningKey, hashi_id: Address, path: &str, at: u64) -> Vec<u8> {
        MemberAuth::sign(key, hashi_id, path, at).to_bytes()
    }

    #[test]
    fn admits_a_member_token_for_this_method_and_deployment() {
        let request = request_with(
            WITHDRAWAL,
            Some(signed(
                &member_key(),
                hashi_id(),
                WITHDRAWAL,
                now_timestamp_ms(),
            )),
        );
        assert_eq!(gate_with_member().admit(&request), Ok(validator()));
    }

    #[test]
    fn refuses_each_failure_with_its_reason() {
        let gate = gate_with_member();
        let now = now_timestamp_ms();
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let cases = [
            (None, Refusal::MissingAuth),
            (Some(vec![1, 2, 3]), Refusal::MalformedAuth),
            (
                Some(signed(
                    &member_key(),
                    hashi_id(),
                    WITHDRAWAL,
                    now - MEMBER_AUTH_MAX_SKEW_MS - 1_000,
                )),
                Refusal::StaleAuth,
            ),
            (
                Some(signed(&outsider, hashi_id(), WITHDRAWAL, now)),
                Refusal::NotMember,
            ),
            (
                Some(signed(
                    &member_key(),
                    hashi_id(),
                    "/sui.hashi.v1alpha.GuardianService/UpdateCommitteeChain",
                    now,
                )),
                Refusal::BadSignature,
            ),
            (
                Some(signed(
                    &member_key(),
                    Address::new([8; 32]),
                    WITHDRAWAL,
                    now,
                )),
                Refusal::BadSignature,
            ),
        ];
        for (auth, refusal) in cases {
            assert_eq!(gate.admit(&request_with(WITHDRAWAL, auth)), Err(refusal));
        }
    }

    #[test]
    fn refuses_everyone_without_a_snapshot() {
        let metrics = Arc::new(ProxyMetrics::new());
        let gate = MemberGate::new(Arc::new(MemberAllowlist::new(metrics.clone())), metrics);
        let request = request_with(
            WITHDRAWAL,
            Some(signed(
                &member_key(),
                hashi_id(),
                WITHDRAWAL,
                now_timestamp_ms(),
            )),
        );
        assert_eq!(gate.admit(&request), Err(Refusal::AllowlistUnavailable));
    }

    #[test]
    fn refusal_codes_match_the_kp_gate() {
        assert_eq!(
            Refusal::MissingAuth.status().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Refusal::MalformedAuth.status().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Refusal::StaleAuth.status().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Refusal::BadSignature.status().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Refusal::NotMember.status().code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            Refusal::AllowlistUnavailable.status().code(),
            tonic::Code::Unavailable
        );
    }

    #[test]
    fn only_the_listed_routes_are_public() {
        for path in [
            "/info",
            "/health",
            "/grpc.health.v1.Health/Check",
            "/sui.hashi.v1alpha.GuardianRelayService/SingleProvisionerInit",
            "/sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo",
            "/sui.hashi.v1alpha.GuardianService/GetGuardianInfo",
            "/sui.hashi.v1alpha.GuardianService/ConfirmCeremony",
            "/sui.hashi.v1alpha.GuardianService/ProvisionerRotateCert",
        ] {
            assert!(is_public(path), "{path} should be public");
        }
        for path in [
            WITHDRAWAL,
            "/sui.hashi.v1alpha.GuardianService/UpdateCommittee",
            "/sui.hashi.v1alpha.GuardianService/UpdateCommitteeChain",
            "/sui.hashi.v1alpha.GuardianService/OperatorInit",
            "/sui.hashi.v1alpha.GuardianService/SomeFutureRpc",
            "/metrics",
            "/info/",
            "/",
            "",
        ] {
            assert!(!is_public(path), "{path} should need a member");
        }
    }
}
