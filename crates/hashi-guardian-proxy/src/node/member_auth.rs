// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The gate in front of every route, on both listeners: node RPCs are served
//! only to members of the current or pending committee, identified by the TLS
//! client certificate they present with their registered key on the node
//! listener ([`crate::tls`]). Besides node RPCs, the node listener serves only
//! `GetGuardianInfo`, since nothing in front of it rate-limits callers. It
//! mirrors the node's `require_known_validator`.

use std::sync::Arc;

use axum::extract::Request;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use hashi_types::proto::guardian_relay_service_server;
use hashi_types::proto::guardian_service_server;
use tonic::metadata::GRPC_CONTENT_TYPE;
use tonic::Status;

use crate::metrics::ProxyMetrics;
use crate::node::members::MemberAllowlist;
use crate::tls;

pub struct MemberGate {
    allowlist: Arc<MemberAllowlist>,
    metrics: Arc<ProxyMetrics>,
}

impl MemberGate {
    pub fn new(allowlist: Arc<MemberAllowlist>, metrics: Arc<ProxyMetrics>) -> Self {
        Self { allowlist, metrics }
    }

    /// Only the node listener takes client certificates, and it requires an
    /// Ed25519 one, so a key means the call came in on the node listener.
    fn admit(&self, route: Route, client_tls_key: Option<[u8; 32]>) -> Result<(), Refusal> {
        let key = match (route, client_tls_key) {
            (Route::GuardianInfo, _) | (Route::Public, None) => return Ok(()),
            (Route::Public, Some(_)) => return Err(Refusal::PublicOnly),
            (Route::Node, None) => return Err(Refusal::NoClientCert),
            (Route::Node, Some(key)) => key,
        };
        let snapshot = self
            .allowlist
            .current()
            .ok_or(Refusal::AllowlistUnavailable)?;
        if !snapshot.members.contains(&key) {
            return Err(Refusal::NotMember);
        }
        Ok(())
    }
}

pub async fn require_committee_member(
    State(gate): State<Arc<MemberGate>>,
    request: Request,
    next: Next,
) -> Response {
    let client_tls_key = request
        .extensions()
        .get::<sui_http::PeerCertificates>()
        .and_then(|certs| certs.peer_certs().first())
        .and_then(tls::node_tls_key);
    match gate.admit(Route::of(request.uri().path()), client_tls_key) {
        Ok(()) => next.run(request).await,
        Err(refusal) => {
            gate.metrics
                .member_refused
                .with_label_values(&[refusal.reason()])
                .inc();
            refuse(&request, refusal)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// Open on both listeners: every node polls it, member or not.
    GuardianInfo,
    /// Status and health checks, attested guardian info, and the KP RPCs,
    /// which carry their own signatures: open, on the public listener only.
    Public,
    /// Everything else, on the node listener to committee members.
    Node,
}

impl Route {
    fn of(path: &str) -> Self {
        if matches!(path, "/info" | "/health") {
            return Self::Public;
        }
        let Some((service, method)) = path.strip_prefix('/').and_then(|path| path.split_once('/'))
        else {
            return Self::Node;
        };
        match (service, method) {
            (guardian_service_server::SERVICE_NAME, "GetGuardianInfo") => Self::GuardianInfo,
            (
                guardian_service_server::SERVICE_NAME,
                "GetAttestedGuardianInfo" | "ConfirmCeremony" | "ProvisionerRotateCert",
            )
            | (
                guardian_relay_service_server::SERVICE_NAME
                | tonic_health::pb::health_server::SERVICE_NAME,
                _,
            ) => Self::Public,
            _ => Self::Node,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    NoClientCert,
    PublicOnly,
    AllowlistUnavailable,
    NotMember,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::NoClientCert => "no_client_cert",
            Self::PublicOnly => "public_only",
            Self::AllowlistUnavailable => "allowlist_unavailable",
            Self::NotMember => "not_member",
        }
    }

    fn status(self) -> Status {
        match self {
            Self::NoClientCert => Status::unauthenticated(
                "node RPCs are served only on the guardian's node endpoint (guardian_node_url), \
                 to committee members presenting their registered TLS key",
            ),
            Self::PublicOnly => Status::permission_denied(
                "served only on the guardian's public endpoint (guardian_url)",
            ),
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

    const WITHDRAWAL: &str = "/sui.hashi.v1alpha.GuardianService/StandardWithdrawal";

    fn member_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
    }

    fn gate_with_member() -> MemberGate {
        let metrics = Arc::new(ProxyMetrics::new());
        let allowlist = Arc::new(MemberAllowlist::new(metrics.clone()));
        allowlist.store(snapshot(&[&member_key()]));
        MemberGate::new(allowlist, metrics)
    }

    fn tls_key(key: &ed25519_dalek::SigningKey) -> Option<[u8; 32]> {
        Some(key.verifying_key().to_bytes())
    }

    #[test]
    fn admits_a_member_and_refuses_everyone_else() {
        let gate = gate_with_member();
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        assert_eq!(gate.admit(Route::Node, tls_key(&member_key())), Ok(()));
        assert_eq!(
            gate.admit(Route::Node, tls_key(&outsider)),
            Err(Refusal::NotMember)
        );
        assert_eq!(gate.admit(Route::Node, None), Err(Refusal::NoClientCert));
    }

    #[test]
    fn the_node_listener_serves_nothing_public_but_guardian_info() {
        let gate = gate_with_member();
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        for client_tls_key in [None, tls_key(&member_key()), tls_key(&outsider)] {
            assert_eq!(gate.admit(Route::GuardianInfo, client_tls_key), Ok(()));
        }
        assert_eq!(gate.admit(Route::Public, None), Ok(()));
        for client_tls_key in [tls_key(&member_key()), tls_key(&outsider)] {
            assert_eq!(
                gate.admit(Route::Public, client_tls_key),
                Err(Refusal::PublicOnly)
            );
        }
    }

    #[test]
    fn refuses_everyone_without_a_snapshot() {
        let metrics = Arc::new(ProxyMetrics::new());
        let gate = MemberGate::new(Arc::new(MemberAllowlist::new(metrics.clone())), metrics);
        assert_eq!(
            gate.admit(Route::Node, tls_key(&member_key())),
            Err(Refusal::AllowlistUnavailable)
        );
    }

    #[test]
    fn each_refusal_has_its_status_code() {
        assert_eq!(
            Refusal::NoClientCert.status().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            Refusal::PublicOnly.status().code(),
            tonic::Code::PermissionDenied
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
    fn routes_each_path() {
        for path in [
            "/info",
            "/health",
            "/grpc.health.v1.Health/Check",
            "/sui.hashi.v1alpha.GuardianRelayService/SingleProvisionerInit",
            "/sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo",
            "/sui.hashi.v1alpha.GuardianService/GetAttestedGuardianInfo",
            "/sui.hashi.v1alpha.GuardianService/ConfirmCeremony",
            "/sui.hashi.v1alpha.GuardianService/ProvisionerRotateCert",
        ] {
            assert_eq!(Route::of(path), Route::Public, "{path}");
        }
        assert_eq!(
            Route::of("/sui.hashi.v1alpha.GuardianService/GetGuardianInfo"),
            Route::GuardianInfo
        );
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
            assert_eq!(Route::of(path), Route::Node, "{path}");
        }
    }
}
