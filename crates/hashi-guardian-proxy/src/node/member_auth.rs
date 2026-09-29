// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The gate in front of every route, on both listeners: node RPCs are served
//! only to members of the current or pending committee, identified by the TLS
//! client certificate they present with their registered key on the node
//! listener ([`crate::tls`]). It mirrors the node's `require_known_validator`.

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

    fn admit(&self, client_tls_key: Option<[u8; 32]>) -> Result<(), Refusal> {
        let key = client_tls_key.ok_or(Refusal::NoClientCert)?;
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
    if is_public(request.uri().path()) {
        return next.run(request).await;
    }
    let client_tls_key = request
        .extensions()
        .get::<sui_http::PeerCertificates>()
        .and_then(|certs| certs.peer_certs().first())
        .and_then(tls::node_tls_key);
    match gate.admit(client_tls_key) {
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
    NoClientCert,
    AllowlistUnavailable,
    NotMember,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::NoClientCert => "no_client_cert",
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

    #[test]
    fn admits_a_member_and_refuses_everyone_else() {
        let gate = gate_with_member();
        let outsider = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        assert_eq!(
            gate.admit(Some(member_key().verifying_key().to_bytes())),
            Ok(())
        );
        assert_eq!(
            gate.admit(Some(outsider.verifying_key().to_bytes())),
            Err(Refusal::NotMember)
        );
        assert_eq!(gate.admit(None), Err(Refusal::NoClientCert));
    }

    #[test]
    fn refuses_everyone_without_a_snapshot() {
        let metrics = Arc::new(ProxyMetrics::new());
        let gate = MemberGate::new(Arc::new(MemberAllowlist::new(metrics.clone())), metrics);
        assert_eq!(
            gate.admit(Some(member_key().verifying_key().to_bytes())),
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
