// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::PoisonError;
use std::time::Duration;

use prometheus::IntCounter;
use prometheus::IntGauge;
use sui_http::PeerCertificates;
use sui_http::ServerHandle;
use sui_sdk_types::Address;
use tokio::time::Instant;

use crate::metrics::Metrics;

const SCAN_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub(crate) struct ConnectionLimiter(Arc<Inner>);

struct Inner {
    limit: usize,
    server: OnceLock<Arc<ServerHandle>>,
    state: Mutex<State>,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct State {
    live: Option<(Instant, HashSet<usize>)>,
    members: HashMap<Address, Member>,
}

struct Member {
    connections: Vec<(PeerCertificates, Instant)>,
    high_water: usize,
    max: IntGauge,
    refused: IntCounter,
}

impl ConnectionLimiter {
    pub(crate) fn new(limit: usize, metrics: Arc<Metrics>) -> Self {
        Self(Arc::new(Inner {
            limit,
            server: OnceLock::new(),
            state: Mutex::new(State::default()),
            metrics,
        }))
    }

    pub(crate) fn set_server(&self, server: Arc<ServerHandle>) {
        let _ = self.0.server.set(server);
    }

    fn admit(&self, member: Address, certs: Option<&PeerCertificates>) -> bool {
        let Some(certs) = certs else {
            return false;
        };
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        let State { live, members } = &mut *state;
        let entry = members.entry(member).or_insert_with(|| {
            let label = member.to_string();
            Member {
                connections: Vec::new(),
                high_water: 0,
                max: self
                    .0
                    .metrics
                    .peer_connections_max
                    .with_label_values(&[&label]),
                refused: self
                    .0
                    .metrics
                    .peer_requests_over_connection_limit_total
                    .with_label_values(&[&label]),
            }
        });
        let key = certs.peer_certs().as_ptr();
        if entry
            .connections
            .iter()
            .any(|(known, _)| known.peer_certs().as_ptr() == key)
        {
            return true;
        }
        if let Some((taken, live)) = self.refresh(live) {
            entry.connections.retain(|(known, since)| {
                since >= taken || live.contains(&(known.peer_certs().as_ptr() as usize))
            });
        }
        if entry.connections.len() >= self.0.limit {
            entry.refused.inc();
            return false;
        }
        entry.connections.push((certs.clone(), Instant::now()));
        if entry.connections.len() > entry.high_water {
            entry.high_water = entry.connections.len();
            entry
                .max
                .set(i64::try_from(entry.high_water).unwrap_or(i64::MAX));
        }
        true
    }

    fn refresh<'a>(
        &self,
        live: &'a mut Option<(Instant, HashSet<usize>)>,
    ) -> Option<&'a (Instant, HashSet<usize>)> {
        let now = Instant::now();
        let stale = live
            .as_ref()
            .is_none_or(|(taken, _)| now.duration_since(*taken) >= SCAN_INTERVAL);
        if stale && let Some(server) = self.0.server.get() {
            let connections = server
                .connections()
                .values()
                .filter_map(|connection| connection.peer_certificates())
                .map(|certs| certs.peer_certs().as_ptr() as usize)
                .collect();
            *live = Some((now, connections));
        }
        live.as_ref()
    }
}

pub(crate) async fn limit_connections_per_peer(
    axum::extract::State(limiter): axum::extract::State<ConnectionLimiter>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(member) = request.extensions().get::<Address>().copied() else {
        return next.run(request).await;
    };
    if !limiter.admit(member, request.extensions().get::<PeerCertificates>()) {
        return super::unavailable(&request, super::PEER_CONNECTION_LIMIT_MSG);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMBER: Address = Address::new([1; 32]);

    async fn gate(
        mut request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        request.extensions_mut().insert(MEMBER);
        next.run(request).await
    }

    fn serve(limiter: &ConnectionLimiter) -> (Arc<ServerHandle>, ed25519_dalek::VerifyingKey) {
        crate::init_crypto_provider();
        let server_key = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let router = axum::Router::new().fallback(|| async { "ok" }).layer(
            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(gate))
                .layer(axum::middleware::from_fn_with_state(
                    limiter.clone(),
                    limit_connections_per_peer,
                )),
        );
        let server = Arc::new(
            sui_http::Builder::new()
                .tls_config(crate::tls::make_server_config(server_key.clone()))
                .serve("127.0.0.1:0", router)
                .unwrap(),
        );
        limiter.set_server(server.clone());
        (server, server_key.verifying_key())
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn connect(
        address: std::net::SocketAddr,
        server_key: &ed25519_dalek::VerifyingKey,
    ) -> h2::client::SendRequest<bytes::Bytes> {
        let client_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let config = crate::tls::make_client_config_with_client_auth(&client_key, server_key);
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(
                rustls::pki_types::ServerName::try_from("hashi").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let (client, connection) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(connection);
        client
    }

    async fn refusal(client: &h2::client::SendRequest<bytes::Bytes>) -> Option<tonic::Status> {
        let request = http::Request::post("https://hashi/test")
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .body(())
            .unwrap();
        let mut client = client.clone().ready().await.unwrap();
        let (response, _) = client.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        tonic::Status::from_header_map(response.headers())
    }

    #[tokio::test]
    async fn a_peer_is_served_on_at_most_four_live_connections() {
        let registry = prometheus::Registry::new();
        let limiter = ConnectionLimiter::new(4, Arc::new(Metrics::new(&registry)));
        let (server, server_key) = serve(&limiter);
        let mut clients = Vec::new();
        for _ in 0..4 {
            let client = connect(*server.local_addr(), &server_key).await;
            assert!(refusal(&client).await.is_none());
            clients.push(client);
        }
        clients.push(connect(*server.local_addr(), &server_key).await);
        let refused = refusal(&clients[4]).await.unwrap();
        assert_eq!(refused.code(), tonic::Code::Unavailable);
        assert!(
            refused
                .message()
                .contains(crate::grpc::PEER_INFLIGHT_LIMIT_MSG)
        );
        assert!(refusal(&clients[0]).await.is_none());

        drop(clients.remove(0));
        until(|| server.number_of_connections() == 4).await;
        tokio::time::sleep(SCAN_INTERVAL).await;
        assert!(refusal(&clients[3]).await.is_none());

        let state = limiter.0.state.lock().unwrap();
        assert_eq!(state.members[&MEMBER].refused.get(), 1);
        assert_eq!(state.members[&MEMBER].max.get(), 4);
    }
}
