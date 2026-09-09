// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use prometheus::Histogram;
use prometheus::IntCounter;
use prometheus::IntGauge;
use sui_sdk_types::Address;

use crate::metrics::Metrics;

#[derive(Clone)]
pub(crate) struct PeerInflightLimiter(Arc<Inner>);

struct Inner {
    limit: u32,
    peers: RwLock<HashMap<Address, Arc<Peer>>>,
    metrics: Arc<Metrics>,
}

struct Peer {
    inflight: AtomicU32,
    high_water: AtomicU32,
    high_water_publish: Mutex<()>,
    at_admission: Histogram,
    max: IntGauge,
    shed: IntCounter,
}

impl PeerInflightLimiter {
    pub(crate) fn new(limit: u32, metrics: Arc<Metrics>) -> Self {
        Self(Arc::new(Inner {
            limit,
            peers: RwLock::new(HashMap::new()),
            metrics,
        }))
    }

    fn peer(&self, address: Address) -> Arc<Peer> {
        if let Some(peer) = self.0.peers.read().unwrap().get(&address) {
            return peer.clone();
        }
        self.0
            .peers
            .write()
            .unwrap()
            .entry(address)
            .or_insert_with(|| {
                let label = address.to_string();
                let metrics = &self.0.metrics;
                Arc::new(Peer {
                    inflight: AtomicU32::new(0),
                    high_water: AtomicU32::new(0),
                    high_water_publish: Mutex::new(()),
                    at_admission: metrics
                        .peer_inflight_at_admission
                        .with_label_values(&[&label]),
                    max: metrics.peer_inflight_max.with_label_values(&[&label]),
                    shed: metrics
                        .peer_requests_shed_total
                        .with_label_values(&[&label]),
                })
            })
            .clone()
    }

    fn try_admit(&self, address: Address) -> Option<Slot> {
        let peer = self.peer(address);
        let limit = self.0.limit;
        let Ok(before) = peer
            .inflight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < limit).then_some(n + 1)
            })
        else {
            peer.shed.inc();
            return None;
        };
        peer.at_admission.observe(f64::from(before));
        let now = before + 1;
        if peer.high_water.fetch_max(now, Ordering::AcqRel) < now {
            let _publish = peer.high_water_publish.lock().unwrap();
            peer.max
                .set(i64::from(peer.high_water.load(Ordering::Acquire)));
        }
        Some(Slot(peer))
    }

    #[cfg(test)]
    fn inflight(&self, address: Address) -> u32 {
        self.peer(address).inflight.load(Ordering::Acquire)
    }
}

struct Slot(Arc<Peer>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) async fn limit_per_peer(
    axum::extract::State(limiter): axum::extract::State<PeerInflightLimiter>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let Some(address) = request.extensions().get::<Address>().copied() else {
        return next.run(request).await;
    };
    let Some(slot) = limiter.try_admit(address) else {
        return shed(&request);
    };
    let response = next.run(request).await;
    response.map(|body| axum::body::Body::new(Guarded { body, _slot: slot }))
}

fn shed<B>(request: &http::Request<B>) -> axum::response::Response {
    if super::is_grpc_content_type(request.headers()) {
        tonic::Status::unavailable(super::PEER_INFLIGHT_LIMIT_MSG).into_http()
    } else {
        axum::response::IntoResponse::into_response((
            http::StatusCode::SERVICE_UNAVAILABLE,
            super::PEER_INFLIGHT_LIMIT_MSG,
        ))
    }
}

struct Guarded<B> {
    body: B,
    _slot: Slot,
}

impl<B: http_body::Body + Unpin> http_body::Body for Guarded<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use tower::Service;

    use super::*;

    fn peer(id: u8) -> Address {
        Address::new([id; 32])
    }

    async fn gate(
        mut request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        let id = request.headers().get("x-peer").map(|v| v.as_bytes()[0]);
        if let Some(id) = id {
            request.extensions_mut().insert(peer(id));
        }
        next.run(request).await
    }

    async fn handler(request: axum::extract::Request) -> &'static str {
        if request.headers().contains_key("x-hold") {
            std::future::pending::<()>().await;
        }
        "ok"
    }

    fn app(limiter: PeerInflightLimiter) -> Router {
        Router::new().route("/", get(handler)).layer(
            tower::ServiceBuilder::new()
                .layer(axum::middleware::from_fn(gate))
                .layer(axum::middleware::from_fn_with_state(
                    limiter,
                    limit_per_peer,
                )),
        )
    }

    fn request(id: u8, hold: bool, grpc: bool) -> axum::extract::Request {
        let mut builder = http::Request::builder()
            .uri("/")
            .header("x-peer", http::HeaderValue::from_bytes(&[id]).unwrap());
        if hold {
            builder = builder.header("x-hold", "1");
        }
        if grpc {
            builder = builder.header(http::header::CONTENT_TYPE, "application/grpc");
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    async fn call(app: &Router, request: axum::extract::Request) -> axum::response::Response {
        app.clone().call(request).await.unwrap()
    }

    #[tokio::test]
    async fn a_full_peer_is_shed_others_are_served_and_a_cancelled_request_frees_its_slot() {
        let limit = 3;
        let registry = prometheus::Registry::new();
        let limiter = PeerInflightLimiter::new(limit, Arc::new(Metrics::new(&registry)));
        let app = app(limiter.clone());

        let mut held: Vec<_> = (0..limit)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { call(&app, request(b'a', true, false)).await })
            })
            .collect();
        while limiter.inflight(peer(b'a')) < limit {
            tokio::task::yield_now().await;
        }

        let shed = call(&app, request(b'a', false, false)).await;
        assert_eq!(shed.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        let shed = call(&app, request(b'a', false, true)).await;
        assert_eq!(shed.status(), http::StatusCode::OK);
        assert_eq!(shed.headers().get("grpc-status").unwrap(), "14");
        assert_eq!(limiter.peer(peer(b'a')).shed.get(), 2);

        let served = call(&app, request(b'b', false, false)).await;
        assert_eq!(served.status(), http::StatusCode::OK);
        let anonymous = http::Request::builder()
            .uri("/")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(call(&app, anonymous).await.status(), http::StatusCode::OK);
        assert_eq!(limiter.inflight(peer(b'a')), limit);

        let cancelled = held.pop().unwrap();
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(limiter.inflight(peer(b'a')), limit - 1);

        let admitted = call(&app, request(b'a', false, false)).await;
        assert_eq!(admitted.status(), http::StatusCode::OK);
        assert_eq!(limiter.inflight(peer(b'a')), limit);
        drop(admitted);
        assert_eq!(limiter.inflight(peer(b'a')), limit - 1);
        assert_eq!(limiter.peer(peer(b'a')).max.get(), i64::from(limit));

        for task in held {
            task.abort();
        }
    }
}
