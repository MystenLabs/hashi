// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use prometheus::Histogram;
use prometheus::IntCounter;
use prometheus::IntGauge;
use sui_sdk_types::Address;

use super::request_body::LimitedBody;
use super::route_limits::RouteLimits;
use crate::metrics::Metrics;

const REQUEST_BUDGET: &str = "request";

#[derive(Clone)]
pub(crate) struct PeerInflightLimiter(Arc<Inner>);

struct Inner {
    limit: u32,
    budget_bytes: u64,
    routes: RouteLimits,
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
    reserved: AtomicU64,
    reserved_high_water: AtomicU64,
    reserved_publish: Mutex<()>,
    reserved_max: IntGauge,
    over_byte_budget: IntCounter,
    too_large: IntCounter,
}

impl Peer {
    fn try_reserve(&self, bytes: u64, budget: u64) -> bool {
        let Ok(before) =
            self.reserved
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                    reserved.checked_add(bytes).filter(|&now| now <= budget)
                })
        else {
            return false;
        };
        let now = before + bytes;
        if self.reserved_high_water.fetch_max(now, Ordering::AcqRel) < now {
            let _publish = self.reserved_publish.lock().unwrap();
            self.reserved_max.set(
                i64::try_from(self.reserved_high_water.load(Ordering::Acquire)).unwrap_or(i64::MAX),
            );
        }
        true
    }
}

pub(super) struct RequestCharge {
    peer: Arc<Peer>,
    budget: u64,
    reserved: AtomicU64,
}

impl RequestCharge {
    pub(super) fn reserve(&self, bytes: u64) -> bool {
        if !self.peer.try_reserve(bytes, self.budget) {
            self.peer.over_byte_budget.inc();
            return false;
        }
        self.reserved.fetch_add(bytes, Ordering::AcqRel);
        true
    }

    pub(super) fn refuse_too_large(&self) {
        self.peer.too_large.inc();
    }
}

impl Drop for RequestCharge {
    fn drop(&mut self) {
        self.peer
            .reserved
            .fetch_sub(*self.reserved.get_mut(), Ordering::AcqRel);
    }
}

impl PeerInflightLimiter {
    pub(crate) fn new(
        limit: u32,
        budget_bytes: u64,
        routes: RouteLimits,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self(Arc::new(Inner {
            limit,
            budget_bytes,
            routes,
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
                    reserved: AtomicU64::new(0),
                    reserved_high_water: AtomicU64::new(0),
                    reserved_publish: Mutex::new(()),
                    reserved_max: metrics
                        .peer_inflight_max_bytes
                        .with_label_values(&[label.as_str(), REQUEST_BUDGET]),
                    over_byte_budget: metrics
                        .peer_requests_over_byte_budget_total
                        .with_label_values(&[label.as_str(), REQUEST_BUDGET]),
                    too_large: metrics
                        .peer_requests_too_large_total
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

    #[cfg(test)]
    fn reserved(&self, address: Address) -> u64 {
        self.peer(address).reserved.load(Ordering::Acquire)
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
    let charge = Arc::new(RequestCharge {
        peer: slot.0.clone(),
        budget: limiter.0.budget_bytes,
        reserved: AtomicU64::new(0),
    });
    let path = request.uri().path();
    let request = match limiter.0.routes.limit(path) {
        Some(limit) => {
            let single_message = !super::route_limits::streams_requests(path);
            let charge = charge.clone();
            request.map(|body| {
                axum::body::Body::new(LimitedBody::new(body, charge, limit, single_message))
            })
        }
        None => request,
    };
    // Held across the handler, since tonic drops a unary body before calling it.
    let response = next.run(request).await;
    drop(charge);
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

#[derive(Clone)]
pub(crate) struct CallerTaskLimiter {
    tasks: Arc<Mutex<HashMap<Address, CallerTasks>>>,
    metrics: Arc<Metrics>,
}

#[derive(Default)]
struct CallerTasks {
    active: usize,
    high_water: usize,
}

pub(crate) struct CallerTaskSlot {
    tasks: Arc<Mutex<HashMap<Address, CallerTasks>>>,
    caller: Address,
}

impl CallerTaskLimiter {
    pub(crate) fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            metrics,
        }
    }

    pub(crate) fn try_admit(&self, caller: Address, limit: usize) -> Option<CallerTaskSlot> {
        let mut tasks = self.tasks.lock().unwrap();
        let entry = tasks.entry(caller).or_default();
        if entry.active >= limit {
            return None;
        }
        entry.active += 1;
        if entry.active > entry.high_water {
            entry.high_water = entry.active;
            self.metrics
                .withdrawal_signing_tasks_max
                .with_label_values(&[&caller.to_string()])
                .set(entry.high_water as i64);
        }
        Some(CallerTaskSlot {
            tasks: self.tasks.clone(),
            caller,
        })
    }
}

impl Drop for CallerTaskSlot {
    fn drop(&mut self) {
        if let Some(entry) = self.tasks.lock().unwrap().get_mut(&self.caller) {
            entry.active -= 1;
        }
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
        let limiter = PeerInflightLimiter::new(
            limit,
            u64::MAX,
            RouteLimits::default(),
            Arc::new(Metrics::new(&registry)),
        );
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

    const HEALTH: &str = "grpc.health.v1.Health";
    const HEALTH_LIMIT: usize = 64 * 1024;
    const WATCH_CAP: usize = 16;

    fn health_routes() -> RouteLimits {
        let mut routes = RouteLimits::default();
        routes.service(HEALTH, HEALTH_LIMIT);
        routes.method(HEALTH, "Watch", WATCH_CAP);
        routes
    }

    fn serve<S>(limiter: PeerInflightLimiter, health: S) -> sui_http::ServerHandle
    where
        S: tower::Service<
                axum::extract::Request,
                Response: axum::response::IntoResponse,
                Error = std::convert::Infallible,
            > + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let router = Router::new()
            .route_service(&format!("/{HEALTH}/{{*rest}}"), health)
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(gate))
                    .layer(axum::middleware::from_fn_with_state(
                        limiter,
                        limit_per_peer,
                    )),
            );
        sui_http::Builder::new()
            .serve(("127.0.0.1", 0), router)
            .unwrap()
    }

    async fn connect(address: std::net::SocketAddr) -> h2::client::SendRequest<bytes::Bytes> {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let (client, connection) = h2::client::handshake(tcp).await.unwrap();
        tokio::spawn(connection);
        client
    }

    async fn open(
        client: &h2::client::SendRequest<bytes::Bytes>,
        method: &str,
        id: u8,
        grpc: bool,
    ) -> (h2::client::ResponseFuture, h2::SendStream<bytes::Bytes>) {
        let mut request = http::Request::post(format!("http://localhost/{HEALTH}/{method}"))
            .header("te", "trailers")
            .header("x-peer", http::HeaderValue::from_bytes(&[id]).unwrap());
        if grpc {
            request = request.header(http::header::CONTENT_TYPE, "application/grpc");
        }
        let mut client = client.clone().ready().await.unwrap();
        client
            .send_request(request.body(()).unwrap(), false)
            .unwrap()
    }

    fn prefix(len: u32) -> Vec<u8> {
        let mut bytes = vec![0];
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes
    }

    async fn grpc_status(response: h2::client::ResponseFuture) -> tonic::Status {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let response = response.await.unwrap();
            if let Some(status) = tonic::Status::from_header_map(response.headers()) {
                return status;
            }
            let mut body = response.into_body();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
            tonic::Status::from_header_map(&body.trailers().await.unwrap().unwrap()).unwrap()
        })
        .await
        .unwrap()
    }

    async fn until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_peer_is_held_to_its_declared_bytes_and_a_finished_message_needs_no_end_stream() {
        let prefix_len = crate::grpc::request_body::PREFIX_LEN;
        let registry = prometheus::Registry::new();
        let limiter = PeerInflightLimiter::new(
            200,
            2 * (HEALTH_LIMIT as u64 + prefix_len),
            health_routes(),
            Arc::new(Metrics::new(&registry)),
        );
        let (reporter, health) = tonic_health::server::health_reporter();
        reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        let server = serve(
            limiter.clone(),
            health.max_decoding_message_size(HEALTH_LIMIT),
        );
        let client = connect(*server.local_addr()).await;

        let stalled_len = 60 * 1024;
        let mut stalled = Vec::new();
        for _ in 0..2 {
            let (response, mut stream) = open(&client, "Check", b'a', true).await;
            let mut data = prefix(stalled_len);
            data.push(0);
            stream.send_data(data.into(), false).unwrap();
            stalled.push((response, stream));
        }
        let held = 2 * (prefix_len + u64::from(stalled_len));
        until(|| limiter.reserved(peer(b'a')) == held).await;

        let (response, mut stream) = open(&client, "Check", b'a', true).await;
        stream.send_data(prefix(stalled_len).into(), false).unwrap();
        let shed = grpc_status(response).await;
        assert_eq!(shed.code(), tonic::Code::Unavailable, "{shed:?}");
        assert!(
            shed.message()
                .contains(crate::grpc::PEER_INFLIGHT_LIMIT_MSG)
        );
        assert_eq!(limiter.peer(peer(b'a')).over_byte_budget.get(), 1);
        assert_eq!(limiter.reserved(peer(b'a')), held);

        let (response, mut stream) = open(&client, "Check", b'b', true).await;
        stream.send_data(prefix(0).into(), true).unwrap();
        assert_eq!(grpc_status(response).await.code(), tonic::Code::Ok);

        let (response, mut stream) = open(&client, "Check", b'c', true).await;
        stream.send_data(vec![0, 0, 0].into(), false).unwrap();
        stream
            .send_data(vec![0, 3, 0x0a, 0x01, b'x', 9, 9, 9].into(), false)
            .unwrap();
        let status = grpc_status(response).await;
        assert_eq!(status.code(), tonic::Code::NotFound, "{status:?}");
        drop(stream);

        let (response, mut stream) = open(&client, "Watch", b'd', false).await;
        stream
            .send_data(prefix(WATCH_CAP as u32 + 1).into(), false)
            .unwrap();
        let status = grpc_status(response).await;
        assert_eq!(status.code(), tonic::Code::OutOfRange, "{status:?}");
        assert_eq!(limiter.peer(peer(b'd')).too_large.get(), 1);
        assert_eq!(limiter.reserved(peer(b'd')), 0);

        for (_, mut stream) in stalled {
            stream.send_reset(h2::Reason::CANCEL);
        }
        until(|| limiter.reserved(peer(b'a')) == 0).await;
    }

    #[test]
    fn a_caller_at_its_signing_cap_is_refused_until_one_of_its_tasks_ends() {
        let limit = 4;
        let registry = prometheus::Registry::new();
        let limiter = CallerTaskLimiter::new(Arc::new(Metrics::new(&registry)));

        let mut held: Vec<_> = (0..limit)
            .map(|_| limiter.try_admit(peer(b'a'), limit).unwrap())
            .collect();
        assert!(limiter.try_admit(peer(b'a'), limit).is_none());
        assert!(limiter.try_admit(peer(b'b'), limit).is_some());

        held.pop();
        assert!(limiter.try_admit(peer(b'a'), limit).is_some());
        assert_eq!(
            limiter
                .metrics
                .withdrawal_signing_tasks_max
                .with_label_values(&[&peer(b'a').to_string()])
                .get(),
            limit as i64
        );
    }
}
