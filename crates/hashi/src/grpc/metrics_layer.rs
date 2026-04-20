// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Tower callback layer plumbing for HTTP/gRPC metrics.
//!
//! This module owns every [`sui_http::middleware::callback`] handler the
//! crate uses. A single [`RpcMetricsMakeCallbackHandler`] type drives
//! both the server-side handler attached to the axum router in
//! `crate::grpc::HttpService::start` and the client-side handler attached
//! to outbound `tonic_rustls::Channel`s in `crate::grpc::client::Client`;
//! the per-role behavior is selected via the [`Role`] passed at
//! construction. The actual prometheus registration lives in
//! [`crate::metrics::Metrics`]; this module is purely the wiring that
//! observes traffic and writes into those metrics.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::http;
use bytes::Buf;
use http::request;
use http::response;
use sui_http::middleware::callback;

use crate::metrics::Metrics;

/// Which RFC 9110 role this node is playing on the observed connection.
///
/// Selects the value written to the `role` label dimension and the
/// direction each body travels relative to this node.
#[derive(Clone, Copy, Debug)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    /// Value for the `role` label dimension on every metric this module
    /// writes.
    fn label(self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Server => "server",
        }
    }

    /// Direction the request body travels from this node's perspective:
    /// the client sends the request (outbound), the server receives it
    /// (inbound).
    fn request_direction(self) -> Direction {
        match self {
            Role::Client => Direction::Outbound,
            Role::Server => Direction::Inbound,
        }
    }

    /// Direction the response body travels from this node's perspective;
    /// the inverse of [`Self::request_direction`].
    fn response_direction(self) -> Direction {
        match self {
            Role::Client => Direction::Inbound,
            Role::Server => Direction::Outbound,
        }
    }
}

/// Direction of HTTP body bytes from the perspective of this node.
/// Selects which byte counter (`bytes_sent_total` vs
/// `bytes_received_total`) the observed bytes are flushed to, and —
/// together with [`Role`] — which body (request vs response) the tally
/// was tracking.
#[derive(Clone, Copy, Debug)]
enum Direction {
    Outbound,
    Inbound,
}

/// Accumulates HTTP body bytes and, when the handler is dropped, flushes
/// the total to both the per-path size histogram and the aggregate
/// sent/received byte counter.
///
/// Flushing on `Drop` covers both the clean end-of-stream path and the
/// partial-body path (cancellation, body error) in one place, so bytes
/// that were actually transferred are always observed.
struct SizeTally {
    metrics: Arc<Metrics>,
    path: Cow<'static, str>,
    role: Role,
    direction: Direction,
    bytes: u64,
}

impl SizeTally {
    fn new(
        metrics: Arc<Metrics>,
        path: Cow<'static, str>,
        role: Role,
        direction: Direction,
    ) -> Self {
        Self {
            metrics,
            path,
            role,
            direction,
            bytes: 0,
        }
    }

    fn add(&mut self, n: usize) {
        self.bytes += n as u64;
    }
}

impl Drop for SizeTally {
    fn drop(&mut self) {
        let labels = &[self.path.as_ref(), self.role.label()];

        // (role, direction) uniquely determines whether this tally was
        // tracking the request or the response body:
        //   client + outbound = request sent; server + inbound = request received
        //   client + inbound  = response received; server + outbound = response sent
        let size_histogram = match (self.role, self.direction) {
            (Role::Client, Direction::Outbound) | (Role::Server, Direction::Inbound) => {
                &self.metrics.request_size_bytes
            }
            (Role::Client, Direction::Inbound) | (Role::Server, Direction::Outbound) => {
                &self.metrics.response_size_bytes
            }
        };
        size_histogram
            .with_label_values(labels)
            .observe(self.bytes as f64);

        let bytes_counter = match self.direction {
            Direction::Outbound => &self.metrics.bytes_sent_total,
            Direction::Inbound => &self.metrics.bytes_received_total,
        };
        bytes_counter.with_label_values(labels).inc_by(self.bytes);
    }
}

/// Single factory for the per-request handler pair used on both ends of
/// the wire. Construct with [`Self::server`] for the axum-side
/// CallbackLayer or [`Self::client`] for the tonic-channel-side
/// CallbackLayer.
#[derive(Clone)]
pub struct RpcMetricsMakeCallbackHandler {
    metrics: Arc<Metrics>,
    role: Role,
}

impl RpcMetricsMakeCallbackHandler {
    pub fn new(metrics: Arc<Metrics>, role: Role) -> Self {
        Self { metrics, role }
    }

    pub fn server(metrics: Arc<Metrics>) -> Self {
        Self::new(metrics, Role::Server)
    }

    pub fn client(metrics: Arc<Metrics>) -> Self {
        Self::new(metrics, Role::Client)
    }
}

impl callback::MakeCallbackHandler for RpcMetricsMakeCallbackHandler {
    type RequestHandler = RequestHandler;
    type ResponseHandler = ResponseHandler;

    fn make_handler(
        &self,
        request: &request::Parts,
    ) -> (Self::RequestHandler, Self::ResponseHandler) {
        let metrics = self.metrics.clone();
        let label = self.role.label();
        let path = extract_path(request, self.role);

        metrics
            .inflight_requests
            .with_label_values(&[path.as_ref(), label])
            .inc();

        let request_handler = RequestHandler {
            tally: SizeTally::new(
                metrics.clone(),
                path.clone(),
                self.role,
                self.role.request_direction(),
            ),
        };
        let response_handler = ResponseHandler {
            tally: SizeTally::new(
                metrics.clone(),
                path.clone(),
                self.role,
                self.role.response_direction(),
            ),
            metrics,
            role: self.role,
            path,
            start: Instant::now(),
            counted_response: false,
        };
        (request_handler, response_handler)
    }
}

/// Request-side handler. Tallies request body bytes; path-level metrics
/// live on [`ResponseHandler`].
pub struct RequestHandler {
    tally: SizeTally,
}

impl callback::RequestHandler for RequestHandler {
    fn on_body_chunk<B: Buf>(&mut self, chunk: &B) {
        self.tally.add(chunk.remaining());
    }
}

/// Response-side handler. Records path-level RPC metrics
/// (`inflight_requests`, `request_latency`, the per-status `requests`
/// counter) labeled by `role`, and tallies response body bytes.
pub struct ResponseHandler {
    metrics: Arc<Metrics>,
    role: Role,
    path: Cow<'static, str>,
    start: Instant,
    // Indicates if we successfully counted the response. In some cases when a request is
    // prematurely canceled this will remain false.
    counted_response: bool,
    tally: SizeTally,
}

impl callback::ResponseHandler for ResponseHandler {
    fn on_response(&mut self, response: &response::Parts) {
        const GRPC_STATUS: http::HeaderName = http::HeaderName::from_static("grpc-status");

        let status = if response
            .headers
            .get(&http::header::CONTENT_TYPE)
            .is_some_and(|content_type| {
                content_type
                    .as_bytes()
                    // check if the content-type starts_with 'application/grpc' in order to
                    // consider this as a gRPC request. A prefix comparison is done instead of a
                    // full equality check in order to account for the various types of
                    // content-types that are considered as gRPC traffic.
                    .starts_with(tonic::metadata::GRPC_CONTENT_TYPE.as_bytes())
            }) {
            let code = response
                .headers
                .get(&GRPC_STATUS)
                .map(http::HeaderValue::as_bytes)
                .map(tonic::Code::from_bytes)
                .unwrap_or(tonic::Code::Ok);

            code_as_str(code)
        } else {
            response.status.as_str()
        };

        self.metrics
            .requests
            .with_label_values(&[self.path.as_ref(), status, self.role.label()])
            .inc();

        self.counted_response = true;
    }

    fn on_service_error<E>(&mut self, _error: &E)
    where
        E: std::fmt::Display + 'static,
    {
        // Only reachable on the client role: axum requires server
        // services to be infallible (Error = Infallible), so no service
        // error can propagate to the server handler. Record under a
        // distinct status so service-level failures are visible and
        // aren't lumped in with canceled requests by the `Drop` fallback.
        self.metrics
            .requests
            .with_label_values(&[self.path.as_ref(), "service-error", self.role.label()])
            .inc();
        self.counted_response = true;
    }

    fn on_body_chunk<B: Buf>(&mut self, chunk: &B) {
        self.tally.add(chunk.remaining());
    }
}

impl Drop for ResponseHandler {
    fn drop(&mut self) {
        let label = self.role.label();

        self.metrics
            .inflight_requests
            .with_label_values(&[self.path.as_ref(), label])
            .dec();

        let latency = self.start.elapsed().as_secs_f64();
        self.metrics
            .request_latency
            .with_label_values(&[self.path.as_ref(), label])
            .observe(latency);

        if !self.counted_response {
            self.metrics
                .requests
                .with_label_values(&[self.path.as_ref(), "canceled", label])
                .inc();
        }
    }
}

fn extract_path(request: &request::Parts, role: Role) -> Cow<'static, str> {
    match role {
        Role::Server => extract_server_path(request),
        Role::Client => extract_client_path(request),
    }
}

fn extract_server_path(request: &request::Parts) -> Cow<'static, str> {
    if let Some(matched_path) = request.extensions.get::<axum::extract::MatchedPath>() {
        if request
            .headers
            .get(&http::header::CONTENT_TYPE)
            .is_some_and(|header| {
                header
                    .as_bytes()
                    // check if the content-type starts_with 'application/grpc' in order to
                    // consider this as a gRPC request. A prefix comparison is done instead of a
                    // full equality check in order to account for the various types of
                    // content-types that are considered as gRPC traffic.
                    .starts_with(tonic::metadata::GRPC_CONTENT_TYPE.as_bytes())
            })
        {
            Cow::Owned(request.uri.path().to_owned())
        } else {
            Cow::Owned(matched_path.as_str().to_owned())
        }
    } else {
        Cow::Borrowed("unknown")
    }
}

/// Build the client-side path label from tonic's [`GrpcMethod`]
/// extension. Tonic-generated clients populate it with the gRPC service
/// and method name before the request reaches our tower stack, giving us
/// a stable label that matches the URI path the server sees. Falls back
/// to the raw URI path for non-tonic callers.
///
/// [`GrpcMethod`]: tonic::GrpcMethod
fn extract_client_path(request: &request::Parts) -> Cow<'static, str> {
    if let Some(method) = request.extensions.get::<tonic::GrpcMethod<'static>>() {
        Cow::Owned(format!("/{}/{}", method.service(), method.method()))
    } else {
        Cow::Owned(request.uri.path().to_owned())
    }
}

fn code_as_str(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "ok",
        tonic::Code::Cancelled => "canceled",
        tonic::Code::Unknown => "unknown",
        tonic::Code::InvalidArgument => "invalid-argument",
        tonic::Code::DeadlineExceeded => "deadline-exceeded",
        tonic::Code::NotFound => "not-found",
        tonic::Code::AlreadyExists => "already-exists",
        tonic::Code::PermissionDenied => "permission-denied",
        tonic::Code::ResourceExhausted => "resource-exhausted",
        tonic::Code::FailedPrecondition => "failed-precondition",
        tonic::Code::Aborted => "aborted",
        tonic::Code::OutOfRange => "out-of-range",
        tonic::Code::Unimplemented => "unimplemented",
        tonic::Code::Internal => "internal",
        tonic::Code::Unavailable => "unavailable",
        tonic::Code::DataLoss => "data-loss",
        tonic::Code::Unauthenticated => "unauthenticated",
    }
}
