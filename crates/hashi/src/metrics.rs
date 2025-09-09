use axum::http;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use prometheus::HistogramVec;
use prometheus::IntCounterVec;
use prometheus::IntGaugeVec;
use prometheus::Registry;
use prometheus::register_histogram_vec_with_registry;
use prometheus::register_int_counter_vec_with_registry;
use prometheus::register_int_gauge_vec_with_registry;
use sui_http::middleware::callback::MakeCallbackHandler;
use sui_http::middleware::callback::ResponseHandler;

#[derive(Clone)]
pub struct Metrics {
    inflight_requests: IntGaugeVec,
    requests: IntCounterVec,
    request_latency: HistogramVec,
}

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10., 20., 30., 60., 90.,
];

impl Metrics {
    pub fn new_default() -> Self {
        Self::new(prometheus::default_registry())
    }

    pub fn new(registry: &Registry) -> Self {
        Self {
            inflight_requests: register_int_gauge_vec_with_registry!(
                "hashi_inflight_requests",
                "Total in-flight RPC requests per route",
                &["path"],
                registry,
            )
            .unwrap(),
            requests: register_int_counter_vec_with_registry!(
                "hashi_requests",
                "Total RPC requests per route and their http status",
                &["path", "status"],
                registry,
            )
            .unwrap(),
            request_latency: register_histogram_vec_with_registry!(
                "hashi_request_latency",
                "Latency of RPC requests per route",
                &["path"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct RpcMetricsMakeCallbackHandler {
    metrics: Arc<Metrics>,
}

impl RpcMetricsMakeCallbackHandler {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

impl MakeCallbackHandler for RpcMetricsMakeCallbackHandler {
    type Handler = RpcMetricsCallbackHandler;

    fn make_handler(&self, request: &http::request::Parts) -> Self::Handler {
        let start = Instant::now();
        let metrics = self.metrics.clone();

        let path =
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
            };

        metrics
            .inflight_requests
            .with_label_values(&[path.as_ref()])
            .inc();

        RpcMetricsCallbackHandler {
            metrics,
            path,
            start,
            counted_response: false,
        }
    }
}

pub struct RpcMetricsCallbackHandler {
    metrics: Arc<Metrics>,
    path: Cow<'static, str>,
    start: Instant,
    // Indicates if we successfully counted the response. In some cases when a request is
    // prematurely canceled this will remain false
    counted_response: bool,
}

impl ResponseHandler for RpcMetricsCallbackHandler {
    fn on_response(&mut self, response: &http::response::Parts) {
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
            .with_label_values(&[self.path.as_ref(), status])
            .inc();

        self.counted_response = true;
    }

    fn on_error<E>(&mut self, _error: &E) {
        // Do nothing if the whole service errored
        //
        // in Axum this isn't possible since all services are required to have an error type of
        // Infallible
    }
}

impl Drop for RpcMetricsCallbackHandler {
    fn drop(&mut self) {
        self.metrics
            .inflight_requests
            .with_label_values(&[self.path.as_ref()])
            .dec();

        let latency = self.start.elapsed().as_secs_f64();
        self.metrics
            .request_latency
            .with_label_values(&[self.path.as_ref()])
            .observe(latency);

        if !self.counted_response {
            self.metrics
                .requests
                .with_label_values(&[self.path.as_ref(), "canceled"])
                .inc();
        }
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

/// Create a metric that measures the uptime from when this metric was constructed.
/// The metric is labeled with:
/// - 'version': binary version, generally be of the format: 'semver-gitrevision'
/// - 'chain_identifier': the identifier of the network which this process is part of
pub fn uptime_metric(
    version: &'static str,
    sui_chain_id: &str,
    bitcoin_chain_id: &str,
) -> Box<dyn prometheus::core::Collector> {
    let opts = prometheus::opts!("uptime", "uptime of the node service in seconds")
        .variable_label("version")
        .variable_label("sui_chain_id")
        .variable_label("bitcoin_chain_id");

    let start_time = std::time::Instant::now();
    let uptime = move || start_time.elapsed().as_secs();
    let metric = prometheus_closure_metric::ClosureMetric::new(
        opts,
        prometheus_closure_metric::ValueType::Counter,
        uptime,
        &[version, sui_chain_id, bitcoin_chain_id],
    )
    .unwrap();

    Box::new(metric)
}

const METRICS_ROUTE: &str = "/metrics";

// Creates a new http server that has as a sole purpose to expose
// an endpoint that prometheus agent can use to poll for the metrics.
pub fn start_prometheus_server(
    addr: std::net::SocketAddr,
    registry: prometheus::Registry,
) -> sui_http::ServerHandle {
    let router = axum::Router::new()
        .route(METRICS_ROUTE, axum::routing::get(metrics))
        .with_state(registry);

    sui_http::Builder::new().serve(addr, router).unwrap()
}

async fn metrics(
    axum::extract::State(registry): axum::extract::State<prometheus::Registry>,
) -> (http::StatusCode, String) {
    let metrics_families = registry.gather();
    match prometheus::TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (http::StatusCode::OK, metrics),
        Err(error) => (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("unable to encode metrics: {error}"),
        ),
    }
}
