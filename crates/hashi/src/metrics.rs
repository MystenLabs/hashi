use axum::http;
use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use prometheus::HistogramVec;
use prometheus::IntCounter;
use prometheus::IntCounterVec;
use prometheus::IntGauge;
use prometheus::IntGaugeVec;
use prometheus::Registry;
use prometheus::register_histogram_vec_with_registry;
use prometheus::register_int_counter_vec_with_registry;
use prometheus::register_int_counter_with_registry;
use prometheus::register_int_gauge_vec_with_registry;
use prometheus::register_int_gauge_with_registry;
use sui_http::middleware::callback::MakeCallbackHandler;
use sui_http::middleware::callback::ResponseHandler;

#[derive(Clone)]
pub struct Metrics {
    // RPC metrics
    inflight_requests: IntGaugeVec,
    requests: IntCounterVec,
    request_latency: HistogramVec,

    pub screener_enabled: IntGauge,

    // Kyoto (Bitcoin light client) metrics
    pub kyoto_connected_peers: IntGauge,
    pub kyoto_synced: IntGauge,
    pub kyoto_best_height: IntGauge,
    pub kyoto_warnings: IntCounterVec,
    pub kyoto_restarts: IntCounter,
    pub kyoto_blocks_received: IntCounter,
    pub kyoto_reorgs: IntCounter,
    pub kyoto_consecutive_failures: IntGauge,
    pub kyoto_sync_percent: IntGauge,

    // General Sui metrics
    sui_epoch: IntGauge,
    latest_checkpoint_height: IntGauge,
    latest_checkpoint_timestamp_ms: IntGauge,

    // Hashi Onchain state metrics
    epoch: IntGauge,
    reconfig_in_progress: IntGauge,
    paused: IntGauge,
    deposit_queue_size: IntGauge,
    withdrawal_queue_size: IntGaugeVec,
    withdrawal_queue_value: IntGaugeVec,
    utxo_pool_size: IntGauge,
    utxo_pool_value: IntGauge,
    proposals: IntGaugeVec,
    num_consumed_presigs: IntGauge,
    treasury_supply: IntGaugeVec,
    package_version_enabled: IntGaugeVec,

    pub deposits_confirmed_total: IntCounter,
    pub withdrawals_finalized_total: IntCounter,
    pub presig_pool_remaining: IntGauge,
    pub sui_tx_submissions_total: IntCounterVec,

    pub is_leader: IntGauge,
    pub leader_retries_total: IntCounterVec,
    pub leader_items_in_backoff: IntGaugeVec,

    pub btc_fee_rate_sat_per_kvb: IntGauge,

    pub mpc_sign_duration_seconds: HistogramVec,
    pub mpc_sign_failures_total: IntCounterVec,
}

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10., 20., 30., 60., 90.,
];

const MPC_SIGN_DURATION_BUCKETS: &[f64] = &[0.1, 0.25, 0.5, 1., 1.5, 2., 2.5, 3., 4., 5., 7.5, 10.];

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
            screener_enabled: register_int_gauge_with_registry!(
                "hashi_screener_enabled",
                "Whether AML screening is enabled (1) or disabled (0)",
                registry,
            )
            .unwrap(),

            // Kyoto metrics
            kyoto_connected_peers: register_int_gauge_with_registry!(
                "hashi_kyoto_connected_peers",
                "Number of currently connected Bitcoin P2P peers",
                registry,
            )
            .unwrap(),
            kyoto_synced: register_int_gauge_with_registry!(
                "hashi_kyoto_synced",
                "Whether the Kyoto light client is fully synced (1) or not (0)",
                registry,
            )
            .unwrap(),
            kyoto_best_height: register_int_gauge_with_registry!(
                "hashi_kyoto_best_height",
                "Best known Bitcoin block height from the Kyoto light client",
                registry,
            )
            .unwrap(),
            kyoto_warnings: register_int_counter_vec_with_registry!(
                "hashi_kyoto_warnings_total",
                "Total Kyoto warnings by type",
                &["type"],
                registry,
            )
            .unwrap(),
            kyoto_restarts: register_int_counter_with_registry!(
                "hashi_kyoto_restarts_total",
                "Total number of Kyoto node restarts due to connectivity loss",
                registry,
            )
            .unwrap(),
            kyoto_blocks_received: register_int_counter_with_registry!(
                "hashi_kyoto_blocks_received_total",
                "Total number of Bitcoin blocks received by the Kyoto light client",
                registry,
            )
            .unwrap(),
            kyoto_reorgs: register_int_counter_with_registry!(
                "hashi_kyoto_reorgs_total",
                "Total number of Bitcoin chain reorganizations observed",
                registry,
            )
            .unwrap(),
            kyoto_consecutive_failures: register_int_gauge_with_registry!(
                "hashi_kyoto_consecutive_failures",
                "Current number of consecutive peer connection failures",
                registry,
            )
            .unwrap(),
            kyoto_sync_percent: register_int_gauge_with_registry!(
                "hashi_kyoto_sync_percent",
                "Compact block filter sync progress (0-100)",
                registry,
            )
            .unwrap(),

            epoch: register_int_gauge_with_registry!(
                "hashi_epoch",
                "current hashi epoch",
                registry,
            )
            .unwrap(),
            sui_epoch: register_int_gauge_with_registry!(
                "hashi_sui_epoch",
                "current sui epoch from latest checkpoint",
                registry,
            )
            .unwrap(),
            reconfig_in_progress: register_int_gauge_with_registry!(
                "hashi_reconfig_in_progress",
                "whether a reconfiguration is in progress (1) or not (0)",
                registry,
            )
            .unwrap(),
            paused: register_int_gauge_with_registry!(
                "hashi_paused",
                "whether the system is paused (1) or not (0)",
                registry,
            )
            .unwrap(),
            latest_checkpoint_height: register_int_gauge_with_registry!(
                "hashi_latest_checkpoint_height",
                "latest processed sui checkpoint height",
                registry,
            )
            .unwrap(),
            latest_checkpoint_timestamp_ms: register_int_gauge_with_registry!(
                "hashi_latest_checkpoint_timestamp_ms",
                "timestamp of latest processed checkpoint in ms",
                registry,
            )
            .unwrap(),
            deposit_queue_size: register_int_gauge_with_registry!(
                "hashi_deposit_queue_size",
                "number of pending deposit requests",
                registry,
            )
            .unwrap(),
            withdrawal_queue_size: register_int_gauge_vec_with_registry!(
                "hashi_withdrawal_queue_size",
                "number of withdrawal requests by status",
                &["status"],
                registry,
            )
            .unwrap(),
            withdrawal_queue_value: register_int_gauge_vec_with_registry!(
                "hashi_withdrawal_queue_value",
                "total value of withdrawal requests by status and coin type in satoshis",
                &["status", "coin_type"],
                registry,
            )
            .unwrap(),
            utxo_pool_size: register_int_gauge_with_registry!(
                "hashi_utxo_pool_size",
                "number of active utxos",
                registry,
            )
            .unwrap(),
            utxo_pool_value: register_int_gauge_with_registry!(
                "hashi_utxo_pool_value",
                "total value of active utxos in satoshis",
                registry,
            )
            .unwrap(),
            proposals: register_int_gauge_vec_with_registry!(
                "hashi_proposals",
                "number of active proposals by type",
                &["type"],
                registry,
            )
            .unwrap(),
            num_consumed_presigs: register_int_gauge_with_registry!(
                "hashi_num_consumed_presigs",
                "number of consumed presignatures",
                registry,
            )
            .unwrap(),
            treasury_supply: register_int_gauge_vec_with_registry!(
                "hashi_treasury_supply",
                "supply of each treasury cap by coin type",
                &["coin_type"],
                registry,
            )
            .unwrap(),
            package_version_enabled: register_int_gauge_vec_with_registry!(
                "hashi_package_version_enabled",
                "enabled package versions (1 = enabled)",
                &["version", "package_id"],
                registry,
            )
            .unwrap(),
            deposits_confirmed_total: register_int_counter_with_registry!(
                "hashi_deposits_confirmed_total",
                "Total number of deposits successfully confirmed on Sui",
                registry,
            )
            .unwrap(),
            withdrawals_finalized_total: register_int_counter_with_registry!(
                "hashi_withdrawals_finalized_total",
                "Total number of withdrawals successfully finalized on Sui",
                registry,
            )
            .unwrap(),
            presig_pool_remaining: register_int_gauge_with_registry!(
                "hashi_presig_pool_remaining",
                "Number of presignatures remaining in the local MPC signing pool",
                registry,
            )
            .unwrap(),
            sui_tx_submissions_total: register_int_counter_vec_with_registry!(
                "hashi_sui_tx_submissions_total",
                "Total Sui transaction submissions by operation and outcome",
                &["operation", "status"],
                registry,
            )
            .unwrap(),
            is_leader: register_int_gauge_with_registry!(
                "hashi_is_leader",
                "Whether this node is the current leader (1) or not (0)",
                registry,
            )
            .unwrap(),
            leader_retries_total: register_int_counter_vec_with_registry!(
                "hashi_leader_retries_total",
                "Total leader retry attempts by operation and error kind",
                &["operation", "error_kind"],
                registry,
            )
            .unwrap(),
            leader_items_in_backoff: register_int_gauge_vec_with_registry!(
                "hashi_leader_items_in_backoff",
                "Number of requests currently in retry backoff by operation",
                &["operation"],
                registry,
            )
            .unwrap(),
            btc_fee_rate_sat_per_kvb: register_int_gauge_with_registry!(
                "hashi_btc_fee_rate_sat_per_kvb",
                "Current estimated Bitcoin fee rate in sat/kvB used for withdrawals",
                registry,
            )
            .unwrap(),
            mpc_sign_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_sign_duration_seconds",
                "Duration of MPC signing operations",
                &["outcome"],
                MPC_SIGN_DURATION_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_sign_failures_total: register_int_counter_vec_with_registry!(
                "hashi_mpc_sign_failures_total",
                "Total MPC signing failures by reason",
                &["reason"],
                registry,
            )
            .unwrap(),
        }
    }

    pub fn update_onchain_state(&self, state: &crate::onchain::OnchainState) {
        self.latest_checkpoint_height
            .set(state.latest_checkpoint_height() as i64);
        self.latest_checkpoint_timestamp_ms
            .set(state.latest_checkpoint_timestamp_ms() as i64);
        self.sui_epoch.set(state.latest_checkpoint_epoch() as i64);

        let guard = state.state();
        let hashi = guard.hashi();

        self.epoch.set(hashi.committees.epoch() as i64);
        self.reconfig_in_progress
            .set(if hashi.committees.pending_epoch_change().is_some() {
                1
            } else {
                0
            });
        self.paused.set(if hashi.config.paused() { 1 } else { 0 });
        self.deposit_queue_size
            .set(hashi.deposit_queue.requests().len() as i64);
        let (requested, approved) = hashi
            .withdrawal_queue
            .requests()
            .values()
            .partition::<Vec<_>, _>(|r| !r.approved);
        let (signed, pending): (Vec<_>, Vec<_>) = hashi
            .withdrawal_queue
            .pending_withdrawals()
            .values()
            .partition(|w| w.signatures.is_some());
        self.withdrawal_queue_size
            .with_label_values(&["requested"])
            .set(requested.len() as i64);
        self.withdrawal_queue_value
            .with_label_values(&["requested", "BTC"])
            .set(requested.iter().map(|r| r.btc_amount).sum::<u64>() as i64);
        self.withdrawal_queue_size
            .with_label_values(&["approved"])
            .set(approved.len() as i64);
        self.withdrawal_queue_value
            .with_label_values(&["approved", "BTC"])
            .set(approved.iter().map(|r| r.btc_amount).sum::<u64>() as i64);
        self.withdrawal_queue_size
            .with_label_values(&["pending"])
            .set(pending.len() as i64);
        self.withdrawal_queue_value
            .with_label_values(&["pending", "BTC"])
            .set(
                pending
                    .iter()
                    .flat_map(|w| &w.requests)
                    .map(|r| r.btc_amount)
                    .sum::<u64>() as i64,
            );
        self.withdrawal_queue_size
            .with_label_values(&["signed"])
            .set(signed.len() as i64);
        self.withdrawal_queue_value
            .with_label_values(&["signed", "BTC"])
            .set(
                signed
                    .iter()
                    .flat_map(|w| &w.requests)
                    .map(|r| r.btc_amount)
                    .sum::<u64>() as i64,
            );
        let active_utxos = hashi.utxo_pool.active_utxos();
        self.utxo_pool_size.set(active_utxos.len() as i64);
        self.utxo_pool_value
            .set(active_utxos.values().map(|u| u.amount).sum::<u64>() as i64);
        {
            use crate::onchain::types::ProposalType;
            let mut counts = std::collections::HashMap::<&str, i64>::new();
            for proposal in hashi.proposals.proposals().values() {
                *counts.entry(proposal.proposal_type.as_str()).or_default() += 1;
            }
            for label in ProposalType::all_labels() {
                self.proposals
                    .with_label_values(&[label])
                    .set(*counts.get(label).unwrap_or(&0));
            }
        }
        self.num_consumed_presigs
            .set(hashi.withdrawal_queue.num_consumed_presigs() as i64);
        for (type_tag, cap) in &hashi.treasury.treasury_caps {
            if let sui_sdk_types::TypeTag::Struct(struct_tag) = type_tag {
                self.treasury_supply
                    .with_label_values(&[struct_tag.name().as_str()])
                    .set(cap.supply as i64);
            }
        }

        self.package_version_enabled.reset();
        for version in &hashi.config.enabled_versions {
            let version_str = version.to_string();
            let package_id_str = guard
                .package_versions()
                .get(version)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            self.package_version_enabled
                .with_label_values(&[&version_str, &package_id_str])
                .set(1);
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
    package_id: &str,
    hashi_object_id: &str,
) -> Box<dyn prometheus::core::Collector> {
    let opts = prometheus::opts!("uptime", "uptime of the node service in seconds")
        .variable_label("version")
        .variable_label("sui_chain_id")
        .variable_label("bitcoin_chain_id")
        .variable_label("package_id")
        .variable_label("hashi_object_id");

    let start_time = std::time::Instant::now();
    let uptime = move || start_time.elapsed().as_secs();
    let metric = prometheus_closure_metric::ClosureMetric::new(
        opts,
        prometheus_closure_metric::ValueType::Counter,
        uptime,
        &[
            version,
            sui_chain_id,
            bitcoin_chain_id,
            package_id,
            hashi_object_id,
        ],
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
