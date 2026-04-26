// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

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

#[derive(Clone)]
pub struct Metrics {
    // RPC metrics. Visible to `crate::grpc::metrics_layer`, which owns
    // the tower CallbackLayer handlers that write into them.
    pub(crate) inflight_requests: IntGaugeVec,
    pub(crate) requests: IntCounterVec,
    pub(crate) request_latency: HistogramVec,
    pub(crate) request_size_bytes: HistogramVec,
    pub(crate) response_size_bytes: HistogramVec,
    pub(crate) bytes_sent_total: IntCounterVec,
    pub(crate) bytes_received_total: IntCounterVec,

    // Per-MPC-protocol body-size metrics.
    pub(crate) mpc_request_size_bytes: HistogramVec,
    pub(crate) mpc_response_size_bytes: HistogramVec,
    pub(crate) mpc_bytes_sent_total: IntCounterVec,
    pub(crate) mpc_bytes_received_total: IntCounterVec,

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
    pub kyoto_peers_with_compact_filters: IntGauge,
    pub kyoto_peers_v2: IntGauge,

    // General Sui metrics
    sui_epoch: IntGauge,
    latest_checkpoint_height: IntGauge,
    latest_checkpoint_timestamp_ms: IntGauge,

    // Hashi Onchain state metrics
    epoch: IntGauge,
    reconfig_in_progress: IntGauge,
    paused: IntGauge,
    deposit_queue_size: IntGauge,
    pub deposit_request_confirmations: IntGaugeVec,
    withdrawal_queue_size: IntGaugeVec,
    withdrawal_queue_value: IntGaugeVec,
    utxo_pool_size: IntGaugeVec,
    utxo_pool_value: IntGaugeVec,
    proposals: IntGaugeVec,
    num_consumed_presigs: IntGauge,
    treasury_supply: IntGaugeVec,
    package_version_enabled: IntGaugeVec,

    pub deposits_confirmed_total: IntCounter,
    pub deposits_rejected_utxo_spent: IntCounter,
    pub never_retry_deposit_ids: IntGauge,
    pub withdrawals_finalized_total: IntCounter,
    pub presig_pool_remaining: IntGauge,
    pub sui_tx_submissions_total: IntCounterVec,

    pub is_leader: IntGauge,
    pub leader_retries_total: IntCounterVec,
    pub leader_items_in_backoff: IntGaugeVec,

    pub btc_fee_rate_sat_per_kvb: IntGauge,

    pub mpc_sign_duration_seconds: HistogramVec,
    pub mpc_sign_failures_total: IntCounterVec,

    // MPC profiling metrics
    pub mpc_reconfig_total_duration_seconds: HistogramVec,
    pub mpc_end_reconfig_duration_seconds: HistogramVec,
    pub mpc_prepare_signing_duration_seconds: HistogramVec,
    pub mpc_total_duration_seconds: HistogramVec,
    pub mpc_dealer_crypto_duration_seconds: HistogramVec,
    pub mpc_p2p_broadcast_duration_seconds: HistogramVec,
    pub mpc_cert_publish_duration_seconds: HistogramVec,
    pub mpc_tob_poll_duration_seconds: HistogramVec,
    pub mpc_cert_verify_duration_seconds: HistogramVec,
    pub mpc_message_process_duration_seconds: HistogramVec,
    pub mpc_message_retrieval_duration_seconds: HistogramVec,
    pub mpc_complaint_recovery_duration_seconds: HistogramVec,
    pub mpc_completion_duration_seconds: HistogramVec,
    pub mpc_presig_conversion_duration_seconds: HistogramVec,
    pub mpc_rotation_prepare_previous_duration_seconds: HistogramVec,
    pub mpc_sign_partial_gen_duration_seconds: HistogramVec,
    pub mpc_sign_collection_duration_seconds: HistogramVec,
    pub mpc_sign_aggregation_duration_seconds: HistogramVec,
    pub mpc_rpc_handler_process_duration_seconds: HistogramVec,
}

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10., 20., 30., 60., 90.,
];

const MPC_SIGN_DURATION_BUCKETS: &[f64] = &[0.1, 0.25, 0.5, 1., 1.5, 2., 2.5, 3., 4., 5., 7.5, 10.];

pub const MPC_LABEL_DKG: &str = "dkg";
pub const MPC_LABEL_KEY_ROTATION: &str = "key_rotation";
pub const MPC_LABEL_NONCE_GENERATION: &str = "nonce_generation";
pub const MPC_LABEL_SIGNING: &str = "signing";

pub const CONFIRMATION_STATUS_LABELS: &[&str] = &[
    "not_found",
    "mempool",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6_plus",
];

// Body-size buckets spanning 256 B through 32 MiB. Powers of four keep
// the bucket count modest while still resolving small and large
// payloads.
const MESSAGE_SIZE_BYTES_BUCKETS: &[f64] = &[
    256.,
    1_024.,
    4_096.,
    16_384.,
    65_536.,
    262_144.,
    1_048_576.,
    4_194_304.,
    16_777_216.,
    33_554_432.,
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
                &["path", "role"],
                registry,
            )
            .unwrap(),
            requests: register_int_counter_vec_with_registry!(
                "hashi_requests",
                "Total RPC requests per route and their http status",
                &["path", "status", "role"],
                registry,
            )
            .unwrap(),
            request_latency: register_histogram_vec_with_registry!(
                "hashi_request_latency",
                "Latency of RPC requests per route",
                &["path", "role"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            request_size_bytes: register_histogram_vec_with_registry!(
                "hashi_request_size_bytes",
                "Size of RPC request bodies in bytes, per route",
                &["path", "role"],
                MESSAGE_SIZE_BYTES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            response_size_bytes: register_histogram_vec_with_registry!(
                "hashi_response_size_bytes",
                "Size of RPC response bodies in bytes, per route",
                &["path", "role"],
                MESSAGE_SIZE_BYTES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            bytes_sent_total: register_int_counter_vec_with_registry!(
                "hashi_bytes_sent_total",
                "Total bytes sent from this node over HTTP/gRPC bodies, per route",
                &["path", "role"],
                registry,
            )
            .unwrap(),
            bytes_received_total: register_int_counter_vec_with_registry!(
                "hashi_bytes_received_total",
                "Total bytes received by this node over HTTP/gRPC bodies, per route",
                &["path", "role"],
                registry,
            )
            .unwrap(),
            mpc_request_size_bytes: register_histogram_vec_with_registry!(
                "hashi_mpc_request_size_bytes",
                "Size of MPC RPC request bodies in bytes, labeled by MPC protocol",
                &["protocol"],
                MESSAGE_SIZE_BYTES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_response_size_bytes: register_histogram_vec_with_registry!(
                "hashi_mpc_response_size_bytes",
                "Size of MPC RPC response bodies in bytes, labeled by MPC protocol",
                &["protocol"],
                MESSAGE_SIZE_BYTES_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_bytes_sent_total: register_int_counter_vec_with_registry!(
                "hashi_mpc_bytes_sent_total",
                "Total bytes sent in MPC RPC bodies, labeled by MPC protocol",
                &["protocol"],
                registry,
            )
            .unwrap(),
            mpc_bytes_received_total: register_int_counter_vec_with_registry!(
                "hashi_mpc_bytes_received_total",
                "Total bytes received in MPC RPC bodies, labeled by MPC protocol",
                &["protocol"],
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
            kyoto_peers_with_compact_filters: register_int_gauge_with_registry!(
                "hashi_kyoto_peers_with_compact_filters",
                "Number of currently connected peers advertising NODE_COMPACT_FILTERS. \
                 If this drops to 0, kyoto cannot make filter sync progress even when \
                 connection counts look healthy.",
                registry,
            )
            .unwrap(),
            kyoto_peers_v2: register_int_gauge_with_registry!(
                "hashi_kyoto_peers_v2",
                "Number of currently connected peers negotiated to BIP-324 (P2P V2) transport.",
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
            deposit_request_confirmations: register_int_gauge_vec_with_registry!(
                "hashi_deposit_request_confirmations",
                "Pending deposit requests bucketed by their transaction status (and block confirmations) on Bitcoin. \
                 The `status` label is one of: not_found, mempool, 0, 1, 2, 3, 4, 5, 6_plus.",
                &["status"],
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
            utxo_pool_size: register_int_gauge_vec_with_registry!(
                "hashi_utxo_pool_size",
                "number of UTXOs in the pool by status",
                &["status"],
                registry,
            )
            .unwrap(),
            utxo_pool_value: register_int_gauge_vec_with_registry!(
                "hashi_utxo_pool_value",
                "value of UTXOs in the pool in satoshis by status",
                &["status"],
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
            deposits_rejected_utxo_spent: register_int_counter_with_registry!(
                "hashi_deposits_rejected_utxo_spent_total",
                "Deposit requests rejected because the UTXO was already spent",
                registry,
            )
            .unwrap(),
            never_retry_deposit_ids: register_int_gauge_with_registry!(
                "hashi_never_retry_deposit_ids",
                "Number of deposit requests currently marked as never retry by the leader",
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

            // MPC profiling: reconfig-level
            mpc_reconfig_total_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_reconfig_total_duration_seconds",
                "Duration of full handle_reconfig",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_end_reconfig_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_end_reconfig_duration_seconds",
                "Duration of submit_end_reconfig",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_prepare_signing_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_prepare_signing_duration_seconds",
                "Duration of prepare_signing",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),

            // MPC profiling: per-phase (labeled by protocol)
            mpc_total_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_total_duration_seconds",
                "End-to-end duration of MPC protocol",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_dealer_crypto_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_dealer_crypto_duration_seconds",
                "Duration of dealer crypto",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_p2p_broadcast_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_p2p_broadcast_duration_seconds",
                "Duration of send_to_many",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_cert_publish_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_cert_publish_duration_seconds",
                "Duration of tob_channel.publish",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_tob_poll_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_tob_poll_duration_seconds",
                "Duration of tob_channel.receive",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_cert_verify_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_cert_verify_duration_seconds",
                "Duration of BLS certificate signature verification",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_message_process_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_message_process_duration_seconds",
                "Duration of AVSS message processing",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_message_retrieval_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_message_retrieval_duration_seconds",
                "Duration of retrieve_dealer_message",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_complaint_recovery_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_complaint_recovery_duration_seconds",
                "Duration of complaint recovery",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_completion_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_completion_duration_seconds",
                "Duration of final aggregation",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_presig_conversion_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_presig_conversion_duration_seconds",
                "Duration of Presignatures::new",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_rotation_prepare_previous_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_rotation_prepare_previous_duration_seconds",
                "Duration of prepare_previous_output",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),

            // MPC profiling: signing phase breakdown
            mpc_sign_partial_gen_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_sign_partial_gen_duration_seconds",
                "Duration of generate_partial_signatures",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_sign_collection_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_sign_collection_duration_seconds",
                "Duration of P2P partial signature collection from peers",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            mpc_sign_aggregation_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_sign_aggregation_duration_seconds",
                "Duration of aggregate_signatures / RS recovery",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),

            // MPC profiling: RPC handler
            mpc_rpc_handler_process_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_rpc_handler_process_duration_seconds",
                "Duration of process_message in RPC handler",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
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
            .partition::<Vec<_>, _>(|r| r.status.is_requested());
        let (signed, pending): (Vec<_>, Vec<_>) = hashi
            .withdrawal_queue
            .withdrawal_txns()
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
                    .flat_map(|w| &w.withdrawal_outputs)
                    .map(|o| o.amount)
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
                    .flat_map(|w| &w.withdrawal_outputs)
                    .map(|o| o.amount)
                    .sum::<u64>() as i64,
            );
        // Track three views of utxo_records:
        // - available:         all selectable UTXOs (locked_by = None), whether
        //                      confirmed or not; this is the coin-selection pool
        // - unconfirmed_change: subset of available whose producing withdrawal
        //                      has not yet confirmed on Bitcoin (produced_by =
        //                      Some); useful for gauging mempool chain depth
        // - locked:            committed to a pending withdrawal, awaiting
        //                      Bitcoin confirmation (locked_by = Some)
        let mut available_count = 0i64;
        let mut unconfirmed_change_count = 0i64;
        let mut locked_count = 0i64;
        let mut available_value = 0u64;
        let mut unconfirmed_change_value = 0u64;
        let mut locked_value = 0u64;
        for record in hashi.utxo_pool.utxo_records().values() {
            if record.locked_by.is_some() {
                locked_count += 1;
                locked_value += record.utxo.amount;
            } else {
                available_count += 1;
                available_value += record.utxo.amount;
                if record.produced_by.is_some() {
                    unconfirmed_change_count += 1;
                    unconfirmed_change_value += record.utxo.amount;
                }
            }
        }
        self.utxo_pool_size
            .with_label_values(&["available"])
            .set(available_count);
        self.utxo_pool_size
            .with_label_values(&["unconfirmed_change"])
            .set(unconfirmed_change_count);
        self.utxo_pool_size
            .with_label_values(&["locked"])
            .set(locked_count);
        self.utxo_pool_value
            .with_label_values(&["available"])
            .set(available_value as i64);
        self.utxo_pool_value
            .with_label_values(&["unconfirmed_change"])
            .set(unconfirmed_change_value as i64);
        self.utxo_pool_value
            .with_label_values(&["locked"])
            .set(locked_value as i64);
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
            .set(hashi.num_consumed_presigs as i64);
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
