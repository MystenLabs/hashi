// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::HistogramVec;
use prometheus::Registry;
use prometheus::register_histogram_vec_with_registry;

pub const MPC_LABEL_DKG: &str = "dkg";
pub const MPC_LABEL_KEY_ROTATION: &str = "key_rotation";
pub const MPC_LABEL_NONCE_GENERATION: &str = "nonce_generation";
pub const MPC_LABEL_SIGNING: &str = "signing";

const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1., 2.5, 5., 10., 20., 30., 60., 90.,
];

#[derive(Clone)]
pub struct MpcMetrics {
    pub mpc_dealer_crypto_duration_seconds: HistogramVec,
    pub mpc_p2p_broadcast_duration_seconds: HistogramVec,
    pub mpc_cert_publish_duration_seconds: HistogramVec,
    pub mpc_tob_poll_duration_seconds: HistogramVec,
    pub mpc_cert_verify_duration_seconds: HistogramVec,
    pub mpc_message_process_duration_seconds: HistogramVec,
    pub mpc_message_retrieval_duration_seconds: HistogramVec,
    pub mpc_complaint_recovery_duration_seconds: HistogramVec,
    pub mpc_completion_duration_seconds: HistogramVec,
    pub mpc_rotation_prepare_previous_duration_seconds: HistogramVec,

    pub mpc_sign_partial_gen_duration_seconds: HistogramVec,
    pub mpc_sign_collection_duration_seconds: HistogramVec,
    pub mpc_sign_aggregation_duration_seconds: HistogramVec,

    pub mpc_rpc_handler_process_duration_seconds: HistogramVec,
}

impl MpcMetrics {
    pub fn new_default() -> Self {
        Self::new(prometheus::default_registry())
    }

    pub fn new(registry: &Registry) -> Self {
        Self {
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
            mpc_rotation_prepare_previous_duration_seconds: register_histogram_vec_with_registry!(
                "hashi_mpc_rotation_prepare_previous_duration_seconds",
                "Duration of prepare_previous_output",
                &["protocol"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
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
}
