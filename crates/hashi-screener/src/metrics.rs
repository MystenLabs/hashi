// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use prometheus::IntCounter;
use prometheus::Registry;
use prometheus::register_int_counter_with_registry;

#[derive(Clone)]
pub struct ScreenerMetrics {
    pub requests: IntCounter,
    pub approved_transactions: IntCounter,
    pub rejected_transactions: IntCounter,
    pub validation_errors: IntCounter,
    pub api_errors: IntCounter,
    pub non_mainnet_auto_approvals: IntCounter,
}

impl ScreenerMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            requests: register_int_counter_with_registry!(
                "total_requests",
                "Total number of requests received by the screener service",
                registry
            )
            .unwrap(),
            approved_transactions: register_int_counter_with_registry!(
                "approved_transactions",
                "Total number of approved transactions",
                registry
            )
            .unwrap(),
            rejected_transactions: register_int_counter_with_registry!(
                "rejected_transactions",
                "Total number of rejected transactions",
                registry
            )
            .unwrap(),
            validation_errors: register_int_counter_with_registry!(
                "validation_errors",
                "Total number of requests that failed validation",
                registry
            )
            .unwrap(),
            api_errors: register_int_counter_with_registry!(
                "api_errors",
                "Total number of MerkleScience API errors",
                registry
            )
            .unwrap(),
            non_mainnet_auto_approvals: register_int_counter_with_registry!(
                "non_mainnet_auto_approvals",
                "Total number of requests auto-approved because chain IDs are non-mainnet",
                registry
            )
            .unwrap(),
        }
    }
}
