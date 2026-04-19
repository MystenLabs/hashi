// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for constructing enclaves at various init stages.
//!
//! Commit 1 keeps these gated on `#[cfg(test)]` so the internal unit tests
//! keep working after the refactor. Commit 2 widens the gate to
//! `#[cfg(any(test, feature = "test-utils"))]` so external crates
//! (integration tests, harnesses) can reuse the same helpers.

use crate::enclave::Enclave;
use crate::s3_logger::S3Logger;
use bitcoin::Network;
use hashi_types::guardian::*;
use std::sync::Arc;

/// Mock S3 logger for use in API calls post operator_init,
/// e.g., provisioner_init, withdrawals.
pub fn mock_logger() -> S3Logger {
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;

    // For unit tests we only need PutObject to succeed, because `sign_and_log()` calls `S3Logger::write()`.
    // The `then_output` helper creates a "simple" rule that repeats indefinitely.
    let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());

    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);

    let config = S3Config::mock_for_testing();

    S3Logger::from_client_for_tests(config, client)
}

pub struct OperatorInitTestArgs {
    pub network: Network,
    pub commitments: ShareCommitments,
    pub s3_logger: S3Logger,
}

impl Default for OperatorInitTestArgs {
    fn default() -> Self {
        let commitments = (1..=NUM_OF_SHARES)
            .map(|id| ShareCommitment {
                id: std::num::NonZeroU16::new(id as u16).unwrap(),
                digest: vec![],
            })
            .collect();

        Self {
            network: Network::Regtest,
            commitments: ShareCommitments::new(commitments).unwrap(),
            s3_logger: mock_logger(),
        }
    }
}

impl OperatorInitTestArgs {
    pub fn with_network(mut self, network: Network) -> Self {
        self.network = network;
        self
    }

    pub fn with_commitments(mut self, commitments: ShareCommitments) -> Self {
        self.commitments = commitments;
        self
    }

    pub fn with_s3_logger(mut self, s3_logger: S3Logger) -> Self {
        self.s3_logger = s3_logger;
        self
    }
}

impl Enclave {
    pub fn create_with_random_keys() -> Arc<Self> {
        let signing_keys = GuardianSignKeyPair::new(rand::thread_rng());
        let encryption_keys = GuardianEncKeyPair::random(&mut rand::thread_rng());
        Arc::new(Enclave::new(signing_keys, encryption_keys))
    }

    /// Create an enclave post operator_init() but pre provisioner_init().
    pub async fn create_operator_initialized() -> Arc<Self> {
        Self::create_operator_initialized_with(OperatorInitTestArgs::default()).await
    }

    pub async fn create_operator_initialized_with(args: OperatorInitTestArgs) -> Arc<Self> {
        let enclave = Self::create_with_random_keys();

        // Initialize S3 logger
        enclave.config.set_s3_logger(args.s3_logger).unwrap();

        // Set bitcoin network
        enclave.config.set_bitcoin_network(args.network).unwrap();

        // Set share commitments
        enclave.set_share_commitments(args.commitments).unwrap();

        // In tests, treat "operator initialized" as including the operator-init identity logs.
        enclave
            .scratchpad
            .operator_init_logging_complete
            .set(())
            .expect("operator_init_logging_complete should only be set once");

        assert!(enclave.is_operator_init_complete() && !enclave.is_provisioner_init_complete());

        enclave
    }
}
