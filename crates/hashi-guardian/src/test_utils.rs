// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Shared test helpers for constructing enclaves at various init stages.
//!
//! Gated on `#[cfg(any(test, feature = "test-utils"))]` at the module
//! declaration in `lib.rs`:
//!   - `cargo test -p hashi-guardian` picks these up automatically via
//!     the `test` cfg.
//!   - External crates (e.g. `e2e-tests`) pull in the `test-utils` cargo
//!     feature to get the same helpers over real gRPC without having to
//!     re-roll the mock S3 plumbing.

use crate::enclave::Enclave;
use crate::s3_logger::S3Logger;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;
use hashi_types::guardian::*;
use rand::RngCore;
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

/// Free-function alias exposed for external crates (the test harness in
/// `e2e-tests` wants to construct an operator-init'd enclave without
/// depending on inherent methods on `Enclave`).
pub async fn create_operator_initialized_enclave(args: OperatorInitTestArgs) -> Arc<Enclave> {
    Enclave::create_operator_initialized_with(args).await
}

/// Inputs needed to complete provisioner-init without running the real
/// share crypto. Lets an integration test drive the enclave into a
/// fully-initialized state given a committee + master pubkey that
/// materialized somewhere else (e.g. hashi's on-chain DKG output).
pub struct FullyInitializedArgs {
    pub network: Network,
    pub committee: HashiCommittee,
    /// The hashi MPC BTC master pubkey. In prod this arrives via
    /// `ProvisionerInitState`; the harness reads it from on-chain state.
    pub master_pubkey: BitcoinPubkey,
    pub withdrawal_config: WithdrawalConfig,
    pub limiter_state: LimiterState,
}

/// Construct an enclave that is fully initialized — same end state as
/// running `operator_init` then `THRESHOLD` `provisioner_init` calls,
/// but without the share encryption / decryption round-trip.
///
/// The enclave gets a freshly-generated BTC keypair (the 2-of-2 taproot
/// wiring would normally derive this from combined shares). That is
/// sufficient for rate-limiter-focused integration tests, which do not
/// currently validate the enclave's BTC witness on-chain.
pub async fn create_fully_initialized_enclave(args: FullyInitializedArgs) -> Arc<Enclave> {
    let FullyInitializedArgs {
        network,
        committee,
        master_pubkey,
        withdrawal_config,
        limiter_state,
    } = args;

    let enclave =
        create_operator_initialized_enclave(OperatorInitTestArgs::default().with_network(network))
            .await;

    // Fresh enclave BTC keypair. In the real flow this would come from
    // combined shares; for tests any valid secp256k1 keypair works.
    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk_bytes);
    let enclave_btc_keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&sk_bytes).expect("random bytes form a valid secp256k1 key"),
    );
    enclave
        .config
        .set_btc_keypair(enclave_btc_keypair)
        .expect("fresh enclave should not have a btc keypair set");
    enclave
        .config
        .set_hashi_btc_pk(master_pubkey)
        .expect("fresh enclave should not have a master pubkey set");
    enclave
        .config
        .set_withdrawal_config(withdrawal_config)
        .expect("fresh enclave should not have a withdrawal config set");

    let init_state =
        ProvisionerInitState::new(committee, withdrawal_config, limiter_state, master_pubkey)
            .expect("valid ProvisionerInitState");
    enclave
        .state
        .init(init_state)
        .expect("provisioner state init should succeed on a fresh enclave");

    enclave
        .scratchpad
        .provisioner_init_logging_complete
        .set(())
        .expect("provisioner_init_logging_complete should only be set once");

    assert!(enclave.is_fully_initialized());
    enclave
}
