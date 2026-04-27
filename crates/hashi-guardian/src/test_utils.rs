// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing enclaves at various init stages.

use crate::enclave::Enclave;
use crate::s3_logger::S3Logger;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;
use hashi_types::guardian::*;
use rand::RngCore;
use std::sync::Arc;

/// Mock S3 logger that returns success for every PutObject call.
pub fn mock_logger() -> S3Logger {
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;

    let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
    S3Logger::from_client_for_tests(S3Config::mock_for_testing(), client)
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
        enclave.config.set_s3_logger(args.s3_logger).unwrap();
        enclave.config.set_bitcoin_network(args.network).unwrap();
        enclave.set_share_commitments(args.commitments).unwrap();
        enclave
            .scratchpad
            .operator_init_logging_complete
            .set(())
            .expect("operator_init_logging_complete should only be set once");

        assert!(enclave.is_operator_init_complete() && !enclave.is_provisioner_init_complete());
        enclave
    }
}

pub async fn create_operator_initialized_enclave(args: OperatorInitTestArgs) -> Arc<Enclave> {
    Enclave::create_operator_initialized_with(args).await
}

pub struct FullyInitializedArgs {
    pub network: Network,
    pub committee: HashiCommittee,
    pub master_pubkey: BitcoinPubkey,
    pub withdrawal_config: WithdrawalConfig,
    pub limiter_state: LimiterState,
}

/// Drive an already operator-initialized enclave to fully-initialized state,
/// skipping the real share-encryption round-trip. Generates a fresh random
/// BTC keypair internally.
///
/// Used by [`create_fully_initialized_enclave`] and by the `e2e-tests`
/// `GuardianHarness` when DKG output becomes available on chain.
pub fn finalize_enclave(
    enclave: &Arc<Enclave>,
    committee: HashiCommittee,
    master_pubkey: BitcoinPubkey,
    withdrawal_config: WithdrawalConfig,
    limiter_state: LimiterState,
) -> GuardianResult<()> {
    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk_bytes);
    let enclave_btc_keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&sk_bytes).expect("random bytes form a valid secp256k1 key"),
    );
    enclave.config.set_btc_keypair(enclave_btc_keypair)?;
    enclave.config.set_hashi_btc_pk(master_pubkey)?;
    enclave.config.set_withdrawal_config(withdrawal_config)?;

    let init_state =
        ProvisionerInitState::new(committee, withdrawal_config, limiter_state, master_pubkey)?;
    enclave.state.init(init_state)?;

    enclave
        .scratchpad
        .provisioner_init_logging_complete
        .set(())
        .map_err(|_| {
            GuardianError::InvalidInputs("provisioner_init_logging_complete already set".into())
        })?;
    Ok(())
}

/// Construct an operator-initialized enclave and drive it to fully-initialized
/// state in one shot. Convenience for unit tests that don't need the
/// intermediate "operator-init only" stage.
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

    finalize_enclave(
        &enclave,
        committee,
        master_pubkey,
        withdrawal_config,
        limiter_state,
    )
    .expect("finalize_enclave should succeed on a fresh enclave");

    assert!(enclave.is_fully_initialized());
    enclave
}
