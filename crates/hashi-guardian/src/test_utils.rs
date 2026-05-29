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

/// Captured `(key, body)` pairs from a `mock_logger_capturing()` logger.
pub type CapturedPuts = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

/// Mock S3 logger that captures every PutObject's (key, body) into the returned
/// Vec. Lets tests assert on what was written. Body is captured via `match_requests`
/// (same Mutex side-channel trick as `mock_logger_with_layout`).
///
/// TODO: retrofit `setup_new_key`, `operator_init`/`provisioner_init`,
/// `withdraw`, and `heartbeat` tests to use this — they currently rely on
/// in-process side effects and the response payload, leaving the on-S3 log
/// shape unverified.
pub fn mock_logger_capturing() -> (S3Logger, CapturedPuts) {
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;

    let captures: CapturedPuts = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captures_w = captures.clone();

    let put_ok = mock!(Client::put_object)
        .match_requests(move |req| {
            let key = req.key().expect("put_object missing key").to_string();
            let body = req
                .body()
                .bytes()
                .expect("body should be in-memory in tests")
                .to_vec();
            captures_w.lock().unwrap().push((key, body));
            true
        })
        .then_output(|| PutObjectOutput::builder().build());
    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
    let logger = S3Logger::from_client_for_tests(S3Config::mock_for_testing(), client);
    (logger, captures)
}

/// Mock S3 logger whose `list_objects_v2(delimiter='/')` and
/// `list_object_versions` responses are computed from an in-memory key set —
/// useful for testing layered prefix tree-walks. PutObject also succeeds.
///
/// The dynamic responses depend on inspecting the request `prefix`; we capture
/// it in a Mutex from `match_requests` and read it in `then_output` (the
/// smithy-mocks API doesn't surface the request inside `then_output`). This
/// is sound under a single-threaded async runtime — each S3 call's predicate
/// runs immediately before its output factory.
pub fn mock_logger_with_layout(keys: impl IntoIterator<Item = String>) -> S3Logger {
    use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsOutput;
    use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Output;
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::types::CommonPrefix;
    use aws_sdk_s3::types::ObjectVersion;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::Mutex;

    let keys: Arc<BTreeSet<String>> = Arc::new(keys.into_iter().collect());

    let v2_prefix: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let v2_prefix_w = v2_prefix.clone();
    let v2_prefix_r = v2_prefix.clone();
    let v2_keys = keys.clone();
    let list_v2 = mock!(Client::list_objects_v2)
        .match_requests(move |req| {
            if req.delimiter() != Some("/") {
                return false;
            }
            *v2_prefix_w.lock().unwrap() = req.prefix().map(|s| s.to_string());
            true
        })
        .then_output(move || {
            let prefix = v2_prefix_r.lock().unwrap().clone().unwrap_or_default();
            let mut children: BTreeSet<String> = BTreeSet::new();
            for key in v2_keys.iter() {
                let Some(rest) = key.strip_prefix(&prefix) else {
                    continue;
                };
                if let Some(slash) = rest.find('/') {
                    let mut child = prefix.clone();
                    child.push_str(&rest[..=slash]);
                    children.insert(child);
                }
            }
            let common_prefixes: Vec<CommonPrefix> = children
                .into_iter()
                .map(|c| CommonPrefix::builder().prefix(c).build())
                .collect();
            ListObjectsV2Output::builder()
                .set_common_prefixes(Some(common_prefixes))
                .build()
        });

    let lv_prefix: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let lv_prefix_w = lv_prefix.clone();
    let lv_prefix_r = lv_prefix.clone();
    let lv_keys = keys.clone();
    let list_versions = mock!(Client::list_object_versions)
        .match_requests(move |req| {
            *lv_prefix_w.lock().unwrap() = req.prefix().map(|s| s.to_string());
            true
        })
        .then_output(move || {
            let prefix = lv_prefix_r.lock().unwrap().clone().unwrap_or_default();
            let versions: Vec<ObjectVersion> = lv_keys
                .iter()
                .filter(|k| k.starts_with(&prefix))
                .map(|k| ObjectVersion::builder().key(k).is_latest(true).build())
                .collect();
            ListObjectVersionsOutput::builder()
                .set_versions(Some(versions))
                .build()
        });

    let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());

    let client = mock_client!(
        aws_sdk_s3,
        RuleMode::MatchAny,
        &[&list_v2, &list_versions, &put_ok]
    );
    S3Logger::from_client_for_tests(S3Config::mock_for_testing(), client)
}

pub struct OperatorInitTestArgs {
    pub network: Network,
    pub secret_sharing_instance: SecretSharingInstance,
    pub s3_logger: S3Logger,
}

const TEST_N: usize = 5;
const TEST_T: usize = 3;

impl Default for OperatorInitTestArgs {
    fn default() -> Self {
        let commitments = (1..=TEST_N)
            .map(|id| ShareCommitment {
                id: std::num::NonZeroU16::new(id as u16).unwrap(),
                digest: vec![],
            })
            .collect();
        let secret_sharing_instance = SecretSharingInstance::new(
            ShareCommitments::new(commitments).unwrap(),
            TEST_N,
            TEST_T,
            0,
        )
        .unwrap();

        Self {
            network: Network::Regtest,
            secret_sharing_instance,
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
        self.secret_sharing_instance =
            SecretSharingInstance::new(commitments, TEST_N, TEST_T, 0).unwrap();
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
        enclave
            .set_secret_sharing_instance(args.secret_sharing_instance)
            .unwrap();
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
    pub master_pubkey: HashiMasterG,
    pub withdrawal_config: WithdrawalConfig,
    pub limiter_state: LimiterState,
}

/// Generate and set a fresh BTC keypair on an operator-init'd enclave.
/// Returns the x-only pubkey so callers can publish it on-chain before
/// the rest of provisioner-init has run (i.e. before DKG completes and
/// `finalize_enclave` can be called). Idempotent: returns the existing
/// pubkey if the keypair has already been set.
pub fn set_or_get_enclave_btc_pubkey(enclave: &Arc<Enclave>) -> GuardianResult<BitcoinPubkey> {
    if let Ok(pk) = enclave.config.enclave_btc_pubkey() {
        return Ok(pk);
    }
    let secp = Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sk_bytes);
    let enclave_btc_keypair = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&sk_bytes).expect("random bytes form a valid secp256k1 key"),
    );
    let pk = enclave_btc_keypair.x_only_public_key().0;
    enclave.config.set_btc_keypair(enclave_btc_keypair)?;
    Ok(pk)
}

/// Drive an operator-initialized enclave to fully-initialized state
/// without running the share-encryption round-trip. The BTC keypair may
/// have been generated up front via [`set_or_get_enclave_btc_pubkey`]
/// (so the on-chain `guardian_btc_public_key` was set at publish time);
/// if not, a fresh one is generated here.
pub fn finalize_enclave(
    enclave: &Arc<Enclave>,
    committee: HashiCommittee,
    master_pubkey: HashiMasterG,
    withdrawal_config: WithdrawalConfig,
    limiter_state: LimiterState,
) -> GuardianResult<()> {
    // Ensure the BTC keypair is set (idempotent — no-op if a caller
    // already generated it before publish).
    let _ = set_or_get_enclave_btc_pubkey(enclave)?;
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

/// Operator-init + finalize in one shot.
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
