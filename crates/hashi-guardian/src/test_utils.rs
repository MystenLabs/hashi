// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for constructing enclaves at various init stages.

use crate::enclave::Enclave;
use crate::s3_client::GuardianS3Client;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Network;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::guardian::*;
use rand::RngCore;
use std::num::NonZeroU16;
use std::sync::Arc;

/// Mock S3 logger that returns success for every PutObject call.
pub fn mock_logger() -> GuardianS3Client {
    use aws_sdk_s3::operation::put_object::PutObjectOutput;
    use aws_sdk_s3::Client;
    use aws_smithy_mocks::mock;
    use aws_smithy_mocks::mock_client;
    use aws_smithy_mocks::RuleMode;
    use hashi_types::guardian::S3Config;

    let put_ok = mock!(Client::put_object).then_output(|| PutObjectOutput::builder().build());
    let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&put_ok]);
    GuardianS3Client::from_client_for_tests(S3Config::mock_for_testing(), client)
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
pub fn mock_logger_capturing() -> (GuardianS3Client, CapturedPuts) {
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
    let logger = GuardianS3Client::from_client_for_tests(S3Config::mock_for_testing(), client);
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
pub fn mock_logger_with_layout(keys: impl IntoIterator<Item = String>) -> GuardianS3Client {
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
    GuardianS3Client::from_client_for_tests(S3Config::mock_for_testing(), client)
}

/// Args for arming a withdraw-mode test enclave. `config` is the stable
/// operator-init config; `ceremony_state` mirrors the snapshot that production
/// `operator_init` reads from S3.
pub struct OperatorInitTestArgs {
    pub s3_logger: GuardianS3Client,
    pub config: InitConfig,
    pub ceremony_state: CeremonyState,
    pub genesis_state: Option<GenesisState>,
}

const TEST_N: usize = 5;
const TEST_T: usize = 3;

fn dummy_secret_sharing_instance() -> SecretSharingInstance {
    let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let shares = crypto::split_secret(&sk, &params, &mut rand::thread_rng());
    let commitments = ShareCommitments::from_shares(&shares).unwrap();
    SecretSharingInstance::new(commitments, TEST_N, TEST_T, 0).unwrap()
}

fn dummy_kp_encrypted_shares() -> KPEncryptedSharesRoster {
    KPEncryptedSharesRoster::new(
        (1..=TEST_N)
            .map(|i| KPEncryptedShares {
                id: NonZeroU16::new(i as u16).unwrap(),
                ciphertexts_by_fingerprint: [(format!("DUMMY FINGERPRINT {i}"), "dummy".into())]
                    .into_iter()
                    .collect(),
            })
            .collect(),
    )
    .unwrap()
}

fn dummy_ceremony_state() -> CeremonyState {
    CeremonyState {
        secret_sharing_instance: dummy_secret_sharing_instance(),
        btc_master_pubkey: crypto::k256_sk_to_btc_xonly_pubkey(
            &k256::SecretKey::from_slice(&[7u8; 32]).unwrap(),
        ),
        cert_seq: 0,
        encrypted_shares: dummy_kp_encrypted_shares(),
    }
}

impl Default for OperatorInitTestArgs {
    fn default() -> Self {
        Self {
            s3_logger: mock_logger(),
            config: InitConfig::mock_for_testing(None),
            ceremony_state: dummy_ceremony_state(),
            genesis_state: None,
        }
    }
}

impl OperatorInitTestArgs {
    pub fn with_genesis_state(mut self, genesis_state: GenesisState) -> Self {
        self.genesis_state = Some(genesis_state);
        self
    }

    pub fn with_config(mut self, config: InitConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the ceremony snapshot to a different secret-sharing instance.
    pub fn with_commitments(mut self, commitments: ShareCommitments) -> Self {
        self.ceremony_state.secret_sharing_instance =
            SecretSharingInstance::new(commitments, TEST_N, TEST_T, 0).unwrap();
        self
    }

    pub fn with_s3_logger(mut self, s3_logger: GuardianS3Client) -> Self {
        self.s3_logger = s3_logger;
        self
    }

    pub fn with_kp_encrypted_shares(mut self, shares: KPEncryptedSharesRoster) -> Self {
        self.ceremony_state.encrypted_shares = shares;
        self
    }
}

impl Enclave {
    /// Enclave in the requested mode with fresh random keys.
    pub fn create_with_random_keys_for_mode(mode: EnclaveMode) -> Arc<Self> {
        let signing_keys = GuardianSignKeyPair::new(rand::thread_rng());
        let encryption_keys = GuardianEncKeyPair::random(&mut rand::thread_rng());
        Arc::new(Enclave::new(signing_keys, encryption_keys, mode))
    }

    /// Withdraw-mode enclave with fresh random keys.
    pub fn create_with_random_keys() -> Arc<Self> {
        Self::create_with_random_keys_for_mode(EnclaveMode::Withdraw)
    }

    /// Create an enclave post operator_init() but pre provisioner_init().
    pub async fn create_operator_initialized() -> Arc<Self> {
        Self::create_operator_initialized_with(OperatorInitTestArgs::default()).await
    }

    pub async fn create_operator_initialized_with(args: OperatorInitTestArgs) -> Arc<Self> {
        let enclave = Self::create_with_random_keys();
        enclave.install_operator_init_for_testing(args);
        assert_eq!(
            enclave.lifecycle(),
            WithdrawStage::OperatorInitialized.into()
        );
        enclave
    }

    /// Apply operator_init's installs to an existing enclave (mirrors `operator_init`'s
    /// withdraw-mode commit). Lets a harness defer operator-init until DKG output exists.
    pub fn install_operator_init_for_testing(&self, args: OperatorInitTestArgs) {
        self.config.set_s3_logger(args.s3_logger).unwrap();
        crate::operator_init::InitInstall::from_parts(
            args.config,
            args.ceremony_state,
            args.genesis_state,
        )
        .install_into(self);
        self.advance_lifecycle_into(WithdrawStage::OperatorInitialized.into())
            .expect("operator init test setup should advance lifecycle");
    }

    pub fn create_operator_initialized_ceremony(s3_logger: GuardianS3Client) -> Arc<Self> {
        let enclave = Self::create_with_random_keys_for_mode(EnclaveMode::Ceremony);
        enclave.config.set_s3_logger(s3_logger).unwrap();
        enclave
            .advance_lifecycle_into(CeremonyStage::OperatorInitialized.into())
            .expect("ceremony operator init test setup should advance lifecycle");
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
    pub limiter_config: LimiterConfig,
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

/// Drive an operator-initialized enclave through provisioner-init by setting the
/// BTC keypair. The live serving state is installed separately by OA helpers. The
/// keypair may already exist from an earlier [`set_or_get_enclave_btc_pubkey`]
/// (idempotent).
pub fn finalize_enclave(enclave: &Arc<Enclave>) -> GuardianResult<()> {
    let _ = set_or_get_enclave_btc_pubkey(enclave)?;
    enclave.advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())?;
    Ok(())
}

/// Install activation-derived live state for tests that need normal operation.
pub fn activate_enclave_for_testing(
    enclave: &Arc<Enclave>,
    committee: HashiCommittee,
    limiter_config: LimiterConfig,
    limiter_state: LimiterState,
) -> GuardianResult<()> {
    let rate_limiter = RateLimiter::new(limiter_config, limiter_state)?;

    enclave.state.init(committee, rate_limiter)?;
    enclave.clear_initialization_state();
    enclave.advance_lifecycle_into(WithdrawStage::Activated.into())?;
    Ok(())
}

/// Operator-init + finalize in one shot.
pub async fn create_fully_initialized_enclave(args: FullyInitializedArgs) -> Arc<Enclave> {
    let FullyInitializedArgs {
        network,
        committee,
        master_pubkey,
        limiter_config,
        limiter_state,
    } = args;

    let config = InitConfig::from_parts_for_testing(limiter_config, master_pubkey, network);
    let enclave =
        create_operator_initialized_enclave(OperatorInitTestArgs::default().with_config(config))
            .await;

    finalize_enclave(&enclave).expect("finalize_enclave should succeed on a fresh enclave");
    activate_enclave_for_testing(&enclave, committee, limiter_config, limiter_state)
        .expect("activate_enclave_for_testing should succeed on a fresh enclave");

    assert!(enclave.is_fully_initialized());
    assert!(enclave.secret_sharing_instance().is_err());
    enclave
}
