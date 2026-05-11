// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use anyhow::anyhow;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::committee::EncryptionPublicKey;
use sui_futures::service::Service;

pub mod backup;
pub mod btc_monitor;
pub mod cli;
pub mod communication;
pub mod config;
pub mod constants;
pub mod db;
pub mod deposits;
pub mod grpc;
pub mod guardian_limiter;
pub mod leader;
pub mod metrics;
pub mod mpc;
pub mod onchain;
pub mod publish;
pub mod storage;
pub mod sui_tx_executor;
pub mod tls;
pub mod utxo_pool;
pub mod withdrawals;

// TODO: Tune based on production workload.
const BATCH_SIZE_PER_WEIGHT: u16 = 10;

pub(crate) struct NextEpochKeys {
    pub encryption_public_key: EncryptionPublicKey,
    pub signing_private_key: Bls12381PrivateKey,
}

pub(crate) fn init_crypto_provider() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
}

pub struct Hashi {
    pub server_version: ServerVersion,
    pub config: config::Config,
    pub metrics: Arc<metrics::Metrics>,
    pub db: Arc<db::Database>,
    onchain_state: OnceLock<onchain::OnchainState>,
    mpc_manager: OnceLock<Arc<RwLock<mpc::MpcManager>>>,
    signing_manager: RwLock<Option<Arc<mpc::SigningManager>>>,
    mpc_handle: OnceLock<mpc::MpcHandle>,
    btc_monitor: OnceLock<crate::btc_monitor::monitor::MonitorClient>,
    screener_client: OnceLock<Option<grpc::screener_client::ScreenerClient>>,
    guardian_client: OnceLock<Option<grpc::guardian_client::GuardianClient>>,
    guardian_signing_pubkey: OnceLock<Option<hashi_types::guardian::GuardianPubKey>>,
    local_limiter: OnceLock<Arc<guardian_limiter::LocalLimiter>>,
    /// Reconfig completion signatures by epoch.
    reconfig_signatures: RwLock<HashMap<u64, Vec<u8>>>,
}

impl Hashi {
    pub fn new(server_version: ServerVersion, config: config::Config) -> anyhow::Result<Arc<Self>> {
        init_crypto_provider();
        let db_path = config.db.as_deref().unwrap();
        let db = db::Database::open(db_path)?;
        let metrics = Arc::new(metrics::Metrics::new_default());
        Ok(Arc::new(Self {
            server_version,
            config,
            metrics,
            db: Arc::new(db),
            onchain_state: OnceLock::new(),
            mpc_manager: OnceLock::new(),
            signing_manager: RwLock::new(None),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
            screener_client: OnceLock::new(),
            guardian_client: OnceLock::new(),
            guardian_signing_pubkey: OnceLock::new(),
            local_limiter: OnceLock::new(),
            reconfig_signatures: RwLock::new(HashMap::new()),
        }))
    }

    pub fn new_with_registry(
        server_version: ServerVersion,
        config: config::Config,
        registry: &prometheus::Registry,
    ) -> anyhow::Result<Arc<Self>> {
        init_crypto_provider();
        let db_path = config.db.as_deref().unwrap();
        let db = db::Database::open(db_path)?;
        let metrics = Arc::new(metrics::Metrics::new(registry));
        Ok(Arc::new(Self {
            server_version,
            config,
            metrics,
            db: Arc::new(db),
            onchain_state: OnceLock::new(),
            mpc_manager: OnceLock::new(),
            signing_manager: RwLock::new(None),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
            screener_client: OnceLock::new(),
            guardian_client: OnceLock::new(),
            guardian_signing_pubkey: OnceLock::new(),
            local_limiter: OnceLock::new(),
            reconfig_signatures: RwLock::new(HashMap::new()),
        }))
    }

    pub fn onchain_state(&self) -> &onchain::OnchainState {
        self.onchain_state
            .get()
            .expect("hashi has not finished initializing")
    }

    // Return reference to the onchain state, allowing the caller to check if it has been
    // initialized or not
    pub fn onchain_state_opt(&self) -> Option<&onchain::OnchainState> {
        self.onchain_state.get()
    }

    pub fn mpc_manager(&self) -> Option<Arc<RwLock<mpc::MpcManager>>> {
        self.mpc_manager.get().cloned()
    }

    pub fn set_mpc_manager(&self, manager: mpc::MpcManager) {
        match self.mpc_manager.get() {
            Some(lock) => {
                // RwLock::write only fails if poisoned (a thread panicked while holding the lock).
                // Poisoning indicates a bug, so we propagate the panic rather than recover.
                *lock.write().unwrap() = manager;
            }
            None => {
                // First-time initialization (e.g. new committee member joining mid-rotation).
                let _ = self.mpc_manager.set(Arc::new(RwLock::new(manager)));
            }
        }
    }

    pub fn signing_manager_for(&self, epoch: u64) -> Option<Arc<mpc::SigningManager>> {
        let stored = self.signing_manager.read().unwrap();
        stored
            .as_ref()
            .filter(|manager| manager.epoch() == epoch)
            .cloned()
    }

    pub fn current_signing_manager(&self) -> Option<Arc<mpc::SigningManager>> {
        let epoch = self.onchain_state_opt()?.epoch();
        self.signing_manager_for(epoch)
    }

    pub fn signing_verifying_key(&self) -> Option<fastcrypto_tbls::threshold_schnorr::G> {
        self.signing_manager
            .read()
            .unwrap()
            .as_ref()
            .map(|manager| manager.verifying_key())
    }

    pub fn store_signing_manager(&self, manager: mpc::SigningManager) {
        *self.signing_manager.write().unwrap() = Some(Arc::new(manager));
    }

    /// Test-only
    pub fn clear_signing_manager_for_test(&self) {
        *self.signing_manager.write().unwrap() = None;
    }

    pub fn btc_monitor(&self) -> &crate::btc_monitor::monitor::MonitorClient {
        self.btc_monitor.get().expect("BtcMonitor not initialized")
    }

    pub fn store_reconfig_signature(&self, epoch: u64, signature: Vec<u8>) {
        self.reconfig_signatures
            .write()
            .unwrap()
            .insert(epoch, signature);
    }

    pub fn get_reconfig_signature(&self, epoch: u64) -> Option<Vec<u8>> {
        self.reconfig_signatures
            .read()
            .unwrap()
            .get(&epoch)
            .cloned()
    }

    pub fn mpc_handle(&self) -> Option<&mpc::MpcHandle> {
        self.mpc_handle.get()
    }

    pub fn screener_client(&self) -> Option<&grpc::screener_client::ScreenerClient> {
        self.screener_client.get().and_then(|opt| opt.as_ref())
    }

    pub fn guardian_client(&self) -> Option<&grpc::guardian_client::GuardianClient> {
        self.guardian_client.get().and_then(|opt| opt.as_ref())
    }

    pub fn guardian_signing_pubkey(&self) -> Option<&hashi_types::guardian::GuardianPubKey> {
        self.guardian_signing_pubkey
            .get()
            .and_then(|opt| opt.as_ref())
    }

    pub fn local_limiter(&self) -> Option<Arc<guardian_limiter::LocalLimiter>> {
        self.local_limiter.get().cloned()
    }

    async fn initialize_onchain_state(&self) -> anyhow::Result<Service> {
        let (onchain_state, service) = onchain::OnchainState::new(
            self.config.sui_rpc.as_deref().unwrap(),
            self.config.hashi_ids(),
            self.config.tls_private_key().ok(),
            Some(self.config.grpc_max_decoding_message_size()),
            Some(self.metrics.clone()),
        )
        .await?;
        self.onchain_state
            .set(onchain_state)
            .map_err(|_| anyhow!("OnchainState already initialized"))?;
        Ok(service)
    }

    pub fn prepare_encryption_key(&self, epoch: u64) -> anyhow::Result<EncryptionPublicKey> {
        if let Some(existing) = self.db.get_encryption_key(epoch)? {
            return Ok(EncryptionPublicKey::from_private_key(&existing));
        }
        let private_key = EncryptionPrivateKey::new(&mut rand::thread_rng());
        let public_key = EncryptionPublicKey::from_private_key(&private_key);
        self.db
            .store_encryption_key(epoch, &private_key)
            .map_err(|e| anyhow!("failed to store encryption key for epoch {epoch}: {e}"))?;
        Ok(public_key)
    }

    pub(crate) fn prepare_next_epoch_keys(&self, epoch: u64) -> anyhow::Result<NextEpochKeys> {
        let encryption_public_key = self.prepare_encryption_key(epoch)?;
        let signing_private_key = self.prepare_signing_key(epoch)?;
        Ok(NextEpochKeys {
            encryption_public_key,
            signing_private_key,
        })
    }

    pub async fn prepare_and_register_keys(self: &Arc<Self>, epoch: u64) -> anyhow::Result<()> {
        let keys = self.prepare_next_epoch_keys(epoch)?;
        let mut executor = sui_tx_executor::SuiTxExecutor::from_hashi(self.clone())?;
        executor
            .execute_register_or_update_validator(
                &self.config,
                None,
                Some(&keys.encryption_public_key),
                Some(&keys.signing_private_key),
            )
            .await
            .map(|_| ())
    }

    fn find_encryption_key_for_committee(
        &self,
        committee: &hashi_types::committee::Committee,
        validator_address: sui_sdk_types::Address,
        epoch: u64,
    ) -> anyhow::Result<EncryptionPrivateKey> {
        let member = committee
            .members()
            .iter()
            .find(|m| m.validator_address() == validator_address)
            .ok_or_else(|| anyhow!("validator not in committee for epoch {epoch}"))?;
        let pub_key = member.encryption_public_key();
        self.db
            .find_encryption_key_matching(pub_key)
            .map_err(|e| anyhow!("DB error looking up encryption key for epoch {epoch}: {e}"))?
            .ok_or_else(|| {
                anyhow!(
                    "no DB encryption key matches committee record for epoch {epoch}; \
                     operator intervention needed (re-register, possibly DB recovery)"
                )
            })
    }

    pub fn prepare_signing_key(&self, epoch: u64) -> anyhow::Result<Bls12381PrivateKey> {
        if let Some(existing) = self.db.get_signing_key(epoch)? {
            return Ok(existing);
        }
        let private_key = Bls12381PrivateKey::generate(&mut rand::thread_rng());
        self.db
            .store_signing_key(epoch, &private_key)
            .map_err(|e| anyhow!("failed to store signing key for epoch {epoch}: {e}"))?;
        Ok(private_key)
    }

    pub(crate) fn find_signing_key_for_committee(
        &self,
        committee: &hashi_types::committee::Committee,
        validator_address: sui_sdk_types::Address,
        epoch: u64,
    ) -> anyhow::Result<Bls12381PrivateKey> {
        let member = committee
            .members()
            .iter()
            .find(|m| m.validator_address() == validator_address)
            .ok_or_else(|| anyhow!("validator not in committee for epoch {epoch}"))?;
        let pub_key = member.public_key();
        self.db
            .find_signing_key_matching(pub_key)
            .map_err(|e| anyhow!("DB error looking up signing key for epoch {epoch}: {e}"))?
            .ok_or_else(|| {
                anyhow!(
                    "no DB signing key matches committee record for epoch {epoch}; \
                     operator intervention needed (re-register, possibly DB recovery)"
                )
            })
    }

    pub(crate) async fn next_reconfig_epoch(&self) -> anyhow::Result<u64> {
        use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
        let mut client = self.onchain_state().client();
        let service_info = client
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();
        let sui_epoch = service_info.epoch();
        let hashi_epoch = self.onchain_state().epoch();
        let is_genesis = hashi_epoch == 0 && self.onchain_state().current_committee().is_none();
        Ok(if is_genesis || hashi_epoch < sui_epoch {
            sui_epoch
        } else {
            sui_epoch + 1
        })
    }

    pub fn create_mpc_manager(
        &self,
        epoch: u64,
        protocol_type: mpc::types::ProtocolType,
    ) -> anyhow::Result<mpc::MpcManager> {
        let state = self.onchain_state().state();
        let hashi = state.hashi();
        let committee_set = &hashi.committees;
        let session_id = mpc::SessionId::new(self.config.sui_chain_id(), epoch, &protocol_type);
        let validator_address = self.config.validator_address()?;
        let encryption_key = self.find_encryption_key_for_committee(
            committee_set
                .committees()
                .get(&epoch)
                .ok_or_else(|| anyhow!("no committee for epoch {epoch}"))?,
            validator_address,
            epoch,
        )?;
        // Absent at genesis: pending_epoch_change=Some(target) but committees()
        // has no entry for the current on-chain epoch yet.
        let previous_encryption_key = committee_set
            .previous_committee_for_target(epoch)
            .map(|(prev_ep, prev_committee)| {
                self.find_encryption_key_for_committee(prev_committee, validator_address, prev_ep)
                    .map(Some)
                    .or_else(|e| {
                        if !prev_committee
                            .members()
                            .iter()
                            .any(|m| m.validator_address() == validator_address)
                        {
                            Ok(None)
                        } else {
                            Err(e)
                        }
                    })
            })
            .transpose()?
            .flatten();
        let signing_key = self.find_signing_key_for_committee(
            committee_set
                .committees()
                .get(&epoch)
                .ok_or_else(|| anyhow!("no committee for epoch {epoch}"))?,
            validator_address,
            epoch,
        )?;
        let store = Box::new(storage::EpochPublicMessagesStore::new(
            self.db.clone(),
            epoch,
        ));
        let address = self.config.validator_address()?;
        let chain_id = self.config.sui_chain_id();
        let batch_size_per_weight =
            if let Some(override_val) = self.config.test_batch_size_per_weight {
                assert_test_only_config(
                    chain_id,
                    self.config.bitcoin_chain_id(),
                    "test_batch_size_per_weight",
                );
                override_val
            } else {
                BATCH_SIZE_PER_WEIGHT
            };
        if self.config.test_corrupt_shares_for.is_some() {
            assert_test_only_config(
                chain_id,
                self.config.bitcoin_chain_id(),
                "test_corrupt_shares_for",
            );
        }
        Ok(mpc::MpcManager::new(
            address,
            committee_set,
            session_id,
            encryption_key,
            previous_encryption_key,
            signing_key,
            store,
            chain_id,
            self.config.test_weight_divisor,
            batch_size_per_weight,
            self.config.test_corrupt_shares_for,
        )?)
    }

    /// Verify the Sui RPC endpoint is on the expected chain.
    async fn verify_sui_chain_id(&self) -> anyhow::Result<()> {
        use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;

        let sui_rpc_url = self.config.sui_rpc.as_deref().unwrap();
        let mut client = sui_rpc::Client::new(sui_rpc_url)?;

        let service_info = client
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();

        let rpc_chain_id = service_info.chain_id();

        let expected = self.config.sui_chain_id();

        anyhow::ensure!(
            rpc_chain_id == expected,
            "Sui chain ID mismatch: local config has {expected}, \
             but RPC endpoint reports {rpc_chain_id}"
        );

        tracing::info!("Sui chain ID verified: {expected}");
        Ok(())
    }

    /// Verify the local config's `bitcoin_chain_id` matches the value stored on-chain.
    fn verify_bitcoin_chain_id(&self) -> anyhow::Result<()> {
        use bitcoin::hashes::Hash as _;
        use std::str::FromStr;

        let onchain_chain_id = self
            .onchain_state()
            .state()
            .hashi()
            .config
            .bitcoin_chain_id()
            .ok_or_else(|| anyhow!("bitcoin_chain_id not found in on-chain config"))?;

        let local_chain_id = self.config.bitcoin_chain_id();
        let block_hash = btc_monitor::config::BlockHash::from_str(local_chain_id)?;
        let local_addr = sui_sdk_types::Address::new(*block_hash.as_byte_array());

        anyhow::ensure!(
            local_addr == onchain_chain_id,
            "bitcoin chain ID mismatch: local config has {local_chain_id}, \
             but on-chain value is {onchain_chain_id}"
        );

        tracing::info!("Bitcoin chain ID verified: {local_chain_id}");
        Ok(())
    }

    /// Verify the connected bitcoind is on the expected network.
    fn verify_bitcoind_network(&self) -> anyhow::Result<()> {
        let rpc = crate::btc_monitor::config::new_rpc_client(
            self.config.bitcoin_rpc(),
            self.config.bitcoin_rpc_auth(),
        )?;

        let info = rpc.get_blockchain_info()?.into_model()?;
        let expected = self.config.bitcoin_network();

        anyhow::ensure!(
            info.chain == expected,
            "bitcoind network mismatch: expected {expected:?}, but node reports {:?}",
            info.chain
        );

        tracing::info!("Bitcoind network verified: {expected:?}");
        Ok(())
    }

    fn initialize_btc_monitor(&self) -> anyhow::Result<Service> {
        self.verify_bitcoind_network()?;

        let monitor_config = crate::btc_monitor::config::MonitorConfig::builder()
            .network(self.config.bitcoin_network())
            .start_height(self.config.bitcoin_start_height())
            .bitcoind_rpc_config(
                self.config.bitcoin_rpc().to_string(),
                self.config.bitcoin_rpc_auth(),
            )
            .trusted_peers(self.config.bitcoin_trusted_peers()?)
            .data_dir(
                self.config
                    .db
                    .as_deref()
                    .expect("Db path is not set")
                    .join("btc-monitor"),
            )
            .build();
        let (client, service) =
            crate::btc_monitor::monitor::Monitor::run(monitor_config, self.metrics.clone())
                .expect("Failed to start BtcMonitor");
        self.btc_monitor
            .set(client)
            .map_err(|_| anyhow!("BtcMonitor already initialized"))?;
        Ok(service)
    }

    pub async fn start(self: Arc<Self>) -> anyhow::Result<Service> {
        let screener = if let Some(endpoint) = self.config.screener_endpoint() {
            match grpc::screener_client::ScreenerClient::new(endpoint) {
                Ok(client) => {
                    tracing::info!("Screener client configured for {}", client.endpoint());
                    Some(client)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to configure screener client for {}: {}",
                        endpoint,
                        e
                    );
                    None
                }
            }
        } else {
            tracing::warn!("No screener endpoint configured; AML screening will be skipped");
            None
        };

        self.metrics
            .screener_enabled
            .set(if screener.is_some() { 1 } else { 0 });

        self.screener_client
            .set(screener)
            .map_err(|_| anyhow!("Screener client already initialized"))?;

        // Verify Sui RPC is on the expected chain before loading any state.
        self.verify_sui_chain_id().await?;

        // Initialize on-chain state first so we can read guardian config from it.
        let onchain_service = self.initialize_onchain_state().await?;

        let guardian_endpoint = {
            let state = self.onchain_state().state();
            state.hashi().config.guardian_url().map(|s| s.to_string())
        }
        .or_else(|| self.config.guardian_endpoint().map(|s| s.to_string()));

        let guardian = if let Some(endpoint) = guardian_endpoint.as_deref() {
            match grpc::guardian_client::GuardianClient::new(endpoint) {
                Ok(client) => {
                    tracing::info!("Guardian client configured for {}", client.endpoint());
                    Some(client)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to configure guardian client for {}: {}",
                        endpoint,
                        e
                    );
                    None
                }
            }
        } else {
            tracing::info!("No guardian endpoint configured; guardian integration disabled");
            None
        };

        self.metrics
            .guardian_enabled
            .set(if guardian.is_some() { 1 } else { 0 });
        self.guardian_client
            .set(guardian)
            .map_err(|_| anyhow!("Guardian client already initialized"))?;

        // Verify the local bitcoin_chain_id matches the on-chain value.
        self.verify_bitcoin_chain_id()?;

        // Sweep any SUI in the configured account to AB to enable parallelization of txns
        sui_tx_executor::sweep_to_address_balance(&mut self.onchain_state().client(), &self.config)
            .await?;

        let next_epoch_keys = match self.next_reconfig_epoch().await {
            Ok(next_epoch) => self
                .prepare_next_epoch_keys(next_epoch)
                .inspect_err(|e| {
                    tracing::warn!(
                        "Failed to prepare encryption/signing keys for epoch {next_epoch}: {e}; \
                         will retry before next start_reconfig"
                    )
                })
                .ok(),
            Err(e) => {
                tracing::warn!("Failed to compute next reconfig epoch: {e}");
                None
            }
        };

        // Register validator (if not already registered) and update any stale metadata.
        match sui_tx_executor::SuiTxExecutor::from_config(&self.config, self.onchain_state())?
            .execute_register_or_update_validator(
                &self.config,
                None,
                next_epoch_keys.as_ref().map(|k| &k.encryption_public_key),
                next_epoch_keys.as_ref().map(|k| &k.signing_private_key),
            )
            .await
        {
            Ok(true) => tracing::info!("Validator registered/updated on-chain"),
            Ok(false) => tracing::debug!("Validator metadata is already up-to-date"),
            Err(e) => tracing::warn!("Failed to register/update validator metadata: {e}"),
        }

        if self.is_in_current_committee() {
            tracing::info!("Node is in the current committee; MPC service will recover state");
        } else if self.onchain_state().epoch() == 0
            && self.onchain_state().current_committee().is_none()
        {
            tracing::info!("No initial committee yet; MPC service will handle genesis bootstrap");
        } else {
            tracing::info!(
                "Node is not in the current committee; skipping initial DKG manager creation"
            );
        }

        let (mpc_service, mpc_handle) = mpc::MpcService::new(self.clone());
        self.mpc_handle
            .set(mpc_handle)
            .expect("MpcHandle already set");

        let btc_monitor_service = self.initialize_btc_monitor().map_err(|e| {
            tracing::error!("Failed to initialize BtcMonitor: {e}");
            e
        })?;

        // Start services
        let (_http_addr, http_service) = grpc::HttpService::new(self.clone()).start().await;
        let leader_service = leader::LeaderService::new(self.clone()).start();
        let mpc_service = mpc_service.start();
        let guardian_bootstrap_service = self.clone().start_guardian_bootstrap();

        let service = Service::new()
            .merge(onchain_service)
            .merge(btc_monitor_service)
            .merge(http_service)
            .merge(leader_service)
            .merge(mpc_service)
            .merge(guardian_bootstrap_service);

        Ok(service)
    }

    async fn try_seed_guardian_state(&self) -> bool {
        let Some(client) = self.guardian_client() else {
            return false;
        };
        self.metrics.guardian_bootstrap_attempts_total.inc();
        let rpc_start = std::time::Instant::now();
        let rpc_result = client.get_guardian_info().await;
        let rpc_elapsed = rpc_start.elapsed().as_secs_f64();
        let info_pb = match rpc_result {
            Ok(info) => {
                self.metrics.record_guardian_rpc(
                    metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                    metrics::GUARDIAN_RPC_OUTCOME_OK,
                    rpc_elapsed,
                );
                info
            }
            Err(e) => {
                self.metrics.record_guardian_rpc(
                    metrics::GUARDIAN_RPC_METHOD_GET_GUARDIAN_INFO,
                    metrics::GUARDIAN_RPC_OUTCOME_UNAVAILABLE,
                    rpc_elapsed,
                );
                self.metrics.record_guardian_bootstrap_outcome(
                    metrics::GUARDIAN_BOOTSTRAP_OUTCOME_RPC_FAILURE,
                );
                tracing::warn!("guardian bootstrap: GetGuardianInfo failed: {e}");
                return false;
            }
        };
        let info = match hashi_types::guardian::GetGuardianInfoResponse::try_from(info_pb) {
            Ok(info) => info,
            Err(e) => {
                self.metrics.record_guardian_bootstrap_outcome(
                    metrics::GUARDIAN_BOOTSTRAP_OUTCOME_PARSE_FAILURE,
                );
                tracing::warn!("guardian bootstrap: parse failed: {e:?}");
                return false;
            }
        };
        let _ = self.guardian_signing_pubkey.set(Some(info.signing_pub_key));
        let (Some(state), Some(config)) = (info.limiter_state, info.limiter_config) else {
            self.metrics.record_guardian_bootstrap_outcome(
                metrics::GUARDIAN_BOOTSTRAP_OUTCOME_NO_LIMITER_YET,
            );
            tracing::debug!("guardian bootstrap: guardian has no limiter yet");
            return false;
        };
        let limiter = Arc::new(guardian_limiter::LocalLimiter::new(config, state));
        if self.local_limiter.set(limiter.clone()).is_ok() {
            tracing::info!(
                ?state,
                ?config,
                "Local guardian limiter seeded from GetGuardianInfo",
            );
            self.metrics.record_limiter_state(&state, &config);
            self.metrics.guardian_limiter_initialized.set(1);
            // Hand the same Arc to OnchainState so the watcher can advance
            // it inline when WithdrawalSignedEvent fires.
            self.onchain_state().set_local_limiter(limiter);
        }
        self.metrics
            .record_guardian_bootstrap_outcome(metrics::GUARDIAN_BOOTSTRAP_OUTCOME_SUCCESS);
        true
    }

    fn start_guardian_bootstrap(self: Arc<Self>) -> Service {
        use backon::Retryable;
        Service::new().spawn_aborting(async move {
            if self.guardian_client().is_none() {
                return Ok(());
            }
            let policy = backon::ExponentialBuilder::default()
                .with_min_delay(std::time::Duration::from_secs(1))
                .with_max_delay(std::time::Duration::from_secs(30))
                .without_max_times();
            let _ = (|| async {
                if self.try_seed_guardian_state().await {
                    Ok::<(), ()>(())
                } else {
                    Err(())
                }
            })
            .retry(policy)
            .await;
            tracing::info!("Guardian bootstrap complete");
            Ok(())
        })
    }

    pub(crate) fn is_in_current_committee(&self) -> bool {
        let address = match self.config.validator_address() {
            Ok(a) => a,
            Err(_) => return false,
        };
        self.onchain_state()
            .current_committee()
            .is_some_and(|c| c.index_of(&address).is_some())
    }
}

#[derive(Clone)]
pub struct ServerVersion {
    pub bin: &'static str,
    pub version: &'static str,
}

impl ServerVersion {
    pub fn new(bin: &'static str, version: &'static str) -> Self {
        Self { bin, version }
    }
}

impl std::fmt::Display for ServerVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.bin)?;
        f.write_str("/")?;
        f.write_str(self.version)
    }
}

fn assert_test_only_config(sui_chain_id: &str, bitcoin_chain_id: &str, field_name: &str) {
    assert!(
        sui_chain_id != constants::SUI_MAINNET_CHAIN_ID
            && sui_chain_id != constants::SUI_TESTNET_CHAIN_ID
            && bitcoin_chain_id == constants::BITCOIN_REGTEST_CHAIN_ID,
        "{field_name} is only allowed on regtest"
    );
}

#[cfg(test)]
mod test {
    use fastcrypto::serde_helpers::ToFromByteArray;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use hashi_types::committee::EncryptionPublicKey;
    use sui_sdk_types::Address;

    use crate::Hashi;
    use crate::ServerVersion;
    use crate::config::Config;
    use crate::grpc::Client;

    fn new_hashi_for_test() -> (std::sync::Arc<Hashi>, tempfile::TempDir) {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let mut config = Config::new_for_testing();
        config.db = Some(tmpdir.path().into());
        let server_version = ServerVersion::new("unknown", "unknown");
        let registry = prometheus::Registry::new();
        let hashi = Hashi::new_with_registry(server_version, config, &registry).unwrap();
        (hashi, tmpdir)
    }

    #[test]
    fn prepare_encryption_key_is_idempotent() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let pk1 = hashi.prepare_encryption_key(1).unwrap();
        let pk2 = hashi.prepare_encryption_key(1).unwrap();
        assert_eq!(
            pk1.as_element().to_byte_array(),
            pk2.as_element().to_byte_array(),
            "second call should return the same public key"
        );
    }

    #[test]
    fn prepare_encryption_key_persists_private_key() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let pk = hashi.prepare_encryption_key(7).unwrap();
        let stored = hashi
            .db
            .get_encryption_key(7)
            .unwrap()
            .expect("private key should be in DB");
        assert_eq!(
            pk.as_element().to_byte_array(),
            EncryptionPublicKey::from_private_key(&stored)
                .as_element()
                .to_byte_array(),
            "returned public key should match the public key derived from the stored private key"
        );
    }

    #[test]
    fn prepare_encryption_key_generates_distinct_keys_per_epoch() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let pk1 = hashi.prepare_encryption_key(1).unwrap();
        let pk2 = hashi.prepare_encryption_key(2).unwrap();
        assert_ne!(
            pk1.as_element().to_byte_array(),
            pk2.as_element().to_byte_array(),
            "different epochs should yield different keys"
        );
    }

    #[test]
    fn prepare_signing_key_is_idempotent() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let k1 = hashi.prepare_signing_key(1).unwrap();
        let k2 = hashi.prepare_signing_key(1).unwrap();
        assert_eq!(
            k1.public_key().as_ref(),
            k2.public_key().as_ref(),
            "second call should return the same key"
        );
    }

    #[test]
    fn prepare_signing_key_persists_private_key() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let returned = hashi.prepare_signing_key(7).unwrap();
        let stored = hashi
            .db
            .get_signing_key(7)
            .unwrap()
            .expect("private key should be in DB");
        assert_eq!(
            returned.public_key().as_ref(),
            stored.public_key().as_ref(),
            "returned key should match the stored private key"
        );
    }

    #[test]
    fn prepare_signing_key_generates_distinct_keys_per_epoch() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let k1 = hashi.prepare_signing_key(1).unwrap();
        let k2 = hashi.prepare_signing_key(2).unwrap();
        assert_ne!(
            k1.public_key().as_ref(),
            k2.public_key().as_ref(),
            "different epochs should yield different keys"
        );
    }

    fn one_member_committee(
        epoch: u64,
        address: Address,
        bls_pub: hashi_types::committee::BLS12381PublicKey,
        enc_pub: EncryptionPublicKey,
    ) -> Committee {
        Committee::new(
            vec![CommitteeMember::new(address, bls_pub, enc_pub, 1)],
            epoch,
            10_000,
            0,
            5_000,
        )
    }

    #[test]
    fn find_signing_key_for_committee_errors_when_db_has_no_match() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let validator_address = Address::new([1u8; 32]);

        // Committee records a BLS pub key the DB knows nothing about.
        let unknown_bls_pub = Bls12381PrivateKey::generate(&mut rand::thread_rng()).public_key();
        let enc_pub = EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(
            &mut rand::thread_rng(),
        ));
        let committee = one_member_committee(5, validator_address, unknown_bls_pub, enc_pub);

        let err = hashi
            .find_signing_key_for_committee(&committee, validator_address, 5)
            .expect_err("lookup must fail when DB has no matching signing key");
        let msg = err.to_string();
        assert!(
            msg.contains("no DB signing key matches committee record for epoch 5"),
            "expected operator-intervention error, got: {msg}"
        );
    }

    #[test]
    fn find_encryption_key_for_committee_errors_when_db_has_no_match() {
        let (hashi, _tmpdir) = new_hashi_for_test();
        let validator_address = Address::new([1u8; 32]);

        // Committee records an encryption pub key the DB knows nothing about.
        let bls_pub = Bls12381PrivateKey::generate(&mut rand::thread_rng()).public_key();
        let unknown_enc_pub = EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(
            &mut rand::thread_rng(),
        ));
        let committee = one_member_committee(5, validator_address, bls_pub, unknown_enc_pub);

        let err = hashi
            .find_encryption_key_for_committee(&committee, validator_address, 5)
            .expect_err("lookup must fail when DB has no matching encryption key");
        let msg = err.to_string();
        assert!(
            msg.contains("no DB encryption key matches committee record for epoch 5"),
            "expected operator-intervention error, got: {msg}"
        );
    }

    #[allow(clippy::field_reassign_with_default)]
    #[tokio::test]
    async fn tls() {
        let tmpdir = tempfile::Builder::new().tempdir().unwrap();
        let server_version = ServerVersion::new("unknown", "unknown");
        let mut config = Config::new_for_testing();
        config.db = Some(tmpdir.path().into());
        let tls_public_key = config.tls_public_key().unwrap();

        let hashi = Hashi::new(server_version, config).unwrap();

        let (local_addr, _http_service) = crate::grpc::HttpService::new(hashi).start().await;

        let address = format!("https://{}", local_addr);
        dbg!(&address);

        let client_tls_config = crate::tls::make_client_config(&tls_public_key);
        let client_auth_server = Client::new(&address, client_tls_config).unwrap();
        let client_no_auth = Client::new_no_auth(&address).unwrap();

        let resp = client_auth_server.get_service_info().await.unwrap();
        dbg!(resp);
        let resp = client_no_auth.get_service_info().await.unwrap();
        dbg!(resp);

        //         loop {
        //             let resp = client
        //                 .get_service_info(GetServiceInfoRequest::default())
        //                 .await;
        //             dbg!(resp);
        //             tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        //         }
    }
}
