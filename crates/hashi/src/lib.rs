// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use anyhow::anyhow;
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
    local_limiter: RwLock<Option<Arc<guardian_limiter::LocalLimiter>>>,
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
            local_limiter: RwLock::new(None),
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
            local_limiter: RwLock::new(None),
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
        self.local_limiter.read().unwrap().clone()
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

    pub fn create_mpc_manager(
        &self,
        epoch: u64,
        protocol_type: mpc::types::ProtocolType,
    ) -> anyhow::Result<mpc::MpcManager> {
        let state = self.onchain_state().state();
        let hashi = state.hashi();
        let committee_set = &hashi.committees;
        let session_id = mpc::SessionId::new(self.config.sui_chain_id(), epoch, &protocol_type);
        let encryption_key = self.config.encryption_private_key()?;
        self.db
            .store_encryption_key(epoch, &encryption_key)
            .map_err(|e| anyhow!("failed to store encryption key: {e}"))?;
        let signing_key = self
            .config
            .protocol_private_key()
            .ok_or_else(|| anyhow!("no protocol_private_key configured"))?;
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

        let guardian = if let Some(endpoint) = self.config.guardian_endpoint() {
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

        self.guardian_client
            .set(guardian)
            .map_err(|_| anyhow!("Guardian client already initialized"))?;

        // Verify Sui RPC is on the expected chain before loading any state.
        self.verify_sui_chain_id().await?;

        // Initialize
        let onchain_service = self.initialize_onchain_state().await?;

        // Verify the local bitcoin_chain_id matches the on-chain value.
        self.verify_bitcoin_chain_id()?;

        // Sweep any SUI in the configured account to AB to enable parallelization of txns
        sui_tx_executor::sweep_to_address_balance(&mut self.onchain_state().client(), &self.config)
            .await?;

        // Register validator (if not already registered) and update any stale metadata.
        match sui_tx_executor::SuiTxExecutor::from_config(&self.config, self.onchain_state())?
            .execute_register_or_update_validator(&self.config, None)
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

    /// Fetch `GetGuardianInfo` once and seed `guardian_signing_pubkey` and
    /// `local_limiter` as far as the response allows. Idempotent. Returns
    /// `true` once the local limiter slot is populated; the retry loop uses
    /// this as its exit signal.
    async fn try_seed_guardian_state(&self) -> bool {
        let Some(client) = self.guardian_client() else {
            return false;
        };
        let info_pb = match client.get_guardian_info().await {
            Ok(info) => info,
            Err(e) => {
                tracing::debug!("guardian bootstrap: GetGuardianInfo failed: {e}");
                return false;
            }
        };
        let info = match hashi_types::guardian::GetGuardianInfoResponse::try_from(info_pb) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("guardian bootstrap: parse failed: {e:?}");
                return false;
            }
        };
        let _ = self.guardian_signing_pubkey.set(Some(info.signing_pub_key));
        let (Some(state), Some(config)) = (info.limiter_state, info.limiter_config) else {
            tracing::debug!("guardian bootstrap: guardian has no limiter yet");
            return false;
        };
        let mut slot = self.local_limiter.write().unwrap();
        if slot.is_none() {
            tracing::info!(
                ?state,
                ?config,
                "Local guardian limiter seeded from GetGuardianInfo",
            );
            *slot = Some(Arc::new(guardian_limiter::LocalLimiter::new(config, state)));
        }
        true
    }

    /// Drive `try_seed_guardian_state` with bounded exponential backoff
    /// until the first success, then exit. The first attempt fires
    /// immediately (delay = 0). No-op when no guardian is configured.
    fn start_guardian_bootstrap(self: Arc<Self>) -> Service {
        Service::new().spawn_aborting(async move {
            if self.guardian_client().is_none() {
                return Ok(());
            }
            const MAX_DELAY: std::time::Duration = std::time::Duration::from_secs(30);
            let mut delay = std::time::Duration::ZERO;
            loop {
                tokio::time::sleep(delay).await;
                if self.try_seed_guardian_state().await {
                    tracing::info!("Guardian bootstrap complete");
                    return Ok(());
                }
                delay = if delay.is_zero() {
                    std::time::Duration::from_secs(1)
                } else {
                    (delay * 2).min(MAX_DELAY)
                };
            }
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
    use crate::Hashi;
    use crate::ServerVersion;
    use crate::config::Config;
    use crate::grpc::Client;

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
