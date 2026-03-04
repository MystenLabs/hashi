use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use anyhow::anyhow;
use sui_futures::service::Service;

pub mod btc_monitor;
pub mod cli;
pub mod communication;
pub mod config;
pub mod constants;
pub mod db;
pub mod deposits;
pub mod grpc;
pub mod leader;
pub mod metrics;
pub mod mpc;
pub mod onchain;
pub mod publish;
pub mod storage;
pub mod sui_tx_executor;
pub mod tls;
pub mod withdrawals;

/// The allowed delta for weight reduction in basis points (800 means 8%).
/// This matches Sui's `random_beacon_reduction_allowed_delta` configuration.
const WEIGHT_REDUCTION_ALLOWED_DELTA: u16 = 800;
// TODO: Tune based on production workload.
const BATCH_SIZE_PER_WEIGHT: u16 = 10;

fn init_crypto_provider() {
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
    signing_manager: OnceLock<Arc<RwLock<mpc::SigningManager>>>,
    mpc_handle: OnceLock<mpc::MpcHandle>,
    btc_monitor: OnceLock<crate::btc_monitor::monitor::MonitorClient>,
    screener_client: OnceLock<Option<grpc::screener_client::ScreenerClient>>,
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
            signing_manager: OnceLock::new(),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
            screener_client: OnceLock::new(),
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
            signing_manager: OnceLock::new(),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
            screener_client: OnceLock::new(),
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

    pub fn signing_manager(&self) -> Arc<RwLock<mpc::SigningManager>> {
        self.signing_manager
            .get()
            .expect("SigningManager not initialized")
            .clone()
    }

    pub fn signing_verifying_key(&self) -> Option<fastcrypto_tbls::threshold_schnorr::G> {
        self.signing_manager
            .get()
            .map(|manager| manager.read().unwrap().verifying_key())
    }

    pub fn init_signing_manager(&self, manager: mpc::SigningManager) {
        self.signing_manager
            .set(Arc::new(RwLock::new(manager)))
            .map_err(|_| anyhow!("SigningManager already initialized"))
            .unwrap();
    }

    pub fn set_signing_manager(&self, manager: mpc::SigningManager) {
        *self
            .signing_manager
            .get()
            .expect("SigningManager not initialized")
            .write()
            .unwrap() = manager;
    }

    pub fn set_or_init_signing_manager(&self, manager: mpc::SigningManager) {
        match self.signing_manager.get() {
            Some(lock) => *lock.write().unwrap() = manager,
            None => {
                let _ = self.signing_manager.set(Arc::new(RwLock::new(manager)));
            }
        }
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

    async fn initialize_onchain_state(&self) -> anyhow::Result<Service> {
        let (onchain_state, service) = onchain::OnchainState::new(
            self.config.sui_rpc.as_deref().unwrap(),
            self.config.hashi_ids(),
            self.config.tls_private_key().ok(),
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
        let committee_set = &state.hashi().committees;
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
                assert!(
                    chain_id != constants::SUI_MAINNET_CHAIN_ID
                        && chain_id != constants::SUI_TESTNET_CHAIN_ID,
                    "test_batch_size_per_weight must not be set on mainnet or testnet"
                );
                override_val
            } else {
                BATCH_SIZE_PER_WEIGHT
            };
        Ok(mpc::MpcManager::new(
            address,
            committee_set,
            session_id,
            encryption_key,
            signing_key,
            store,
            WEIGHT_REDUCTION_ALLOWED_DELTA,
            chain_id,
            self.config.test_weight_divisor,
            batch_size_per_weight,
        )?)
    }

    fn initialize_btc_monitor(&self) -> anyhow::Result<Service> {
        let monitor_config = crate::btc_monitor::config::MonitorConfig::builder()
            .network(self.config.bitcoin_network())
            .confirmation_threshold(self.config.bitcoin_confirmation_threshold())
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
        let (client, service) = crate::btc_monitor::monitor::Monitor::run(monitor_config)
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

        // Initialize
        let onchain_service = self.initialize_onchain_state().await?;

        // Sweep any SUI in the configured account to AB to enable parallelization of txns
        sui_tx_executor::sweep_to_address_balance(&mut self.onchain_state().client(), &self.config)
            .await?;

        if self.is_in_current_committee() {
            let epoch = self.onchain_state().epoch();
            let mpc_manager = self
                .create_mpc_manager(epoch, mpc::types::ProtocolType::Dkg)
                .map_err(|e| {
                    tracing::error!("Failed to create MpcManager: {e}");
                    e
                })?;
            self.mpc_manager
                .set(Arc::new(RwLock::new(mpc_manager)))
                .map_err(|_| anyhow!("MpcManager already set"))?;
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

        let service = Service::new()
            .merge(onchain_service)
            .merge(btc_monitor_service)
            .merge(http_service)
            .merge(leader_service)
            .merge(mpc_service);

        Ok(service)
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
