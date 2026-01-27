use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;

use anyhow::anyhow;

pub mod communication;
pub mod config;
pub mod db;
pub mod deposits;
pub mod dkg;
pub mod grpc;
pub mod leader;
pub mod metrics;
pub mod mpc;
pub mod onchain;
pub mod storage;
pub mod sui_tx_executor;
pub mod tls;

/// The allowed delta for weight reduction in basis points (800 means 8%).
/// This matches Sui's `random_beacon_reduction_allowed_delta` configuration.
const WEIGHT_REDUCTION_ALLOWED_DELTA: u16 = 800;

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
    dkg_manager: OnceLock<Arc<RwLock<dkg::DkgManager>>>,
    mpc_handle: OnceLock<mpc::MpcHandle>,
    btc_monitor: OnceLock<hashi_btc::monitor::MonitorClient>,
}

impl Hashi {
    pub fn new(server_version: ServerVersion, config: config::Config) -> Arc<Self> {
        init_crypto_provider();
        let metrics = Arc::new(metrics::Metrics::new_default());
        let db = db::Database::open(config.db.as_deref().unwrap());
        Arc::new(Self {
            server_version,
            config,
            metrics,
            db: Arc::new(db),
            onchain_state: OnceLock::new(),
            dkg_manager: OnceLock::new(),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
        })
    }

    pub fn new_with_registry(
        server_version: ServerVersion,
        config: config::Config,
        registry: &prometheus::Registry,
    ) -> Arc<Self> {
        init_crypto_provider();
        let db = db::Database::open(config.db.as_deref().unwrap());
        Arc::new(Self {
            server_version,
            config,
            metrics: Arc::new(metrics::Metrics::new(registry)),
            db: Arc::new(db),
            onchain_state: OnceLock::new(),
            dkg_manager: OnceLock::new(),
            mpc_handle: OnceLock::new(),
            btc_monitor: OnceLock::new(),
        })
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

    pub fn dkg_manager(&self) -> Arc<RwLock<dkg::DkgManager>> {
        self.dkg_manager
            .get()
            .expect("DkgManager not initialized")
            .clone()
    }

    pub fn set_dkg_manager(&self, manager: dkg::DkgManager) {
        *self
            .dkg_manager
            .get()
            .expect("DkgManager not initialized")
            .write()
            // RwLock::write only fails if poisoned (a thread panicked while holding the lock).
            // Poisoning indicates a bug, so we propagate the panic rather than recover.
            .unwrap() = manager;
    }

    pub fn btc_monitor(&self) -> &hashi_btc::monitor::MonitorClient {
        self.btc_monitor.get().expect("BtcMonitor not initialized")
    }

    async fn initialize_onchain_state(&self) {
        let onchain_state = onchain::OnchainState::new(
            self.config.sui_rpc.as_deref().unwrap(),
            self.config.hashi_ids(),
            self.config.tls_private_key().ok(),
        )
        .await
        .unwrap();
        self.onchain_state.set(onchain_state).unwrap();
    }

    pub fn create_dkg_manager(
        &self,
        epoch: u64,
        protocol_type: dkg::types::ProtocolType,
    ) -> anyhow::Result<dkg::DkgManager> {
        let state = self.onchain_state().state();
        let committee_set = &state.hashi().committees;
        let session_id = dkg::SessionId::new(self.config.sui_chain_id(), epoch, &protocol_type);
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
        Ok(dkg::DkgManager::new(
            self.config.validator_address()?,
            committee_set,
            session_id,
            encryption_key,
            signing_key,
            store,
            WEIGHT_REDUCTION_ALLOWED_DELTA,
        )?)
    }

    fn initialize_btc_monitor(&self) -> anyhow::Result<()> {
        let monitor_config = hashi_btc::config::MonitorConfig::builder()
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
        self.btc_monitor
            .set(
                hashi_btc::monitor::Monitor::run(monitor_config)
                    .expect("Failed to start BtcMonitor"),
            )
            .map_err(|_| anyhow!("BtcMonitor already initialized"))?;
        Ok(())
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            // Initialize
            self.initialize_onchain_state().await;

            let epoch = self.onchain_state().state().hashi().committees.epoch();
            let dkg_manager = match self.create_dkg_manager(epoch, dkg::types::ProtocolType::Dkg) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!("Failed to create DkgManager: {e}");
                    return;
                }
            };
            if self
                .dkg_manager
                .set(Arc::new(RwLock::new(dkg_manager)))
                .is_err()
            {
                panic!("DkgManager already set");
            }
            let (mpc_service, mpc_handle) = mpc::MpcService::new(self.clone());
            self.mpc_handle
                .set(mpc_handle)
                .expect("MpcHandle already set");

            if let Err(e) = self.initialize_btc_monitor() {
                tracing::error!("Failed to initialize BtcMonitor: {e}");
                return;
            }

            // Start services
            let http_service = grpc::HttpService::new(self.clone()).start();
            let leader_service = leader::LeaderService::new(self.clone()).start();
            let mpc_service = mpc_service.start();
            tokio::join!(http_service, leader_service, mpc_service);
        });
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

        let hashi = Hashi::new(server_version, config);

        let http_server = crate::grpc::HttpService::new(hashi).start().await;

        let address = format!("https://{}", http_server.local_addr());
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
