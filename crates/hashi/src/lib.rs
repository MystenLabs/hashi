use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

use anyhow::anyhow;

pub mod committee;
pub mod communication;
pub mod config;
pub mod db;
pub mod deposits;
pub mod dkg;
pub mod grpc;
pub mod metrics;
pub mod onchain;
pub mod proto;
pub mod storage;
pub mod tls;

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
    // TODO: Replace `DkgManager` by `MpcManager`
    dkg_manager: OnceLock<Mutex<dkg::DkgManager>>,
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

    pub fn dkg_manager(&self) -> &Mutex<dkg::DkgManager> {
        self.dkg_manager.get().expect("DkgManager not initialized")
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

    fn initialize_dkg(&self) -> anyhow::Result<()> {
        let state = self.onchain_state().state();
        let committee_set = &state.hashi().committees;
        let session_id = dkg::SessionId::new(
            self.config.sui_chain_id(),
            committee_set.epoch(),
            &dkg::types::ProtocolType::DkgKeyGeneration,
        );
        let encryption_key = self.config.encryption_private_key()?;
        let signing_key = self
            .config
            .protocol_private_key()
            .ok_or_else(|| anyhow!("no protocol_private_key configured"))?;
        let store = Box::new(storage::EpochPublicMessagesStore::new(
            self.db.clone(),
            committee_set.epoch(),
        ));
        let dkg_manager = dkg::DkgManager::new(
            self.config.validator_address()?,
            committee_set,
            session_id,
            encryption_key,
            signing_key,
            store,
        )?;
        self.dkg_manager
            .set(Mutex::new(dkg_manager))
            .map_err(|_| anyhow!("DkgManager already initialized"))?;
        Ok(())
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
            self.initialize_onchain_state().await;
            if let Err(e) = self.initialize_dkg() {
                tracing::error!("Failed to initialize DKG: {e}");
            }
            if let Err(e) = self.initialize_btc_monitor() {
                tracing::error!("Failed to initialize BtcMonitor: {e}");
            }
            let _http_server = grpc::HttpService::new(self.clone()).start().await;
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
