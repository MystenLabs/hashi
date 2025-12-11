use std::sync::{Arc, Mutex};

pub mod bls;
pub mod communication;
pub mod config;
pub mod dkg;
pub mod grpc;
pub mod metrics;
pub mod onchain;
pub mod proto;
pub mod storage;
pub mod tls;

pub struct Hashi {
    pub server_version: ServerVersion,
    pub config: config::Config,
    pub metrics: Arc<metrics::Metrics>,
    onchain_state: std::sync::OnceLock<onchain::OnchainState>,
    // TODO: Remove `Option` wrappers below after we are able to initialize them
    // TODO: Replace `DkgManager` by `MpcManager`
    pub dkg_manager: Option<Mutex<dkg::DkgManager>>,
}

impl Hashi {
    pub fn new(
        server_version: ServerVersion,
        config: config::Config,
        dkg_manager: Option<dkg::DkgManager>,
    ) -> Arc<Self> {
        let metrics = Arc::new(metrics::Metrics::new_default());
        Arc::new(Self {
            server_version,
            config,
            metrics,
            onchain_state: Default::default(),
            dkg_manager: dkg_manager.map(Mutex::new),
        })
    }

    pub fn new_with_registry(
        server_version: ServerVersion,
        config: config::Config,
        dkg_manager: Option<dkg::DkgManager>,
        registry: &prometheus::Registry,
    ) -> Arc<Self> {
        Arc::new(Self {
            server_version,
            config,
            metrics: Arc::new(metrics::Metrics::new(registry)),
            onchain_state: Default::default(),
            dkg_manager: dkg_manager.map(Mutex::new),
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

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
            self.initialize_onchain_state().await;
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
        let server_version = ServerVersion::new("unknown", "unknown");
        let config = Config::new_for_testing();
        let tls_public_key = config.tls_public_key().unwrap();

        let hashi = Hashi::new(server_version, config, None);

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
