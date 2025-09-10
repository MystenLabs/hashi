use std::sync::Arc;

pub mod bls;
pub mod committee;
pub mod config;
pub mod grpc;
pub mod metrics;
pub mod proto;
pub mod tls;

pub struct Hashi {
    pub server_version: ServerVersion,
    pub config: config::Config,
    pub metrics: Arc<metrics::Metrics>,
}

impl Hashi {
    pub fn new(server_version: ServerVersion, config: config::Config) -> Arc<Self> {
        let metrics = Arc::new(metrics::Metrics::new_default());
        Arc::new(Self {
            server_version,
            config,
            metrics,
        })
    }

    pub fn new_with_registry(
        server_version: ServerVersion,
        config: config::Config,
        registry: &prometheus::Registry,
    ) -> Arc<Self> {
        Arc::new(Self {
            server_version,
            config,
            metrics: Arc::new(metrics::Metrics::new(registry)),
        })
    }

    pub fn start(self: Arc<Self>) {
        tokio::spawn(async move {
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
    use crate::proto::GetServiceInfoRequest;
    use crate::proto::bridge_service_client::BridgeServiceClient;

    #[allow(clippy::field_reassign_with_default)]
    #[tokio::test]
    async fn tls() {
        let server_version = ServerVersion::new("unknown", "unknown");
        let config = Config::new_for_testing();
        let tls_public_key = config.tls_public_key().unwrap();

        let hashi = Hashi::new(server_version, config);

        let http_server = crate::grpc::HttpService::new(hashi).start().await;

        let address = format!("https://{}", http_server.local_addr());
        dbg!(&address);

        let client_tls_config = crate::tls::make_client_config(tls_public_key);
        // let client_tls_config = crate::tls::make_client_config_no_verification();
        let channel = tonic_rustls::Channel::from_shared(address)
            .unwrap()
            .tls_config(client_tls_config)
            .unwrap()
            .connect()
            .await
            .unwrap();

        let mut client = BridgeServiceClient::new(channel);
        let resp = client
            .get_service_info(GetServiceInfoRequest::default())
            .await
            .unwrap();
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
