// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;

use sui_crypto::simple::SimpleKeypair;
use sui_sdk_types::Address;

use crate::constants::SUI_MAINNET_CHAIN_ID;

const DEFAULT_WITHDRAWAL_SIGNING_CONCURRENCY: usize = 25;
const DEFAULT_MPC_SIGNING_CHUNK_SIZE: usize = 64;
pub(crate) const DEFAULT_ONCHAIN_CONFIG_POLL_INTERVAL_MS: u64 = 300_000;
/// Tonic's 4 MiB default is too small to scrape a large on-chain state or
/// receive large MPC round messages.
pub(crate) const DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

fn deserialize_backup_pgp_cert<'de, D>(
    deserializer: D,
) -> Result<Option<hashi_types::pgp::PgpPublicCert>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = <Option<String> as serde::Deserialize>::deserialize(deserializer)? else {
        return Ok(None);
    };

    let path = Path::new(&value);
    let armored = if path.is_file() {
        std::fs::read_to_string(path).map_err(serde::de::Error::custom)?
    } else {
        value
    };

    hashi_types::pgp::PgpPublicCert::new(armored)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

#[derive(Clone, Debug, Default, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_address: Option<Address>,

    /// The local address to bind the gRPC+TLS server on.
    ///
    /// Defaults to `0.0.0.0:443` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<SocketAddr>,

    /// The publicly reachable URL advertised to other validators on-chain
    /// (e.g. `https://validator1.example.com:8443`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,

    /// Configure the address to listen on for http metrics
    ///
    /// Defaults to `127.0.0.1:9180` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_http_address: Option<SocketAddr>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_chain_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_chain_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashi_ids: Option<HashiIds>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sui_rpc: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_rpc: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_rpc_auth: Option<crate::btc_monitor::config::BtcRpcAuth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_start_height: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_trusted_peers: Option<Vec<String>>,

    /// Database path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,

    /// Armored OpenPGP certificate or certificate file path used for node backups.
    #[serde(
        default,
        deserialize_with = "deserialize_backup_pgp_cert",
        skip_serializing_if = "Option::is_none"
    )]
    pub backup_pgp_cert: Option<hashi_types::pgp::PgpPublicCert>,

    /// Directory to write automatic encrypted backups into.
    ///
    /// Defaults to `/tmp` if not specified.
    // TODO: eventually we should probably make this field mandatory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_dir: Option<PathBuf>,

    /// Force validator to run as leader, or never run as leader
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_run_as_leader: Option<ForceRunAsLeader>,

    /// Weight divisor for testing. Reduces validator weights to improve integration test performance.
    /// Can only be set if `sui_chain_id` is not mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_weight_divisor: Option<u16>,

    /// Override `BATCH_SIZE_PER_WEIGHT` for testing smaller presignature batches.
    /// Can only be set if `sui_chain_id` is not mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_batch_size_per_weight: Option<u16>,

    /// Override the presignature-derivation activation epoch for testing the
    /// epoch-boundary flip. Can only be set if `sui_chain_id` is not mainnet or
    /// testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_presignature_derivation_activation_epoch: Option<u64>,

    /// Override this binary's max supported protocol version — both what it
    /// advertises and what its reconfig latch accepts — so one build can
    /// simulate a mixed fleet in the protocol-version flip test. Can only be
    /// set if `sui_chain_id` is not mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_supported_protocol_version_max: Option<u64>,

    /// URL of the screener gRPC service endpoint (e.g. `https://hashi-screener.mystenlabs.com`).
    /// When not set, AML screening is skipped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screener_endpoint: Option<String>,

    /// URL of the `hashi-guardian` gRPC endpoint. When not set, the guardian
    /// integration is bypassed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardian_endpoint: Option<String>,

    /// Maximum gRPC decoding message size in bytes.
    ///
    /// Defaults to 32 MiB if not specified. Tonic's built-in default is 4 MiB,
    /// which is too small to scrape a large on-chain state or receive large MPC
    /// round messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_max_decoding_message_size: Option<usize>,

    /// Maximum number of tasks to process concurrently for a leader job such as processing deposit requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_leader_job_tasks: Option<usize>,

    /// Minimum time (ms) the leader waits after the oldest approved withdrawal
    /// request was submitted before committing a batch. The batch fires earlier
    /// if it reaches `withdrawal_max_batch_size`.
    ///
    /// Defaults to 300,000 ms (5 minutes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_batching_delay_ms: Option<u64>,

    /// Maximum number of withdrawal requests to include in a single Bitcoin
    /// transaction. The batch commits immediately once this many requests are
    /// ready, without waiting for `withdrawal_batching_delay_ms` to elapse.
    ///
    /// Defaults to 70 (the algorithm's hard upper bound).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_max_batch_size: Option<usize>,

    /// Max number of withdrawal-tx inputs whose MPC signatures the signer
    /// will collect in parallel within a single `sign_withdrawal_transaction`
    /// RPC.
    ///
    /// Defaults to 25.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_signing_concurrency: Option<usize>,

    /// Number of per-input MPC signatures the leader writes to chain in one
    /// `commit_input_signatures` PTB — the on-chain write batch size `M`. Trades
    /// durability granularity (work lost on a leader crash) against the number of
    /// commit PTBs per withdrawal. Purely a leader-side batching choice: the
    /// contract certs over exactly the indices written, so any size is valid up
    /// to Sui's 16 KiB pure-arg limit (~250 × 64B sigs).
    ///
    /// Defaults to 64.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc_signing_chunk_size: Option<usize>,

    /// Maximum number of mempool-only (0-confirmation) ancestors a UTXO may
    /// have and still be eligible as a coin-selection input. Constrains how
    /// deep the chain of unconfirmed transactions can grow, staying within
    /// Bitcoin's relay policy limits.
    ///
    /// Defaults to 5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_mempool_chain_depth: Option<usize>,

    /// Confirmation target (blocks) passed to `estimatesmartfee` when
    /// pricing withdrawal miner fees. Low-traffic chains (e.g. signet)
    /// need a high value (≥ 49) so Core's long-horizon estimator is used.
    ///
    /// Defaults to 3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal_fee_conf_target: Option<u16>,

    /// Interval (ms) between watcher polls of the on-chain Hashi config while
    /// the launch is pending — the safety net for `finish_publish`, which sets
    /// `guardian_url` and the guardian BTC key with no event. Polling stops
    /// once both are on-chain.
    ///
    /// Defaults to 300,000 ms (5 minutes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onchain_config_poll_interval_ms: Option<u64>,

    /// Test-only: corrupt AVSS shares sent to this address, triggering the
    /// complaint recovery flow. Must not be set on mainnet or testnet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_corrupt_shares_for: Option<Address>,

    /// Configure pushing Prometheus metrics out to a sui-proxy instance. When
    /// unset, the push task is not started and the only metrics surface is the
    /// local scrape endpoint at `metrics_http_address`.
    ///
    /// The push uses the same `tls_private_key` already registered on chain in
    /// `MemberInfo.tls_public_key`, so no additional credential setup is
    /// required for operators that have already completed hashi committee
    /// registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_push: Option<MetricsPushConfig>,
}

#[derive(Clone, Debug, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MetricsPushConfig {
    /// sui-proxy `/publish/metrics` URL (e.g. `https://metrics-proxy.testnet.example.com/publish/metrics`).
    pub push_url: String,

    /// How often to push. Defaults to 60s if unset (matches sui-node default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_interval_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ForceRunAsLeader {
    /// Use default leader selection, taking turns
    #[default]
    Default,
    /// Always run as leader
    Always,
    /// Never run as aleader
    Never,
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, anyhow::Error> {
        let file = std::fs::read(path)?;
        toml::from_slice(&file).map_err(Into::into)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), anyhow::Error> {
        let toml = toml::to_string(self)?;
        std::fs::write(path, toml).map_err(Into::into)
    }

    pub fn tls_private_key(&self) -> Result<ed25519_dalek::SigningKey, anyhow::Error> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let raw = self
            .tls_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no tls_private_key configured"))?;

        if let Ok(private_key) = ed25519_dalek::SigningKey::read_pkcs8_pem_file(raw) {
            Ok(private_key)
        } else if let Ok(private_key) = ed25519_dalek::SigningKey::read_pkcs8_der_file(raw) {
            Ok(private_key)
        } else if let Ok(private_key) = ed25519_dalek::SigningKey::from_pkcs8_pem(raw) {
            Ok(private_key)
        } else {
            // maybe some other format?
            Err(anyhow::anyhow!("unable to load tls_private_key"))
        }
    }

    pub fn tls_public_key(&self) -> Result<ed25519_dalek::VerifyingKey, anyhow::Error> {
        let tls_private_key = self.tls_private_key()?;

        Ok(ed25519_dalek::VerifyingKey::from(&tls_private_key))
    }

    /// Load the operator signing keypair from `operator-private-key`.
    ///
    /// The configured value may be a file path or an inline key; see
    /// [`crate::keys::load_keypair`] for the accepted formats.
    pub fn operator_private_key(&self) -> Result<SimpleKeypair, anyhow::Error> {
        let raw = self
            .operator_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no operator_private_key configured"))?;

        crate::keys::load_keypair(raw).context("unable to load the operator private key")
    }

    pub fn validator_address(&self) -> Result<Address, anyhow::Error> {
        self.validator_address
            .ok_or_else(|| anyhow::anyhow!("no validator address configured"))
    }

    pub fn listen_address(&self) -> SocketAddr {
        self.listen_address
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 443)))
    }

    pub fn endpoint_url(&self) -> Option<&str> {
        self.endpoint_url.as_deref()
    }

    pub fn metrics_http_address(&self) -> SocketAddr {
        self.metrics_http_address
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9180)))
    }

    pub fn sui_chain_id(&self) -> &str {
        self.sui_chain_id.as_deref().unwrap_or(SUI_MAINNET_CHAIN_ID)
    }

    pub fn bitcoin_chain_id(&self) -> &str {
        self.bitcoin_chain_id
            .as_deref()
            .unwrap_or(crate::constants::BITCOIN_MAINNET_CHAIN_ID)
    }

    pub fn bitcoin_network(&self) -> crate::btc_monitor::config::Network {
        crate::btc_monitor::config::network_from_chain_id(self.bitcoin_chain_id()).unwrap()
    }

    pub fn bitcoin_rpc(&self) -> &str {
        self.bitcoin_rpc
            .as_deref()
            .unwrap_or("http://localhost:8332")
    }

    pub fn bitcoin_start_height(&self) -> u32 {
        self.bitcoin_start_height.unwrap_or(800_000)
    }

    pub fn bitcoin_rpc_auth(&self) -> corepc_client::client_sync::Auth {
        self.bitcoin_rpc_auth
            .as_ref()
            .unwrap_or(&crate::btc_monitor::config::BtcRpcAuth::None)
            .to_corepc_auth()
    }

    /// Parse configured Bitcoin peer strings into kyoto trusted peers.
    /// Hostnames are not resolved here — kyoto resolves them at connection
    /// time, and the monitor's supervisor rebuilds the node on disconnect
    /// to re-resolve and follow IP changes (e.g., Kubernetes pod rotation).
    pub fn bitcoin_trusted_peers(&self) -> anyhow::Result<Vec<kyoto::TrustedPeer>> {
        let Some(peer_strs) = self.bitcoin_trusted_peers.as_ref() else {
            return Ok(Vec::new());
        };

        let mut peers = Vec::new();
        for s in peer_strs {
            let (host, port_str) = s.rsplit_once(':').ok_or_else(|| {
                anyhow::anyhow!("Invalid bitcoin peer '{s}': expected 'host:port' format")
            })?;
            let port = port_str
                .parse::<u16>()
                .map_err(|e| anyhow::anyhow!("Invalid port in bitcoin peer '{s}': {e}"))?;
            peers.push(kyoto::TrustedPeer::from_hostname(host, port));
        }
        Ok(peers)
    }

    pub fn hashi_ids(&self) -> HashiIds {
        // TODO fill in mainnet values once published
        self.hashi_ids.unwrap_or(HashiIds {
            package_id: Address::ZERO,
            hashi_object_id: Address::ZERO,
        })
    }

    pub fn force_run_as_leader(&self) -> ForceRunAsLeader {
        self.force_run_as_leader.clone().unwrap_or_default()
    }

    pub fn backup_dir(&self) -> &Path {
        self.backup_dir.as_deref().unwrap_or(Path::new("/tmp"))
    }

    pub fn test_weight_divisor(&self) -> u16 {
        self.test_weight_divisor.unwrap_or(1)
    }

    pub fn screener_endpoint(&self) -> Option<&str> {
        self.screener_endpoint.as_deref()
    }

    pub fn guardian_endpoint(&self) -> Option<&str> {
        self.guardian_endpoint.as_deref()
    }

    pub fn grpc_max_decoding_message_size(&self) -> usize {
        self.grpc_max_decoding_message_size
            .unwrap_or(DEFAULT_GRPC_MAX_DECODING_MESSAGE_SIZE)
    }

    pub fn max_concurrent_leader_job_tasks(&self) -> usize {
        self.max_concurrent_leader_job_tasks.unwrap_or(32)
    }

    pub fn withdrawal_batching_delay_ms(&self) -> u64 {
        self.withdrawal_batching_delay_ms.unwrap_or(300_000)
    }

    pub fn onchain_config_poll_interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(
            self.onchain_config_poll_interval_ms
                .unwrap_or(DEFAULT_ONCHAIN_CONFIG_POLL_INTERVAL_MS),
        )
    }

    pub fn withdrawal_max_batch_size(&self) -> usize {
        self.withdrawal_max_batch_size
            .unwrap_or(crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS)
            .min(crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS)
    }

    pub fn withdrawal_signing_concurrency(&self) -> usize {
        self.withdrawal_signing_concurrency
            .unwrap_or(DEFAULT_WITHDRAWAL_SIGNING_CONCURRENCY)
            .max(1)
    }

    pub fn mpc_signing_chunk_size(&self) -> usize {
        self.mpc_signing_chunk_size
            .unwrap_or(DEFAULT_MPC_SIGNING_CHUNK_SIZE)
            .max(1)
    }

    pub fn max_mempool_chain_depth(&self) -> usize {
        self.max_mempool_chain_depth
            .unwrap_or(crate::utxo_pool::CoinSelectionParams::DEFAULT_MAX_MEMPOOL_CHAIN_DEPTH)
    }

    pub fn withdrawal_fee_conf_target(&self) -> u16 {
        self.withdrawal_fee_conf_target.unwrap_or(3)
    }

    // Creates a new config suitable for testing. In particular this config will:
    // - have randomly generated private key material
    // - localhost only listen addresses using available ports
    pub fn new_for_testing() -> Self {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use std::ops::Deref;

        let mut config = Config::default();

        let tls_private_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        config.tls_private_key = Some(
            tls_private_key
                .to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
                .unwrap()
                .deref()
                .to_owned(),
        );

        let listen_addr = SocketAddr::from(([127, 0, 0, 1], get_available_port()));
        config.listen_address = Some(listen_addr);
        config.endpoint_url = Some(format!("https://{listen_addr}"));
        config.metrics_http_address =
            Some(SocketAddr::from(([127, 0, 0, 1], get_available_port())));

        config
    }
}

/// Relevant Onchain Ids for the hashi protocol.
#[derive(Debug, Clone, Copy, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HashiIds {
    /// The original package id of the `hashi` package.
    pub package_id: Address,
    /// Id of the main `Hashi` shared object.
    pub hashi_object_id: Address,
}

/// Return an ephemeral, available port. On unix systems, the port returned will be in the
/// TIME_WAIT state ensuring that the OS won't hand out this port for some grace period.
/// Callers should be able to bind to this port given they use SO_REUSEADDR.
pub fn get_available_port() -> u16 {
    const MAX_PORT_RETRIES: u32 = 1000;

    for _ in 0..MAX_PORT_RETRIES {
        if let Ok(port) = get_ephemeral_port() {
            return port;
        }
    }

    panic!("Error: could not find an available port on localhost");
}

fn get_ephemeral_port() -> std::io::Result<u16> {
    use std::net::TcpListener;
    use std::net::TcpStream;

    // Request a random available port from the OS
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let addr = listener.local_addr()?;

    // Create and accept a connection (which we'll promptly drop) in order to force the port
    // into the TIME_WAIT state, ensuring that the port will be reserved from some limited
    // amount of time (roughly 60s on some Linux systems)
    let _sender = TcpStream::connect(addr)?;
    let _incoming = listener.accept()?;

    Ok(addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_for_testing() {
        let config = Config::new_for_testing();
        let localhost = std::net::Ipv4Addr::new(127, 0, 0, 1);

        // Test addresses use localhost
        assert_eq!(config.listen_address().ip(), localhost);
        assert_eq!(config.metrics_http_address().ip(), localhost);

        // Test ports are different
        let listen_port = config.listen_address().port();
        let metrics_port = config.metrics_http_address().port();
        assert_ne!(listen_port, metrics_port);

        // Test endpoint_url is derived from listen_address
        let endpoint_url = config.endpoint_url().unwrap();
        assert_eq!(endpoint_url, format!("https://127.0.0.1:{listen_port}"));

        // Test TLS key is generated and valid PEM format
        assert!(config.tls_private_key.is_some());
        let tls_key = config.tls_private_key.as_ref().unwrap();
        assert!(tls_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(tls_key.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn backup_pgp_cert_accepts_file_path() {
        let dir = tempfile::Builder::new().tempdir().unwrap();
        let cert_path = dir.path().join("backup-cert.asc");
        let config_path = dir.path().join("config.toml");
        let (public_cert, _) = hashi_types::pgp::test_utils::mock_pgp_keypair();
        std::fs::write(&cert_path, &public_cert).unwrap();

        let mut config = toml::Table::new();
        config.insert(
            "backup-pgp-cert".to_string(),
            toml::Value::String(cert_path.to_string_lossy().into_owned()),
        );
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let config = Config::load(&config_path).unwrap();
        assert_eq!(
            config.backup_pgp_cert.unwrap().armored(),
            public_cert.as_str()
        );
    }

    #[test]
    fn backup_dir_uses_configured_path() {
        let config = Config {
            backup_dir: Some(PathBuf::from("/var/lib/hashi/backups")),
            ..Default::default()
        };
        assert_eq!(config.backup_dir(), Path::new("/var/lib/hashi/backups"));
    }

    #[test]
    fn rejects_unknown_root_field() {
        let error = toml::from_str::<Config>("databse = '/var/lib/hashi/db'")
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field `databse`"), "{error}");
    }

    #[test]
    fn rejects_root_field_nested_under_hashi_ids() {
        let address = Address::ZERO;
        let config = format!(
            "[hashi-ids]\npackage-id = '{address}'\nhashi-object-id = '{address}'\ndb = '/var/lib/hashi/db'\n"
        );

        let error = toml::from_str::<Config>(&config).unwrap_err().to_string();
        assert!(error.contains("unknown field `db`"), "{error}");
        assert!(
            error.contains("expected `package-id` or `hashi-object-id`"),
            "{error}"
        );
    }

    #[test]
    fn test_get_available_port_unique_ports() {
        let port1 = get_available_port();
        let port2 = get_available_port();
        assert_ne!(port1, port2, "Should return different ports");
    }

    #[test]
    fn test_withdrawal_max_batch_size_defaults_to_absolute_cap() {
        let config = Config::default();
        assert_eq!(
            config.withdrawal_max_batch_size(),
            crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS
        );
    }

    #[test]
    fn test_withdrawal_max_batch_size_clamps_to_absolute_cap() {
        let config = Config {
            withdrawal_max_batch_size: Some(200),
            ..Config::default()
        };
        assert_eq!(
            config.withdrawal_max_batch_size(),
            crate::utxo_pool::CoinSelectionParams::MAX_WITHDRAWAL_REQUESTS
        );
    }
}
