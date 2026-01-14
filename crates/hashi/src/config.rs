use std::net::SocketAddr;
use std::path::PathBuf;

use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::committee::EncryptionPublicKey;

#[derive(Clone, Debug, Default, serde_derive::Deserialize, serde_derive::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_private_key: Option<Bls12381PrivateKey>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_private_key: Option<EncryptionPrivateKey>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator_private_key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_address: Option<Address>,

    /// Configure the address to listen on for https
    ///
    /// Defaults to `0.0.0.0:443` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_address: Option<SocketAddr>,

    /// Configure the address to listen on for http
    ///
    /// Defaults to `0.0.0.0:80` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_address: Option<SocketAddr>,

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
    pub bitcoin_rpc_auth: Option<hashi_btc::config::BtcRpcAuth>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_confirmation_threshold: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bitcoin_start_height: Option<u32>,

    /// Database path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db: Option<PathBuf>,

    /// Force validator to run as leader, or never run as leader
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_run_as_leader: Option<ForceRunAsLeader>,
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

    pub fn protocol_private_key(&self) -> Option<Bls12381PrivateKey> {
        self.protocol_private_key.clone()
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

    pub fn encryption_private_key(&self) -> Result<EncryptionPrivateKey, anyhow::Error> {
        self.encryption_private_key
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no encryption_private_key configured"))
    }

    pub fn encryption_public_key(&self) -> Result<EncryptionPublicKey, anyhow::Error> {
        let encryption_private_key = self.encryption_private_key()?;

        Ok(EncryptionPublicKey::from_private_key(
            &encryption_private_key,
        ))
    }

    //TODO support more than just Ed25519
    pub fn operator_private_key(&self) -> Result<Ed25519PrivateKey, anyhow::Error> {
        let raw = self
            .operator_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no operator_private_key configured"))?;

        if let Ok(private_key) = std::fs::read(raw) {
            if let Ok(pk) = Ed25519PrivateKey::from_der(&private_key) {
                return Ok(pk);
            }

            if let Some(pk) = std::str::from_utf8(&private_key)
                .ok()
                .and_then(|pk| Ed25519PrivateKey::from_pem(pk).ok())
            {
                return Ok(pk);
            }
        }

        if let Ok(private_key) = Ed25519PrivateKey::from_pem(raw) {
            return Ok(private_key);
        }

        // maybe some other format?
        Err(anyhow::anyhow!("unable to load operator_private_key"))
    }

    pub fn validator_address(&self) -> Result<Address, anyhow::Error> {
        self.validator_address
            .ok_or_else(|| anyhow::anyhow!("no validator address configured"))
    }

    pub fn https_address(&self) -> SocketAddr {
        self.https_address
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 443)))
    }

    pub fn http_address(&self) -> SocketAddr {
        self.http_address
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 80)))
    }

    pub fn metrics_http_address(&self) -> SocketAddr {
        self.metrics_http_address
            .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 9180)))
    }

    pub fn sui_chain_id(&self) -> &str {
        self.sui_chain_id
            .as_deref()
            .unwrap_or("4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S")
    }

    pub fn bitcoin_chain_id(&self) -> &str {
        self.bitcoin_chain_id
            .as_deref()
            .unwrap_or("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
    }

    pub fn bitcoin_network(&self) -> hashi_btc::config::Network {
        hashi_btc::config::network_from_chain_id(self.bitcoin_chain_id()).unwrap()
    }

    pub fn bitcoin_rpc(&self) -> &str {
        self.bitcoin_rpc
            .as_deref()
            .unwrap_or("http://localhost:8332")
    }

    pub fn bitcoin_confirmation_threshold(&self) -> u32 {
        self.bitcoin_confirmation_threshold.unwrap_or(6)
    }

    pub fn bitcoin_start_height(&self) -> u32 {
        self.bitcoin_start_height.unwrap_or(800_000)
    }

    pub fn bitcoin_rpc_auth(&self) -> hashi_btc::config::bitcoincore_rpc::Auth {
        self.bitcoin_rpc_auth
            .as_ref()
            .unwrap_or(&hashi_btc::config::BtcRpcAuth::None)
            .to_bitcoincore_rpc_auth()
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

        config.protocol_private_key = Some(Bls12381PrivateKey::generate(&mut rand::thread_rng()));
        config.encryption_private_key = Some(EncryptionPrivateKey::new(&mut rand::thread_rng()));

        config.https_address = Some(SocketAddr::from(([127, 0, 0, 1], get_available_port())));
        config.http_address = Some(SocketAddr::from(([127, 0, 0, 1], get_available_port())));
        config.metrics_http_address =
            Some(SocketAddr::from(([127, 0, 0, 1], get_available_port())));

        config
    }
}

/// Relevant Onchain Ids for the hashi protocol.
#[derive(Debug, Clone, Copy, serde_derive::Deserialize, serde_derive::Serialize)]
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
        assert_eq!(config.https_address().ip(), localhost);
        assert_eq!(config.http_address().ip(), localhost);
        assert_eq!(config.metrics_http_address().ip(), localhost);

        // Test ports are different
        let https_port = config.https_address().port();
        let http_port = config.http_address().port();
        let metrics_port = config.metrics_http_address().port();
        assert_ne!(https_port, http_port);
        assert_ne!(https_port, metrics_port);
        assert_ne!(http_port, metrics_port);

        // Test TLS key is generated and valid PEM format
        assert!(config.tls_private_key.is_some());
        let tls_key = config.tls_private_key.as_ref().unwrap();
        assert!(tls_key.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(tls_key.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn test_get_available_port_unique_ports() {
        let port1 = get_available_port();
        let port2 = get_available_port();
        assert_ne!(port1, port2, "Should return different ports");
    }
}
