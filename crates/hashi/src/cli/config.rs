//! Configuration for the Hashi CLI
//!
//! Configuration can be loaded from a TOML file and/or environment variables.
//! CLI arguments take precedence over config file values.

use crate::config::load_ed25519_private_key_from_path;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use std::path::PathBuf;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

/// Bitcoin RPC and wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BitcoinConfig {
    /// Bitcoin Core RPC endpoint URL
    pub rpc_url: Option<String>,

    /// RPC authentication username
    pub rpc_user: Option<String>,

    /// RPC authentication password
    pub rpc_password: Option<String>,

    /// Bitcoin network: "regtest", "testnet4", or "mainnet"
    pub network: Option<String>,

    /// Path to a WIF-encoded private key file for BTC operations
    pub private_key_path: Option<PathBuf>,
}

/// CLI Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    /// Sui RPC endpoint URL
    #[serde(default = "default_sui_rpc_url")]
    pub sui_rpc_url: String,

    /// Hashi package ID (original package, used for type resolution)
    pub package_id: Option<Address>,

    /// Hashi shared object ID
    pub hashi_object_id: Option<Address>,

    /// Path to the keypair file for signing transactions
    pub keypair_path: Option<PathBuf>,

    /// Optional: Gas coin object ID to use for transactions
    pub gas_coin: Option<Address>,

    /// Optional Bitcoin configuration for deposit/withdrawal commands
    #[serde(default)]
    pub bitcoin: Option<BitcoinConfig>,
}

fn default_sui_rpc_url() -> String {
    "https://fullnode.mainnet.sui.io:443".to_string()
}

/// Default path for the CLI config file written by `hashi-localnet start`.
const DEFAULT_CONFIG_PATH: &str = ".hashi/localnet/hashi-cli.toml";

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            sui_rpc_url: default_sui_rpc_url(),
            package_id: None,
            hashi_object_id: None,
            keypair_path: None,
            gas_coin: None,
            bitcoin: None,
        }
    }
}

/// CLI overrides for Bitcoin configuration, from command-line flags.
#[derive(Default)]
pub struct BitcoinOverrides {
    pub rpc_url: Option<String>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub network: Option<String>,
    pub private_key: Option<PathBuf>,
}

impl CliConfig {
    /// Load configuration from file and CLI overrides.
    ///
    /// When no explicit config path is provided, checks for a default config
    /// file at `.hashi/localnet/hashi-cli.toml` (written by `hashi-localnet start`).
    pub fn load(
        config_path: Option<&Path>,
        sui_rpc_url: Option<String>,
        package_id: Option<String>,
        hashi_object_id: Option<String>,
        keypair_path: Option<PathBuf>,
        btc_overrides: BitcoinOverrides,
    ) -> Result<Self> {
        let default_path = PathBuf::from(DEFAULT_CONFIG_PATH);
        let mut config = if let Some(path) = config_path {
            Self::load_from_file(path)?
        } else if default_path.exists() {
            Self::load_from_file(&default_path)?
        } else {
            Self::default()
        };

        // Apply CLI overrides (these always win)
        if let Some(url) = sui_rpc_url {
            config.sui_rpc_url = url;
        }

        if let Some(id) = package_id {
            config.package_id = Some(
                Address::from_hex(&id).with_context(|| format!("Invalid package ID: {}", id))?,
            );
        }

        if let Some(id) = hashi_object_id {
            config.hashi_object_id = Some(
                Address::from_hex(&id)
                    .with_context(|| format!("Invalid Hashi object ID: {}", id))?,
            );
        }

        if let Some(path) = keypair_path {
            config.keypair_path = Some(path);
        }

        // Apply BTC overrides
        config.apply_btc_overrides(btc_overrides);

        Ok(config)
    }

    /// Load configuration from a TOML file
    fn load_from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
    }

    fn apply_btc_overrides(&mut self, overrides: BitcoinOverrides) {
        let has_overrides = overrides.rpc_url.is_some()
            || overrides.rpc_user.is_some()
            || overrides.rpc_password.is_some()
            || overrides.network.is_some()
            || overrides.private_key.is_some();

        if !has_overrides {
            return;
        }

        let btc = self.bitcoin.get_or_insert_with(BitcoinConfig::default);
        if let Some(url) = overrides.rpc_url {
            btc.rpc_url = Some(url);
        }
        if let Some(user) = overrides.rpc_user {
            btc.rpc_user = Some(user);
        }
        if let Some(password) = overrides.rpc_password {
            btc.rpc_password = Some(password);
        }
        if let Some(network) = overrides.network {
            btc.network = Some(network);
        }
        if let Some(key) = overrides.private_key {
            btc.private_key_path = Some(key);
        }
    }

    /// Generate a template configuration file
    pub fn generate_template() -> String {
        r#"# Hashi CLI Configuration
# ========================

# Sui RPC endpoint URL
# For mainnet: https://fullnode.mainnet.sui.io:443
# For testnet: https://fullnode.testnet.sui.io:443
sui_rpc_url = "https://fullnode.mainnet.sui.io:443"

# Hashi package ID (the original package address)
# This is used for resolving Move types
# package_id = "0x..."

# Hashi shared object ID
# This is the main Hashi shared object that holds state
# hashi_object_id = "0x..."

# Path to your keypair file for signing transactions (PEM or DER format)
# keypair_path = "/path/to/keypair.pem"

# Optional: Specific gas coin to use for transactions
# If not specified, the CLI will select an available SUI coin
# gas_coin = "0x..."

# [bitcoin]
# rpc_url = "http://127.0.0.1:18443"
# rpc_user = "test"
# rpc_password = "test"
# network = "regtest"
# private_key_path = "/path/to/btc.wif"
"#
        .to_string()
    }

    /// Validate that required configuration is present
    pub fn validate(&self) -> Result<()> {
        if self.package_id.is_none() {
            anyhow::bail!("package_id is required. Set it via --package-id or in the config file.");
        }
        if self.hashi_object_id.is_none() {
            anyhow::bail!(
                "hashi_object_id is required. Set it via --hashi-object-id or in the config file."
            );
        }
        Ok(())
    }

    /// Get the package ID, panics if not set
    pub fn package_id(&self) -> Address {
        self.package_id.expect("package_id not configured")
    }

    /// Get the Hashi object ID, panics if not set
    pub fn hashi_object_id(&self) -> Address {
        self.hashi_object_id
            .expect("hashi_object_id not configured")
    }

    /// Load the keypair from the configured path
    ///
    /// Returns `None` if no keypair path is configured.
    /// Returns an error if the path is configured but the keypair cannot be loaded.
    ///
    /// Uses the shared `load_ed25519_private_key_from_path` from the hashi crate,
    /// which supports DER and PEM formats.
    pub fn load_keypair(&self) -> Result<Option<Ed25519PrivateKey>> {
        let Some(ref path) = self.keypair_path else {
            return Ok(None);
        };

        let pk = load_ed25519_private_key_from_path(path)
            .with_context(|| format!("Failed to load keypair from {}", path.display()))?;

        Ok(Some(pk))
    }

    /// Get a Bitcoin RPC client from the config, if configured.
    pub fn btc_rpc_client(&self) -> Result<Option<bitcoincore_rpc::Client>> {
        let Some(ref btc) = self.bitcoin else {
            return Ok(None);
        };
        let Some(ref url) = btc.rpc_url else {
            return Ok(None);
        };

        let auth = match (&btc.rpc_user, &btc.rpc_password) {
            (Some(user), Some(pass)) => bitcoincore_rpc::Auth::UserPass(user.clone(), pass.clone()),
            _ => bitcoincore_rpc::Auth::None,
        };

        let client = bitcoincore_rpc::Client::new(url, auth)
            .with_context(|| format!("Failed to connect to Bitcoin RPC at {}", url))?;
        Ok(Some(client))
    }

    /// Require a Bitcoin RPC client, returning an error if not configured.
    pub fn require_btc_rpc_client(&self) -> Result<bitcoincore_rpc::Client> {
        self.btc_rpc_client()?.ok_or_else(|| {
            anyhow::anyhow!(
                "Bitcoin RPC not configured. Set [bitcoin] in your config file or use --btc-rpc-url"
            )
        })
    }

    /// Get the path to the config file this was loaded from, for in-place updates.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let contents = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write config to {}", path.display()))?;
        Ok(())
    }
}
