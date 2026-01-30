//! Configuration for the Hashi CLI
//!
//! Configuration can be loaded from a TOML file and/or environment variables.
//! CLI arguments take precedence over config file values.

use anyhow::Context;
use anyhow::Result;
use hashi::config::load_ed25519_private_key_from_path;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

/// CLI Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Sui RPC endpoint URL
    #[serde(default = "default_sui_rpc_url")]
    pub sui_rpc_url: String,

    /// Hashi package ID (original package, used for type resolution)
    pub package_id: Option<Address>,

    /// Hashi shared object ID
    pub hashi_object_id: Option<Address>,

    /// Path to the keypair file for signing transactions
    pub keypair_path: Option<std::path::PathBuf>,

    /// Optional: Gas coin object ID to use for transactions
    pub gas_coin: Option<Address>,
}

fn default_sui_rpc_url() -> String {
    "https://fullnode.mainnet.sui.io:443".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sui_rpc_url: default_sui_rpc_url(),
            package_id: None,
            hashi_object_id: None,
            keypair_path: None,
            gas_coin: None,
        }
    }
}

impl Config {
    /// Load configuration from file and CLI overrides
    pub fn load(
        config_path: Option<&Path>,
        sui_rpc_url: Option<String>,
        package_id: Option<String>,
        hashi_object_id: Option<String>,
        keypair_path: Option<std::path::PathBuf>,
    ) -> Result<Self> {
        // Start with default config
        let mut config = if let Some(path) = config_path {
            Self::load_from_file(path)?
        } else {
            Self::default()
        };

        // Apply CLI overrides
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

        Ok(config)
    }

    /// Load configuration from a TOML file
    fn load_from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))
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

# Path to your keypair file for signing transactions
# Supports: Sui keystore format, or raw private key
# keypair_path = "/path/to/keypair.json"

# Optional: Specific gas coin to use for transactions
# If not specified, the CLI will select an available SUI coin
# gas_coin = "0x..."
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
}
