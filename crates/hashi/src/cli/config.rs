// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the Hashi CLI
//!
//! Configuration can be loaded from a TOML file and/or environment variables.
//! CLI arguments take precedence over config file values.

use crate::config::load_ed25519_private_key_from_path;
use age::plugin;
use age::x25519;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::fmt;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

impl FromStr for BackupRecipient {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(recipient) = x25519::Recipient::from_str(s) {
            return Ok(Self::Native(recipient));
        }
        match plugin::Recipient::from_str(s) {
            Ok(recipient) => Ok(Self::Plugin(recipient)),
            Err(plugin_err) => anyhow::bail!(
                "failed to parse age recipient '{s}': not a valid x25519 recipient, and not a valid plugin recipient ({plugin_err})"
            ),
        }
    }
}

impl fmt::Display for BackupRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(r) => write!(f, "{r}"),
            Self::Plugin(r) => write!(f, "{r}"),
        }
    }
}

impl fmt::Debug for BackupRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackupRecipient({self})")
    }
}

/// Bitcoin RPC and wallet configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BitcoinConfig {
    /// Bitcoin Core RPC endpoint URL
    pub rpc_url: Option<String>,

    /// RPC authentication username
    pub rpc_user: Option<String>,

    /// RPC authentication password
    pub rpc_password: Option<String>,

    /// Bitcoin network: "regtest", "testnet4", "signet", or "mainnet"
    pub network: Option<String>,

    /// Path to a WIF-encoded private key file for BTC operations
    pub private_key_path: Option<PathBuf>,
}

/// CLI Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    #[serde(skip)]
    pub loaded_from_path: Option<PathBuf>,

    /// Sui RPC endpoint URL
    #[serde(default = "default_sui_rpc_url")]
    pub sui_rpc_url: String,

    /// Hashi package ID (original package, used for type resolution)
    pub package_id: Option<Address>,

    /// Hashi shared object ID
    pub hashi_object_id: Option<Address>,

    /// Path to the keypair file for signing transactions
    pub keypair_path: Option<PathBuf>,

    /// Age recipient public key used for config backups.
    ///
    /// Accepts both native x25519 recipients and plugin recipients (e.g. YubiKey).
    #[serde(default, with = "optional_age_recipient")]
    pub backup_age_pubkey: Option<BackupRecipient>,

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
            loaded_from_path: None,
            sui_rpc_url: default_sui_rpc_url(),
            package_id: None,
            hashi_object_id: None,
            keypair_path: None,
            backup_age_pubkey: None,
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

        let mut config: Self = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        config.loaded_from_path = Some(path.to_path_buf());
        Ok(config)
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

# Age recipient public key used by `hashi config backup`
# backup_age_pubkey = "age1..."

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

    /// All file paths which must be backed up to enable full node recovery
    pub fn backup_file_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(path) = &self.loaded_from_path {
            paths.push(path.clone());
        }

        if let Some(path) = &self.keypair_path {
            paths.push(path.clone());
        }

        if let Some(bitcoin) = &self.bitcoin
            && let Some(path) = &bitcoin.private_key_path
        {
            paths.push(path.clone());
        }

        paths
    }

    /// Get a Bitcoin RPC client from the config, if configured.
    pub fn btc_rpc_client(&self) -> Result<Option<corepc_client::client_sync::v29::Client>> {
        let Some(ref btc) = self.bitcoin else {
            return Ok(None);
        };
        let Some(ref url) = btc.rpc_url else {
            return Ok(None);
        };

        let auth = match (&btc.rpc_user, &btc.rpc_password) {
            (Some(user), Some(pass)) => {
                corepc_client::client_sync::Auth::UserPass(user.clone(), pass.clone())
            }
            _ => corepc_client::client_sync::Auth::None,
        };

        let client = crate::btc_monitor::config::new_rpc_client(url, auth)
            .with_context(|| format!("Failed to connect to Bitcoin RPC at {}", url))?;
        Ok(Some(client))
    }

    /// Require a Bitcoin RPC client, returning an error if not configured.
    pub fn require_btc_rpc_client(&self) -> Result<corepc_client::client_sync::v29::Client> {
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

/// An age recipient that can be used as the target of a config backup.
///
/// Supports both native x25519 recipients (`age1...`) and plugin recipients
/// (`age1<plugin-name>1...`, e.g. `age1yubikey1...`). Plugin recipients are only
/// resolved against a plugin binary at encryption time, so storing one in the
/// config does not require the plugin to be installed.
#[derive(Clone)]
pub enum BackupRecipient {
    Native(x25519::Recipient),
    Plugin(plugin::Recipient),
}

mod optional_age_recipient {
    use super::BackupRecipient;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;
    use std::str::FromStr;

    pub fn serialize<S>(value: &Option<BackupRecipient>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(recipient) => serializer.serialize_some(&recipient.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<BackupRecipient>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| BackupRecipient::from_str(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}
