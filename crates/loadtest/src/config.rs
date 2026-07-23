// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Working out which deployment to drive, and how.
//!
//! Package and object ids move on every full redeploy, and a hand-maintained
//! env file goes stale silently: the superseded Hashi object still exists and
//! still accepts deposits, so a run against stale ids looks like it works while
//! testing nothing. Ids are therefore read from a running pod's `config.toml`
//! by default, and cross-checked when they are supplied explicitly.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::Args;
use hashi::btc_monitor::config::parse_btc_network;
use hashi::cli::config::BitcoinOverrides;
use hashi::cli::config::CliConfig;
use serde::Deserialize;
use serde_json::Value;
use sui_sdk_types::Address;

use crate::bridge::Bridge;

/// Settings shared by every subcommand.
///
/// Split in two so `--help` reads as coherent groups rather than one list
/// interleaved with the per-run knobs.
#[derive(Args, Debug, Clone)]
pub struct CommonOpts {
    #[command(flatten)]
    pub deployment: DeploymentOpts,

    #[command(flatten)]
    pub bitcoin: BitcoinOpts,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Deployment")]
pub struct DeploymentOpts {
    /// Kubernetes namespace to read the deployment's ids from
    #[arg(long, default_value = "hashi-devnet", global = true)]
    pub namespace: String,

    /// Pod to read `config.toml` from
    #[arg(long, default_value = "hashi-server-0", global = true)]
    pub pod: String,

    /// Hashi Move package id [default: read from the cluster]
    #[arg(long, env = "HASHI_PACKAGE_ID", global = true)]
    pub package_id: Option<String>,

    /// Hashi shared object id [default: read from the cluster]
    #[arg(long, env = "HASHI_OBJECT_ID", global = true)]
    pub hashi_object_id: Option<String>,

    /// Sui RPC URL [default: read from the cluster]
    #[arg(long, env = "SUI_RPC_URL", global = true)]
    pub sui_rpc_url: Option<String>,

    /// Sui address that receives hBTC and signs [default: `sui client active-address`]
    #[arg(long, env = "SUI_ADDR", global = true)]
    pub sui_address: Option<String>,

    /// Signing key file: PKCS#8 PEM/DER, a `suiprivkey1...` line, or a keystore entry
    #[arg(long, short = 'k', env = "HASHI_KEYPAIR", global = true)]
    pub keypair: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Bitcoin")]
pub struct BitcoinOpts {
    /// Bitcoin network: mainnet, testnet4, signet or regtest
    #[arg(long, env = "BTC_NETWORK", default_value = "signet", global = true)]
    pub btc_network: String,

    /// Bitcoin Core RPC URL
    #[arg(
        long,
        env = "BTC_RPC_URL",
        default_value = "http://127.0.0.1:38332",
        global = true
    )]
    pub btc_rpc_url: String,

    /// Bitcoin Core RPC username
    #[arg(long, env = "BTC_RPC_USER", global = true)]
    pub btc_rpc_user: Option<String>,

    /// Bitcoin Core RPC password
    #[arg(long, env = "BTC_RPC_PASSWORD", global = true)]
    pub btc_rpc_password: Option<String>,

    /// Bitcoin Core wallet holding the funding UTXOs
    #[arg(long, env = "BTC_WALLET", default_value = "mining", global = true)]
    pub btc_wallet: String,
}

/// Fully resolved settings for a run.
pub struct Resolved {
    pub package_id: Address,
    pub hashi_object_id: Address,
    pub sui_address: Address,
    pub sui_rpc_url: String,
    pub btc_network: bitcoin::Network,
    pub btc_rpc_url: String,
    pub btc_rpc_user: String,
    pub btc_rpc_password: String,
    pub btc_wallet: String,
    pub namespace: String,
    /// What the cluster reported, when it was reachable. Kept so preflight can
    /// cross-check ids and genesis without a second `kubectl exec`.
    pub cluster: Option<ClusterInfo>,
    /// True when an id actually came from the cluster rather than a flag.
    pub discovered_from_k8s: bool,
    cli_config: CliConfig,
}

impl Resolved {
    pub fn bridge(&self) -> Result<Bridge> {
        Bridge::new(self.cli_config.clone(), self.btc_network)
    }
}

/// The subset of a node's `config.toml` worth reading.
#[derive(Debug, Deserialize)]
struct PodConfig {
    #[serde(rename = "hashi-ids")]
    hashi_ids: PodHashiIds,
    #[serde(rename = "sui-rpc")]
    sui_rpc: Option<String>,
    #[serde(rename = "bitcoin-chain-id")]
    bitcoin_chain_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodHashiIds {
    #[serde(rename = "package-id")]
    package_id: String,
    #[serde(rename = "hashi-object-id")]
    hashi_object_id: String,
}

/// What the cluster says, for cross-checking against local state.
#[derive(Debug, Clone)]
pub struct ClusterInfo {
    pub package_id: String,
    pub hashi_object_id: String,
    pub sui_rpc: Option<String>,
    pub bitcoin_chain_id: Option<String>,
}

pub fn read_cluster_config(namespace: &str, pod: &str) -> Result<ClusterInfo> {
    let out = Command::new("kubectl")
        .args([
            "-n",
            namespace,
            "exec",
            pod,
            "-c",
            "hashi",
            "--",
            "cat",
            "/opt/hashi/config/config.toml",
        ])
        .output()
        .context("failed to run kubectl; is it installed and on PATH?")?;
    if !out.status.success() {
        bail!(
            "kubectl exec {namespace}/{pod} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let cfg: PodConfig = toml::from_str(&String::from_utf8_lossy(&out.stdout))
        .with_context(|| format!("failed to parse config.toml from {namespace}/{pod}"))?;
    Ok(ClusterInfo {
        package_id: cfg.hashi_ids.package_id,
        hashi_object_id: cfg.hashi_ids.hashi_object_id,
        sui_rpc: cfg.sui_rpc,
        bitcoin_chain_id: cfg.bitcoin_chain_id,
    })
}

fn sui_active_address() -> Result<String> {
    let out = Command::new("sui")
        .args(["client", "active-address"])
        .output()
        .context("failed to run `sui`; pass --sui-address instead")?;
    if !out.status.success() {
        bail!("`sui client active-address` failed; pass --sui-address instead");
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

impl CommonOpts {
    /// Resolve every setting, reading the cluster once and using it both to
    /// fill in what was not given and to cross-check what was.
    pub fn resolve(&self) -> Result<Resolved> {
        let d = &self.deployment;
        let b = &self.bitcoin;

        let needs_cluster =
            d.package_id.is_none() || d.hashi_object_id.is_none() || d.sui_rpc_url.is_none();

        let cluster = match read_cluster_config(&d.namespace, &d.pod) {
            Ok(c) => Some(c),
            // Only fatal when the cluster is the only source for an id.
            Err(e) if needs_cluster => {
                return Err(e.context(
                    "could not read the deployment's ids from the cluster; pass --package-id, \
                     --hashi-object-id and --sui-rpc-url explicitly to work without kubectl",
                ));
            }
            Err(_) => None,
        };

        let package_id = d
            .package_id
            .clone()
            .or_else(|| cluster.as_ref().map(|c| c.package_id.clone()))
            .ok_or_else(|| anyhow!("no package id"))?;
        let hashi_object_id = d
            .hashi_object_id
            .clone()
            .or_else(|| cluster.as_ref().map(|c| c.hashi_object_id.clone()))
            .ok_or_else(|| anyhow!("no hashi object id"))?;
        let sui_rpc_url = d
            .sui_rpc_url
            .clone()
            .or_else(|| cluster.as_ref().and_then(|c| c.sui_rpc.clone()))
            .ok_or_else(|| anyhow!("no sui rpc url; pass --sui-rpc-url"))?;

        let sui_address_raw = match &d.sui_address {
            Some(a) => a.clone(),
            None => sui_active_address()?,
        };
        let sui_address = sui_address_raw
            .parse::<Address>()
            .with_context(|| format!("invalid --sui-address `{sui_address_raw}`"))?;

        let keypair = d.keypair.clone().ok_or_else(|| {
            anyhow!(
                "no signing key: pass --keypair (or set HASHI_KEYPAIR).\nExport one with:\n  \
                 sui keytool export --key-identity {sui_address} --json | jq -r \
                 .exportedPrivateKey > signer.key"
            )
        })?;
        if !keypair.exists() {
            bail!("keypair file {} does not exist", keypair.display());
        }

        let btc_rpc_user = b
            .btc_rpc_user
            .clone()
            .ok_or_else(|| anyhow!("no --btc-rpc-user (or BTC_RPC_USER)"))?;
        let btc_rpc_password = b
            .btc_rpc_password
            .clone()
            .ok_or_else(|| anyhow!("no --btc-rpc-password (or BTC_RPC_PASSWORD)"))?;
        let btc_network = parse_btc_network(Some(&b.btc_network))?;

        // Build the CLI's own config so the bridge side behaves exactly as
        // `hashi <subcommand>` would. Every field is supplied, so the CLI's
        // default config file cannot influence a run.
        let cli_config = CliConfig::load(
            None,
            Some(sui_rpc_url.clone()),
            Some(package_id.clone()),
            Some(hashi_object_id.clone()),
            Some(keypair),
            BitcoinOverrides {
                rpc_url: Some(b.btc_rpc_url.clone()),
                rpc_user: Some(btc_rpc_user.clone()),
                rpc_password: Some(btc_rpc_password.clone()),
                network: Some(b.btc_network.clone()),
                private_key: None,
            },
        )?;

        Ok(Resolved {
            package_id: package_id
                .parse()
                .with_context(|| format!("invalid package id `{package_id}`"))?,
            hashi_object_id: hashi_object_id
                .parse()
                .with_context(|| format!("invalid hashi object id `{hashi_object_id}`"))?,
            sui_address,
            sui_rpc_url,
            btc_network,
            btc_rpc_url: b.btc_rpc_url.clone(),
            btc_rpc_user,
            btc_rpc_password,
            btc_wallet: b.btc_wallet.clone(),
            namespace: d.namespace.clone(),
            cluster,
            // The cluster is read whenever reachable; this is only true when an
            // id actually came from it.
            discovered_from_k8s: needs_cluster,
            cli_config,
        })
    }
}

/// The Hashi object's onchain config map.
///
/// These override the code defaults and are what the committee actually
/// enforces, so a run reads them rather than assuming: an amount below
/// `bitcoin_withdrawal_minimum`, or a paused bridge, rejects every request —
/// and by then the deposits are funded.
#[derive(Debug, Default)]
pub struct OnchainConfig(BTreeMap<String, Value>);

impl OnchainConfig {
    /// Best-effort read via the `sui` CLI. `None` means "could not read", and
    /// callers degrade to skipping the check rather than failing.
    pub fn read(hashi_object_id: Address) -> Option<Self> {
        let out = Command::new("sui")
            .args(["client", "object", &hashi_object_id.to_string(), "--json"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let json: Value = serde_json::from_slice(&out.stdout).ok()?;
        let mut entries = BTreeMap::new();
        collect_vecmap(&json, &mut entries);
        (!entries.is_empty()).then_some(Self(entries))
    }

    /// Values are enum-wrapped (`{"@variant": "U64", "pos0": "123"}`) and Sui
    /// renders u64 as a string.
    pub fn u64(&self, key: &str) -> Option<u64> {
        match self.0.get(key)? {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.0.get(key)?.as_bool()
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.as_str()
    }
}

/// Walk the object JSON collecting every `{key, value: {@variant, pos0}}` pair.
/// Walking rather than modelling keeps this working across object-layout
/// changes; only the VecMap entry shape has to hold.
fn collect_vecmap(v: &Value, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Object(map) => {
            if let (Some(Value::String(k)), Some(value)) = (map.get("key"), map.get("value"))
                && let Some(inner) = unwrap_variant(value)
            {
                out.insert(k.clone(), inner.clone());
            }
            map.values().for_each(|child| collect_vecmap(child, out));
        }
        Value::Array(items) => items.iter().for_each(|child| collect_vecmap(child, out)),
        _ => {}
    }
}

fn unwrap_variant(v: &Value) -> Option<&Value> {
    match v {
        Value::Object(map) if map.contains_key("@variant") => map.get("pos0"),
        other => Some(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_config_entries_out_of_the_object_json() {
        // Shape as `sui client object --json` renders it: VecMap entries nested
        // under the object contents, values wrapped in an enum variant, and u64
        // rendered as a string.
        let json = serde_json::json!({
            "content": { "config": { "config": { "contents": [
                { "key": "paused", "value": { "@variant": "Bool", "pos0": false } },
                { "key": "bitcoin_withdrawal_minimum",
                  "value": { "@variant": "U64", "pos0": "30000" } },
                { "key": "guardian_url",
                  "value": { "@variant": "String", "pos0": "https://g.example" } },
            ]}}}
        });
        let mut entries = BTreeMap::new();
        collect_vecmap(&json, &mut entries);
        let cfg = OnchainConfig(entries);

        assert_eq!(cfg.bool("paused"), Some(false));
        assert_eq!(cfg.u64("bitcoin_withdrawal_minimum"), Some(30_000));
        assert_eq!(cfg.string("guardian_url"), Some("https://g.example"));
        assert_eq!(cfg.u64("absent"), None);
    }
}
