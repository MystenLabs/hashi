// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What the containers share: the network endpoints, the key material baked
//! into the config image at genesis, and the files the bootstrap hands to
//! everyone else through the shared volume.

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use corepc_client::client_sync::Auth;
use corepc_client::client_sync::v29::Client as BtcClient;
use serde::Deserialize;
use serde::Serialize;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_sdk_types::Address;

pub const WALLET_NAME: &str = "test";
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(clap::Args, Clone)]
pub struct CommonArgs {
    #[arg(long, env = "SUI_RPC_URL", default_value = "http://fullnode:9000")]
    pub sui_rpc: String,

    #[arg(long, env = "BTC_RPC_URL", default_value = "http://bitcoind:18443")]
    pub btc_rpc: String,

    #[arg(long, env = "BTC_RPC_USER", default_value = "test")]
    pub btc_rpc_user: String,

    #[arg(long, env = "BTC_RPC_PASSWORD", default_value = "test")]
    pub btc_rpc_password: String,

    #[arg(long, env = "GUARDIAN_URL", default_value = "http://guardian:3000")]
    pub guardian_url: String,

    /// Key material generated alongside the Sui genesis.
    #[arg(
        long,
        env = "HASHI_ENV_FILE",
        default_value = "/genesis/hashi-env.yaml"
    )]
    pub env_file: PathBuf,

    /// Volume through which the bootstrap hands out the deployment and node configs.
    #[arg(long, env = "SHARED_DIR", default_value = "/shared")]
    pub shared_dir: PathBuf,
}

impl CommonArgs {
    pub fn shared(&self) -> Shared {
        Shared {
            dir: self.shared_dir.clone(),
        }
    }

    pub fn btc_auth(&self) -> Auth {
        Auth::UserPass(self.btc_rpc_user.clone(), self.btc_rpc_password.clone())
    }

    /// A client bound to the shared wallet; node-level RPCs work through it too.
    pub fn btc_wallet(&self) -> Result<BtcClient> {
        Ok(BtcClient::new_with_auth(
            &format!("{}/wallet/{WALLET_NAME}", self.btc_rpc),
            self.btc_auth(),
        )?)
    }
}

/// `hashi-env.yaml`, written by the config image's genesis generator.
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct EnvFile {
    /// Sui keystore encoding (base64 of flag || seed) of the genesis-funded account.
    pub funded_account_key: String,
    pub validators: Vec<ValidatorEntry>,
    /// Hex secp256k1 secret for the test guardian's BTC key.
    pub guardian_btc_secret_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ValidatorEntry {
    /// Hostname of the hashi node container (e.g. `hashi1`).
    pub hashi_host: String,
    /// Sui keystore encoding of the validator's account key, which is also the
    /// hashi operator key.
    pub account_key: String,
}

impl EnvFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw =
            std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        Ok(serde_yaml::from_slice(&raw)?)
    }

    pub fn funded_key(&self) -> Result<Ed25519PrivateKey> {
        parse_sui_key(&self.funded_account_key)
    }

    pub fn guardian_btc_keypair(&self) -> Result<bitcoin::secp256k1::Keypair> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        bitcoin::secp256k1::Keypair::from_seckey_str(&secp, &self.guardian_btc_secret_key)
            .context("invalid guardian-btc-secret-key")
    }
}

impl ValidatorEntry {
    pub fn key(&self) -> Result<Ed25519PrivateKey> {
        parse_sui_key(&self.account_key)
    }
}

fn parse_sui_key(b64: &str) -> Result<Ed25519PrivateKey> {
    Ed25519PrivateKey::from_base64(b64).map_err(|e| anyhow::anyhow!("invalid sui key: {e}"))
}

/// Deployment facts that only exist once the bootstrap has published hashi.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct Deployment {
    pub package_id: Address,
    pub hashi_object_id: Address,
    pub sui_chain_id: String,
}

impl Deployment {
    pub fn hashi_ids(&self) -> hashi::config::HashiIds {
        hashi::config::HashiIds {
            package_id: self.package_id,
            hashi_object_id: self.hashi_object_id,
        }
    }
}

pub struct Shared {
    dir: PathBuf,
}

impl Shared {
    fn deployment_path(&self) -> PathBuf {
        self.dir.join("deployment.json")
    }

    /// The hashi node containers wait for this file and then run `hashi server` on it.
    pub fn node_config_path(&self, hashi_host: &str) -> PathBuf {
        self.dir.join(format!("{hashi_host}.toml"))
    }

    pub fn bootstrap_done_path(&self) -> PathBuf {
        self.dir.join("bootstrap.done")
    }

    pub fn write_deployment(&self, deployment: &Deployment) -> Result<()> {
        write_atomic(
            &self.deployment_path(),
            &serde_json::to_vec_pretty(deployment)?,
        )
    }

    pub async fn wait_for_deployment(&self) -> Result<Deployment> {
        let path = self.deployment_path();
        wait_for_file(&path).await;
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }
}

/// Readers poll for these files, so they must never observe a partial write.
pub fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub async fn wait_for_file(path: &Path) {
    let mut logged = false;
    while !path.exists() {
        if !logged {
            tracing::info!("waiting for {}", path.display());
            logged = true;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Retry `f` every [`POLL_INTERVAL`] until it succeeds, logging failures now and then.
pub async fn retry<T, F, Fut>(what: &str, mut f: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempt: u64 = 0;
    loop {
        match f().await {
            Ok(value) => return value,
            Err(e) => {
                if attempt.is_multiple_of(10) {
                    tracing::info!("{what} not ready yet (attempt {attempt}): {e:#}");
                }
                attempt += 1;
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }
}

/// Load, or on first use create, the shared wallet. bitcoind forgets loaded
/// wallets when it restarts, so callers re-run this after wallet RPC errors.
pub fn ensure_wallet(common: &CommonArgs) -> Result<()> {
    let node = BtcClient::new_with_auth(&common.btc_rpc, common.btc_auth())?;
    if node.load_wallet(WALLET_NAME).is_err() {
        // Either already loaded or never created; creating covers the latter
        // and fails harmlessly for the former.
        let _ = node.create_wallet(WALLET_NAME);
    }
    common.btc_wallet()?.get_balance()?;
    Ok(())
}

pub async fn wait_for_sui(client: &mut sui_rpc::Client) -> Result<String> {
    Ok(retry("sui fullnode", || {
        let mut client = client.clone();
        async move {
            let info = client
                .ledger_client()
                .get_service_info(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::default())
                .await?
                .into_inner();
            anyhow::ensure!(info.checkpoint_height() > 1, "no checkpoints produced yet");
            Ok(info.chain_id().to_owned())
        }
    })
    .await)
}

/// A read-only, self-updating view of the hashi on-chain state. The returned
/// service keeps it in sync and must be held for as long as the view is used.
pub async fn onchain_view(
    sui_rpc: &str,
    deployment: &Deployment,
) -> (hashi::onchain::OnchainState, sui_futures::service::Service) {
    retry("hashi on-chain state", || {
        hashi::onchain::OnchainState::new(sui_rpc, deployment.hashi_ids(), None, None, None)
    })
    .await
}

/// True once genesis DKG has produced a committee and MPC key and no
/// reconfiguration is in flight.
pub fn committee_ready(onchain: &hashi::onchain::OnchainState) -> bool {
    onchain.current_committee().is_some()
        && !onchain.mpc_public_key().is_empty()
        && onchain
            .state()
            .hashi()
            .committees
            .pending_epoch_change()
            .is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the formats `docker/antithesis/config/genesis/generate.py` writes:
    /// the key encoding, and the address it funds at genesis for that key.
    #[test]
    fn env_file_matches_genesis_generator() {
        let env: EnvFile = serde_yaml::from_str(
            "funded-account-key: AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n\
             validators:\n\
             - name: validator1\n  \
               hashi-host: hashi1\n  \
               account-key: AAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH\n\
             guardian-btc-secret-key: 0707070707070707070707070707070707070707070707070707070707070707\n",
        )
        .unwrap();
        let expected: Address =
            "0xa0ccc8bcc83f6c628340134f8546a21e0618fd1aaa02432bba454c4a2c2233da"
                .parse()
                .unwrap();
        assert_eq!(
            env.funded_key().unwrap().public_key().derive_address(),
            expected
        );
        assert_eq!(
            env.validators[0]
                .key()
                .unwrap()
                .public_key()
                .derive_address(),
            expected
        );
        env.guardian_btc_keypair().unwrap();
    }
}
