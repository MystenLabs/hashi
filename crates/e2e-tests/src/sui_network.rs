// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use hashi::config::get_available_port;
use std::collections::BTreeMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Argument;
use sui_sdk_types::GasPayment;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::SharedInput;
use sui_sdk_types::StructTag;
use sui_sdk_types::Transaction;
use sui_sdk_types::TransactionExpiration;
use sui_sdk_types::TransactionKind;
use sui_sdk_types::TransferObjects;
use sui_sdk_types::bcs::ToBcs;
use tokio::time::Duration;
use tokio::time::sleep;

const DEFAULT_NUM_VALIDATORS: usize = 4;
const DEFAULT_EPOCH_DURATION_MS: u64 = 86_400_000; // 24 hours; tests that need epoch changes should set a shorter duration
const MAX_NETWORK_STARTUP_ATTEMPTS: usize = 5;
const NETWORK_STARTUP_LOCK_FILE: &str = "hashi-e2e-sui-startup.lock";
const NETWORK_STARTUP_TIMEOUT_SECS: u64 = 120;
const NETWORK_STARTUP_POLL_INTERVAL_SECS: u64 = 1;

pub fn sui_binary() -> &'static Path {
    static SUI_BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    SUI_BINARY
        .get_or_init(|| {
            if let Ok(path) = std::env::var("SUI_BINARY") {
                return PathBuf::from(path);
            }
            if let Ok(output) = Command::new("which").arg("sui").output()
                && output.status.success()
            {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !path.is_empty() {
                    return PathBuf::from(path);
                }
            }
            panic!("sui binary not found. Please install sui or set SUI_BINARY env var")
        })
        .as_path()
}

#[derive(Debug)]
enum NetworkStartupError {
    AddressInUse(String),
    Failed(String),
}

impl std::fmt::Display for NetworkStartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddressInUse(diagnostics) => {
                write!(f, "Sui network failed to bind a port. {diagnostics}")
            }
            Self::Failed(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for NetworkStartupError {}

async fn acquire_startup_lock() -> Result<File> {
    let path = std::env::temp_dir().join(NETWORK_STARTUP_LOCK_FILE);
    tokio::task::spawn_blocking(move || {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open Sui startup lock {}", path.display()))?;
        file.lock()
            .with_context(|| format!("lock Sui startup lock {}", path.display()))?;
        Ok(file)
    })
    .await
    .context("join Sui startup lock task")?
}

async fn wait_for_ready(
    client: &mut Client,
    process: &mut Child,
    dir: &Path,
) -> std::result::Result<(), NetworkStartupError> {
    // Wait till the network has started up and at least one checkpoint has been produced.
    for _ in 0..NETWORK_STARTUP_TIMEOUT_SECS {
        if let Some(diagnostics) = address_in_use_diagnostics(dir) {
            return Err(NetworkStartupError::AddressInUse(diagnostics));
        }
        match process.try_wait() {
            Ok(Some(status)) => {
                return Err(NetworkStartupError::Failed(format!(
                    "Sui network exited during startup with {status}. {}",
                    startup_diagnostics(dir),
                )));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(NetworkStartupError::Failed(format!(
                    "Failed to inspect Sui network process: {error}. {}",
                    startup_diagnostics(dir),
                )));
            }
        }
        if let Ok(resp) = client
            .ledger_client()
            .get_service_info(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::default())
            .await
            && resp.into_inner().checkpoint_height() > 1
        {
            return Ok(());
        }
        sleep(Duration::from_secs(NETWORK_STARTUP_POLL_INTERVAL_SECS)).await;
    }
    Err(NetworkStartupError::Failed(format!(
        "Network failed to start within {}s timeout. {}",
        NETWORK_STARTUP_TIMEOUT_SECS,
        startup_diagnostics(dir),
    )))
}

fn address_in_use_diagnostics(dir: &Path) -> Option<String> {
    let stderr = std::fs::read_to_string(dir.join("out.stderr")).ok()?;
    stderr
        .contains("Address already in use")
        .then(|| startup_diagnostics(dir))
}

fn startup_diagnostics(dir: &Path) -> String {
    crate::tail_logs(&[
        ("stderr", &dir.join("out.stderr")),
        ("stdout", &dir.join("out.stdout")),
    ])
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child guard is armed")
    }

    fn disarm(mut self) -> Child {
        self.child.take().expect("child guard is armed")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            terminate_child(child);
        }
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Handle for a Sui network running via pre-compiled binary
pub struct SuiNetworkHandle {
    /// Child process running sui
    process: Child,

    /// Temporary directory for config (auto-cleanup on drop)
    pub dir: PathBuf,

    /// Network endpoints
    pub rpc_url: String,
    pub client: Client,

    /// Network configuration
    pub num_validators: usize,
    pub epoch_duration_ms: u64,

    pub validator_keys: BTreeMap<Address, Ed25519PrivateKey>,
    pub user_keys: Vec<Ed25519PrivateKey>,

    /// Admin interface ports for each validator (for triggering epoch changes)
    pub admin_ports: Vec<u16>,
}

impl Drop for SuiNetworkHandle {
    fn drop(&mut self) {
        terminate_child(&mut self.process);
    }
}

pub struct SuiNetworkBuilder {
    pub dir: Option<PathBuf>,
    pub num_validators: usize,
    pub epoch_duration_ms: u64,
    pub sui_binary_path: Option<PathBuf>, // Optional custom binary
    pub rpc_port: Option<u16>,
}

impl Default for SuiNetworkBuilder {
    fn default() -> Self {
        Self {
            num_validators: DEFAULT_NUM_VALIDATORS,
            epoch_duration_ms: DEFAULT_EPOCH_DURATION_MS,
            sui_binary_path: None,
            dir: None,
            rpc_port: None,
        }
    }
}

impl SuiNetworkBuilder {
    pub fn with_num_validators(mut self, n: usize) -> Self {
        self.num_validators = n;
        self
    }

    pub fn with_epoch_duration_ms(mut self, ms: u64) -> Self {
        self.epoch_duration_ms = ms;
        self
    }

    pub fn with_binary(mut self, path: PathBuf) -> Self {
        self.sui_binary_path = Some(path);
        self
    }

    pub fn dir(mut self, dir: &Path) -> Self {
        self.dir = Some(dir.to_owned());
        self
    }

    pub fn with_rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    pub async fn build(self) -> Result<SuiNetworkHandle> {
        let dir = self
            .dir
            .clone()
            .ok_or_else(|| anyhow!("no directory configured"))?;

        let (process, rpc_url, client, validator_keys, user_keys, admin_ports) = {
            // Sui genesis probes ports and releases them before `sui start` binds. Serialize that
            // gap across test processes, then retry a fresh genesis if an already-running swarm
            // owns one of the selected ports.
            let _startup_lock = acquire_startup_lock().await?;

            let mut started = None;
            for attempt in 1..=MAX_NETWORK_STARTUP_ATTEMPTS {
                if attempt > 1 {
                    std::fs::remove_dir_all(&dir).with_context(|| {
                        format!("remove failed Sui genesis directory {}", dir.display())
                    })?;
                }
                self.generate_genesis(&dir)?;
                let NetworkKeys {
                    validator_keys,
                    user_keys,
                    admin_ports,
                } = load_keys(&dir)?;

                let rpc_port = self.rpc_port.unwrap_or_else(get_available_port);
                let mut process = ChildGuard::new(self.start_network(&dir, rpc_port)?);
                let rpc_url = format!("http://127.0.0.1:{rpc_port}");
                let mut client = sui_rpc::Client::new(&rpc_url)?;

                match wait_for_ready(&mut client, process.child_mut(), &dir).await {
                    Ok(()) => {
                        started = Some((
                            process.disarm(),
                            rpc_url,
                            client,
                            validator_keys,
                            user_keys,
                            admin_ports,
                        ));
                        break;
                    }
                    Err(NetworkStartupError::AddressInUse(diagnostics))
                        if attempt < MAX_NETWORK_STARTUP_ATTEMPTS =>
                    {
                        tracing::warn!(
                            attempt,
                            max_attempts = MAX_NETWORK_STARTUP_ATTEMPTS,
                            "Sui network selected an occupied port; regenerating genesis. \
                             {diagnostics}",
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            started.ok_or_else(|| anyhow!("Sui network startup attempts exhausted"))?
        };

        let mut sui = SuiNetworkHandle {
            process,
            dir,
            rpc_url,
            client,
            num_validators: self.num_validators,
            epoch_duration_ms: self.epoch_duration_ms,
            validator_keys,
            user_keys,
            admin_ports,
        };

        // Make sure SuiSystemState has been upgraded to v2
        sui.upgrade_sui_system_state().await?;

        // Make sure validator accounts are funded
        let fund_requests = sui
            .validator_keys
            .keys()
            // give each validator 1M SUI
            .map(|address| (*address, 1_000_000 * 1_000_000_000))
            .collect::<Vec<_>>();
        sui.fund(&fund_requests).await?;

        Ok(sui)
    }

    fn generate_genesis(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut cmd = Command::new(sui_binary());
        cmd.arg("genesis")
            .arg("--working-dir")
            .arg(dir)
            .arg("--epoch-duration-ms")
            .arg(self.epoch_duration_ms.to_string())
            .arg("--committee-size")
            .arg(self.num_validators.to_string())
            .arg("--with-faucet");
        let status = cmd.status()?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to generate genesis"));
        }
        Ok(())
    }

    fn start_network(&self, dir: &Path, rpc_port: u16) -> Result<Child> {
        let stdout_name = dir.join("out.stdout");
        let stdout = std::fs::File::create(stdout_name)?;
        let stderr_name = dir.join("out.stderr");
        let stderr = std::fs::File::create(stderr_name)?;

        let mut cmd = Command::new(sui_binary());

        cmd.arg("start")
            .arg("--network.config")
            .arg(dir)
            .arg("--fullnode-rpc-port")
            .arg(rpc_port.to_string())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|e| anyhow!("Failed to run `sui start`: {e}"))
    }
}

fn ed25519_private_key_from_base64(b64: &str) -> Result<Ed25519PrivateKey> {
    let bytes = <base64ct::Base64 as base64ct::Encoding>::decode_vec(b64)?;
    Ok(Ed25519PrivateKey::new((&bytes[..]).try_into()?))
}

struct NetworkKeys {
    validator_keys: BTreeMap<Address, Ed25519PrivateKey>,
    user_keys: Vec<Ed25519PrivateKey>,
    admin_ports: Vec<u16>,
}

fn load_keys(dir: &Path) -> Result<NetworkKeys> {
    #[derive(serde::Deserialize)]
    struct Config {
        validator_configs: Vec<NodeConfig>,
        account_keys: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "kebab-case")]
    struct NodeConfig {
        account_key_pair: RawKey,
        admin_interface_port: u16,
    }

    #[derive(serde::Deserialize)]
    struct RawKey {
        value: String,
    }

    let raw = std::fs::read(dir.join("network.yaml"))?;
    let network_config: Config = serde_yaml::from_slice(&raw)?;

    let mut validator_keys = BTreeMap::new();
    let mut admin_ports = vec![];

    for validator in network_config.validator_configs {
        let keypair = Ed25519PrivateKey::from_base64(&validator.account_key_pair.value)
            .map_err(|e| anyhow!("invalid validator account key: {e}"))?;
        let address = keypair.public_key().derive_address();
        validator_keys.insert(address, keypair);
        admin_ports.push(validator.admin_interface_port);
    }

    let mut user_keys = vec![];

    for raw_key in network_config.account_keys {
        user_keys.push(ed25519_private_key_from_base64(&raw_key)?);
    }

    Ok(NetworkKeys {
        validator_keys,
        user_keys,
        admin_ports,
    })
}

impl SuiNetworkHandle {
    pub async fn fund(&mut self, requests: &[(Address, u64)]) -> Result<()> {
        let private_key = self.user_keys.first().unwrap();
        let sender = private_key.public_key().derive_address();
        let price = self.client.get_reference_gas_price().await?;

        let gas_objects = self
            .client
            .select_coins(
                &sender,
                &StructTag::sui().into(),
                requests.iter().map(|request| request.1).sum(),
                &[],
            )
            .await?;

        let (inputs, transfers): (Vec<Input>, Vec<sui_sdk_types::Command>) = requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                (
                    Input::Pure(request.0.to_bcs().unwrap()),
                    sui_sdk_types::Command::TransferObjects(TransferObjects {
                        objects: vec![Argument::NestedResult(0, i as u16)],
                        address: Argument::Input(i as u16),
                    }),
                )
            })
            .unzip();

        let (input_amounts, argument_amounts) = requests
            .iter()
            .enumerate()
            .map(|(i, request)| {
                (
                    Input::Pure(request.1.to_bcs().unwrap()),
                    Argument::Input((i + inputs.len()) as u16),
                )
            })
            .unzip();
        let pt = ProgrammableTransaction {
            inputs: [inputs, input_amounts].concat(),
            commands: [
                vec![sui_sdk_types::Command::SplitCoins(
                    sui_sdk_types::SplitCoins {
                        coin: Argument::Gas,
                        amounts: argument_amounts,
                    },
                )],
                transfers,
            ]
            .concat(),
        };

        let gas_payment_objects = gas_objects
            .iter()
            .map(|o| -> anyhow::Result<_> { Ok((&o.object_reference()).try_into()?) })
            .collect::<Result<Vec<_>>>()?;

        let publish_transaction = Transaction {
            kind: TransactionKind::ProgrammableTransaction(pt),
            sender,
            gas_payment: GasPayment {
                objects: gas_payment_objects,
                owner: sender,
                price,
                budget: 1_000_000_000,
            },
            expiration: TransactionExpiration::None,
        };

        let signature = private_key.sign_transaction(&publish_transaction)?;

        let response = self
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(publish_transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                std::time::Duration::from_secs(10),
            )
            .await?
            .into_inner();

        assert!(
            response.transaction().effects().status().success(),
            "fund failed"
        );
        Ok(())
    }

    pub async fn current_sui_epoch(&mut self) -> Result<u64> {
        // Bounded: a wedged fullnode must surface as a diagnosable error, not
        // an unbounded await that outlives the nextest terminate-after and
        // discards every captured log.
        let resp = tokio::time::timeout(
            Duration::from_secs(30),
            self.client
                .ledger_client()
                .get_service_info(sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest::default()),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("get_service_info timed out after 30s (fullnode wedged?)")
        })??;
        Ok(resp.into_inner().epoch())
    }

    pub async fn force_close_epoch(&mut self) -> Result<()> {
        let current_epoch = self.current_sui_epoch().await?;
        let target_epoch = current_epoch + 1;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        for port in &self.admin_ports {
            let url = format!(
                "http://127.0.0.1:{}/force-close-epoch?epoch={}",
                port, current_epoch
            );
            let resp = client.post(&url).send().await.map_err(|e| {
                anyhow::anyhow!("force-close-epoch POST to admin port {port} failed: {e}")
            })?;
            anyhow::ensure!(
                resp.status().is_success(),
                "force-close-epoch on admin port {port} returned {}",
                resp.status()
            );
        }
        for _ in 0..NETWORK_STARTUP_TIMEOUT_SECS {
            match self.current_sui_epoch().await {
                Ok(epoch) if epoch >= target_epoch => return Ok(()),
                Ok(_) => {}
                // Keep polling through transient RPC errors; the loop bound
                // converts a persistent one into the diagnosable bail below.
                Err(e) => tracing::warn!("epoch poll failed while awaiting close: {e:#}"),
            }
            sleep(Duration::from_secs(NETWORK_STARTUP_POLL_INTERVAL_SECS)).await;
        }
        bail!(
            "Sui epoch did not advance {current_epoch} -> {target_epoch} within {}s of \
             force-close-epoch (validator admin endpoints all acknowledged)",
            NETWORK_STARTUP_TIMEOUT_SECS
        )
    }

    async fn upgrade_sui_system_state(&mut self) -> Result<()> {
        let private_key = self.user_keys.first().unwrap();
        let sender = private_key.public_key().derive_address();
        let price = self.client.get_reference_gas_price().await?;

        let gas_objects = self
            .client
            .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
            .await?;

        let pt = ProgrammableTransaction {
            inputs: vec![Input::Shared(SharedInput::new(
                Address::from_static("0x5"),
                1,
                true,
            ))],
            commands: vec![sui_sdk_types::Command::MoveCall(MoveCall {
                package: Address::from_static("0x3"),
                module: Identifier::from_static("sui_system"),
                function: Identifier::from_static("active_validator_addresses"),
                type_arguments: vec![],
                arguments: vec![Argument::Input(0)],
            })],
        };

        let gas_payment_objects = gas_objects
            .iter()
            .map(|o| -> anyhow::Result<_> { Ok((&o.object_reference()).try_into()?) })
            .collect::<Result<Vec<_>>>()?;

        let transaction = Transaction {
            kind: TransactionKind::ProgrammableTransaction(pt),
            sender,
            gas_payment: GasPayment {
                objects: gas_payment_objects,
                owner: sender,
                price,
                budget: 1_000_000_000,
            },
            expiration: TransactionExpiration::None,
        };

        let signature = private_key.sign_transaction(&transaction)?;

        let response = self
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(transaction.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_str("*")),
                std::time::Duration::from_secs(10),
            )
            .await?
            .into_inner();

        assert!(
            response.transaction().effects().status().success(),
            "upgrade_sui_system_state failed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn test_parallel_sui_networks() -> Result<()> {
        use futures::future::join_all;
        use std::collections::HashSet;

        const NUM_PARALLEL_NETWORKS: usize = 3;
        const NUM_VALIDATORS: usize = 1;

        let tempdir = TempDir::new()?;

        // Spawn multiple networks in parallel
        let network_futures: Vec<_> = (0..NUM_PARALLEL_NETWORKS)
            .map(|i| {
                let dir = tempdir.path().join(format!("{i}"));

                async move {
                    let network = SuiNetworkBuilder::default()
                        .with_num_validators(NUM_VALIDATORS)
                        .dir(&dir)
                        .build()
                        .await;
                    (i, network)
                }
            })
            .collect();

        // Wait for all networks to start
        let results = join_all(network_futures).await;

        // Verify all networks started successfully with unique ports
        let mut networks = Vec::new();
        let mut rpc_ports = HashSet::new();

        for (i, result) in results {
            match result {
                Ok(network) => {
                    let rpc_port: u16 = network
                        .rpc_url
                        .split(':')
                        .next_back()
                        .and_then(|p| p.parse().ok())
                        .expect("Failed to parse RPC port");

                    // Verify ports are unique
                    assert!(
                        rpc_ports.insert(rpc_port),
                        "Network {} has duplicate RPC port {}",
                        i,
                        rpc_port
                    );

                    // Verify network configuration
                    assert_eq!(network.num_validators, NUM_VALIDATORS);

                    networks.push(network);
                }
                Err(e) => {
                    panic!("Network {} failed to start: {}", i, e);
                }
            }
        }

        assert_eq!(networks.len(), NUM_PARALLEL_NETWORKS);

        Ok(())
    }
}
