use anyhow::Result;
use hashi::Hashi;

/// Bitcoin regtest genesis block hash (BIP-122 chain ID).
/// See: https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
const BITCOIN_REGTEST_CHAIN_ID: &str =
    "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
use hashi::ServerVersion;
use hashi::config::Config as HashiConfig;
use hashi::config::HashiIds;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::sync::Arc;
use sui_crypto::SuiSigner;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::BatchGetObjectsRequest;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::GetServiceInfoRequest;
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
use sui_sdk_types::bcs::ToBcs;
use tracing::info;

use crate::BitcoinNodeHandle;
use crate::SuiNetworkHandle;

const HTTPS_SCHEME: &str = "https://";
const HTTP_SCHEME: &str = "http://";

pub struct HashiNodeHandle(pub Arc<Hashi>);

impl HashiNodeHandle {
    pub fn new(config: HashiConfig) -> Result<Self> {
        let server_version = ServerVersion::new("test-hashi", "0.1.0");
        let registry = prometheus::Registry::new();
        let hashi_instance = Hashi::new_with_registry(server_version, config, &registry);
        Ok(Self(hashi_instance))
    }

    pub fn start(&self) {
        self.0.clone().start();
    }

    pub fn https_url(&self) -> String {
        format!("{}{}", HTTPS_SCHEME, self.0.config.https_address())
    }

    pub fn http_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.0.config.http_address())
    }

    pub fn metrics_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.0.config.metrics_http_address())
    }

    pub fn https_address(&self) -> SocketAddr {
        self.0.config.https_address()
    }

    pub fn http_address(&self) -> SocketAddr {
        self.0.config.http_address()
    }

    pub fn metrics_address(&self) -> SocketAddr {
        self.0.config.metrics_http_address()
    }
}

/// Process-based node handle
/// Each node runs in a separate OS process to avoid lock contention.
pub struct HashiProcessHandle {
    pub config: HashiConfig,
    config_path: PathBuf,
    process: Option<Child>,
}

impl HashiProcessHandle {
    pub fn new(config: HashiConfig, config_path: PathBuf) -> Result<Self> {
        let config_str = toml::to_string_pretty(&config)?;
        std::fs::write(&config_path, config_str)?;
        Ok(Self {
            config,
            config_path,
            process: None,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        let binary = hashi_binary();
        let log_dir = self.config_path.parent().unwrap();
        let validator = self.config.validator_address.unwrap();
        let stdout_file = std::fs::File::create(log_dir.join(format!("{}.stdout", validator)))?;
        let stderr_file = std::fs::File::create(log_dir.join(format!("{}.stderr", validator)))?;
        let child = Command::new(&binary)
            .arg("--config")
            .arg(&self.config_path)
            .env("RUST_LOG", "info,hashi=debug")
            .stdout(stdout_file)
            .stderr(stderr_file)
            .spawn()?;
        self.process = Some(child);
        info!(
            "Started hashi process with PID: {:?}",
            self.process.as_ref().map(|p| p.id())
        );
        Ok(())
    }

    pub fn https_url(&self) -> String {
        format!("{}{}", HTTPS_SCHEME, self.config.https_address())
    }

    pub fn tls_public_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        self.config.tls_public_key()
    }
}

impl Drop for HashiProcessHandle {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn hashi_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // crates/test-networks -> crates
    path.pop(); // crates -> repo root
    path.push("target/release/hashi");
    path
}

pub struct HashiNetwork {
    ids: HashiIds,
    nodes: Vec<HashiNodeHandle>,
}

impl HashiNetwork {
    pub fn nodes(&self) -> &[HashiNodeHandle] {
        &self.nodes
    }

    pub fn ids(&self) -> HashiIds {
        self.ids
    }
}

pub struct HashiProcessNetwork {
    ids: HashiIds,
    nodes: Vec<HashiProcessHandle>,
}

impl HashiProcessNetwork {
    pub fn nodes(&self) -> &[HashiProcessHandle] {
        &self.nodes
    }

    pub fn nodes_mut(&mut self) -> &mut [HashiProcessHandle] {
        &mut self.nodes
    }

    pub fn ids(&self) -> HashiIds {
        self.ids
    }

    pub fn start_all(&mut self) -> Result<()> {
        for node in &mut self.nodes {
            node.start()?;
        }
        Ok(())
    }
}

pub struct HashiNetworkBuilder {
    pub num_nodes: usize,
    pub auto_start: bool,
}

impl HashiNetworkBuilder {
    pub fn new() -> Self {
        Self {
            num_nodes: 1,
            auto_start: true,
        }
    }

    pub fn with_num_nodes(mut self, num_nodes: usize) -> Self {
        self.num_nodes = num_nodes;
        self
    }

    pub fn with_auto_start(mut self, auto_start: bool) -> Self {
        self.auto_start = auto_start;
        self
    }

    pub async fn build(
        self,
        dir: &Path,
        sui: &SuiNetworkHandle,
        bitcoin: &BitcoinNodeHandle,
        hashi_ids: HashiIds,
    ) -> Result<HashiNetwork> {
        let bitcoin_rpc = bitcoin.rpc_url().to_owned();
        let sui_rpc = sui.rpc_url.clone();
        let service_info = sui
            .client
            .clone()
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();

        let mut configs = Vec::with_capacity(self.num_nodes);
        for (validator_address, private_key) in sui.validator_keys.iter().take(self.num_nodes) {
            let mut config = HashiConfig::new_for_testing();
            config.hashi_ids = Some(hashi_ids);
            config.validator_address = Some(*validator_address);
            config.operator_private_key = Some(private_key.to_pem()?);
            config.sui_rpc = Some(sui_rpc.clone());
            config.bitcoin_rpc = Some(bitcoin_rpc.clone());
            config.db = Some(dir.join(validator_address.to_string()));

            config.sui_chain_id = service_info.chain_id.clone();
            config.bitcoin_chain_id = Some(BITCOIN_REGTEST_CHAIN_ID.to_string());

            configs.push(config);
        }

        for config in &configs {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }

        // Init the initial committee
        bootstrap(sui, hashi_ids).await?;

        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let validator_address = config.validator_address()?;
            let node_handle = HashiNodeHandle::new(config)?;
            if self.auto_start {
                node_handle.start();
            }
            info!(
                "Created Hashi node {} at HTTPS: {}, HTTP: {}, Metrics: {}",
                validator_address,
                node_handle.https_address(),
                node_handle.http_address(),
                node_handle.metrics_address()
            );
            nodes.push(node_handle);
        }

        Ok(HashiNetwork {
            ids: hashi_ids,
            nodes,
        })
    }

    pub async fn build_process_network(
        self,
        dir: &Path,
        sui: &SuiNetworkHandle,
        bitcoin: &BitcoinNodeHandle,
        hashi_ids: HashiIds,
    ) -> Result<HashiProcessNetwork> {
        std::fs::create_dir_all(dir)?;
        let bitcoin_rpc = bitcoin.rpc_url().to_owned();
        let sui_rpc = sui.rpc_url.clone();
        let service_info = sui
            .client
            .clone()
            .ledger_client()
            .get_service_info(GetServiceInfoRequest::default())
            .await?
            .into_inner();
        let mut configs = Vec::with_capacity(self.num_nodes);
        for (validator_address, private_key) in sui.validator_keys.iter().take(self.num_nodes) {
            let mut config = HashiConfig::new_for_testing();
            config.hashi_ids = Some(hashi_ids);
            config.validator_address = Some(*validator_address);
            config.operator_private_key = Some(private_key.to_pem()?);
            config.sui_rpc = Some(sui_rpc.clone());
            config.bitcoin_rpc = Some(bitcoin_rpc.clone());
            config.db = Some(dir.join(validator_address.to_string()));
            config.sui_chain_id = service_info.chain_id.clone();
            config.bitcoin_chain_id = Some(BITCOIN_REGTEST_CHAIN_ID.to_string());

            configs.push(config);
        }
        for config in &configs {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }
        bootstrap(sui, hashi_ids).await?;
        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let validator_address = config.validator_address()?;
            let config_path = dir.join(format!("{}.toml", validator_address));
            let mut node_handle = HashiProcessHandle::new(config, config_path)?;
            if self.auto_start {
                node_handle.start()?;
            }
            info!(
                "Created Hashi process node {} at HTTPS: {}",
                validator_address,
                node_handle.https_url()
            );
            nodes.push(node_handle);
        }
        Ok(HashiProcessNetwork {
            ids: hashi_ids,
            nodes,
        })
    }
}

impl Default for HashiNetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

async fn register_onchain(mut client: sui_rpc::Client, config: &HashiConfig) -> Result<()> {
    let ids = config.hashi_ids();
    let private_key = config.operator_private_key()?;
    let protocol_private_key = config.protocol_private_key().unwrap();
    let protocol_public_key = protocol_private_key.public_key();
    let sender = private_key.public_key().derive_address();
    let validator_address = config.validator_address()?;
    let price = client.get_reference_gas_price().await?;

    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;

    let system_objects = client
        .ledger_client()
        .batch_get_objects(
            BatchGetObjectsRequest::default()
                .with_requests(vec![
                    GetObjectRequest::new(&Address::from_static("0x5")),
                    GetObjectRequest::new(&ids.hashi_object_id),
                ])
                .with_read_mask(FieldMask::from_str("*")),
        )
        .await?
        .into_inner();
    let sui_system = system_objects.objects[0].object();
    let hashi_system = system_objects.objects[1].object();

    let public_key_input = Input::Pure(protocol_public_key.as_ref().to_vec().to_bcs()?);
    let proof_of_possession = Input::Pure(
        protocol_private_key
            .proof_of_possession(0, validator_address)
            .signature()
            .as_ref()
            .to_bcs()?,
    );
    let https_address = Input::Pure(format!("https://{}", config.https_address()).to_bcs()?);
    let tls_public_key = Input::Pure(config.tls_public_key()?.as_bytes().to_vec().to_bcs()?);
    let encryption_public_key = Input::Pure(
        config
            .encryption_public_key()?
            .as_element()
            .compress()
            .as_slice()
            .to_bcs()?,
    );
    let validator_address_pure = Input::Pure(validator_address.to_bcs()?);

    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Shared(SharedInput::new(
                sui_system.object_id().parse()?,
                sui_system.owner().version(),
                false,
            )),
            Input::Shared(SharedInput::new(
                hashi_system.object_id().parse()?,
                hashi_system.owner().version(),
                true,
            )),
            public_key_input,
            proof_of_possession,
            https_address,
            tls_public_key,
            encryption_public_key,
            validator_address_pure,
        ],
        commands: vec![
            sui_sdk_types::Command::MoveCall(MoveCall {
                package: ids.package_id,
                module: Identifier::from_static("validator"),
                function: Identifier::from_static("register"),
                type_arguments: vec![],
                arguments: vec![
                    Argument::Input(1),
                    Argument::Input(0),
                    Argument::Input(2),
                    Argument::Input(3),
                    Argument::Input(6),
                ],
            }),
            sui_sdk_types::Command::MoveCall(MoveCall {
                package: ids.package_id,
                module: Identifier::from_static("validator"),
                function: Identifier::from_static("update_https_address"),
                type_arguments: vec![],
                arguments: vec![Argument::Input(1), Argument::Input(7), Argument::Input(4)],
            }),
            sui_sdk_types::Command::MoveCall(MoveCall {
                package: ids.package_id,
                module: Identifier::from_static("validator"),
                function: Identifier::from_static("update_tls_public_key"),
                type_arguments: vec![],
                arguments: vec![Argument::Input(1), Argument::Input(7), Argument::Input(5)],
            }),
        ],
    };

    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: gas_objects
                .iter()
                .map(|o| (&o.object_reference()).try_into())
                .collect::<Result<_, _>>()?,
            owner: sender,
            price,
            budget: 1_000_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = private_key.sign_transaction(&transaction)?;

    let response = client
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
        "register failed"
    );

    Ok(())
}

pub async fn update_tls_public_key(
    mut client: sui_rpc::Client,
    config: &HashiConfig,
) -> Result<()> {
    let ids = config.hashi_ids();
    let private_key = config.operator_private_key()?;
    let sender = private_key.public_key().derive_address();
    let validator_address = config.validator_address()?;
    let price = client.get_reference_gas_price().await?;

    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;

    let system_objects = client
        .ledger_client()
        .batch_get_objects(
            BatchGetObjectsRequest::default()
                .with_requests(vec![
                    GetObjectRequest::new(&Address::from_static("0x5")),
                    GetObjectRequest::new(&ids.hashi_object_id),
                ])
                .with_read_mask(FieldMask::from_str("*")),
        )
        .await?
        .into_inner();
    let hashi_system = system_objects.objects[1].object();

    let tls_public_key = Input::Pure(config.tls_public_key()?.as_bytes().to_vec().to_bcs()?);
    let validator_address_pure = Input::Pure(validator_address.to_bcs()?);

    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Shared(SharedInput::new(
                hashi_system.object_id().parse()?,
                hashi_system.owner().version(),
                true,
            )),
            validator_address_pure,
            tls_public_key,
        ],
        commands: vec![sui_sdk_types::Command::MoveCall(MoveCall {
            package: ids.package_id,
            module: Identifier::from_static("validator"),
            function: Identifier::from_static("update_tls_public_key"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0), Argument::Input(1), Argument::Input(2)],
        })],
    };

    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: gas_objects
                .iter()
                .map(|o| (&o.object_reference()).try_into())
                .collect::<Result<_, _>>()?,
            owner: sender,
            price,
            budget: 1_000_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = private_key.sign_transaction(&transaction)?;

    let response = client
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
        "register failed"
    );

    Ok(())
}

async fn bootstrap(sui: &SuiNetworkHandle, hashi_ids: HashiIds) -> Result<()> {
    let mut client = sui.client.clone();
    let private_key = sui.user_keys.first().unwrap();
    let sender = private_key.public_key().derive_address();
    let price = client.get_reference_gas_price().await?;

    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;

    let system_objects = client
        .ledger_client()
        .batch_get_objects(
            BatchGetObjectsRequest::default()
                .with_requests(vec![
                    GetObjectRequest::new(&Address::from_static("0x5")),
                    GetObjectRequest::new(&hashi_ids.hashi_object_id),
                ])
                .with_read_mask(FieldMask::from_str("*")),
        )
        .await?
        .into_inner();
    let sui_system = system_objects.objects[0].object();
    let hashi_system = system_objects.objects[1].object();

    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Shared(SharedInput::new(
                sui_system.object_id().parse()?,
                sui_system.owner().version(),
                false,
            )),
            Input::Shared(SharedInput::new(
                hashi_system.object_id().parse()?,
                hashi_system.owner().version(),
                true,
            )),
        ],
        commands: vec![sui_sdk_types::Command::MoveCall(MoveCall {
            package: hashi_ids.package_id,
            module: Identifier::from_static("hashi"),
            function: Identifier::from_static("bootstrap"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(1), Argument::Input(0)],
        })],
    };

    let transaction = Transaction {
        kind: TransactionKind::ProgrammableTransaction(pt),
        sender,
        gas_payment: GasPayment {
            objects: gas_objects
                .iter()
                .map(|o| (&o.object_reference()).try_into())
                .collect::<Result<_, _>>()?,
            owner: sender,
            price,
            budget: 1_000_000_000,
        },
        expiration: TransactionExpiration::None,
    };

    let signature = private_key.sign_transaction(&transaction)?;

    let response = client
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
        "bootstrap failed"
    );

    Ok(())
}
