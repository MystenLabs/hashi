use anyhow::Result;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config as HashiConfig;
use hashi::config::HashiIds;
use std::net::SocketAddr;
use std::path::Path;
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
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

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

    pub async fn wait_for_dkg_completion(&self, timeout: std::time::Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.wait_for_dkg_completion_inner())
            .await
            .map_err(|_| anyhow::anyhow!("DKG completion timed out after {:?}", timeout))
    }

    async fn wait_for_dkg_completion_inner(&self) {
        loop {
            // Wait for hashi to finish initializing
            let onchain_state = match self.0.onchain_state_opt() {
                Some(state) => state,
                None => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            let epoch_threshold_and_committee = {
                let state = onchain_state.state();
                let epoch = state.hashi().committees.epoch();
                state.hashi().committees.current_committee().map(|c| {
                    let threshold = c.total_weight() * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR;
                    (epoch, threshold, c.clone())
                })
            };
            let (epoch, threshold, committee) = match epoch_threshold_and_committee {
                Some(et) => et,
                None => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            let raw_certs = match onchain_state.fetch_dkg_certs(epoch).await {
                Ok(certs) => certs,
                Err(_) => {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                }
            };
            let certified_weight: u64 = raw_certs
                .iter()
                .filter_map(|(dealer, _)| committee.weight_of(dealer).ok())
                .sum();
            if certified_weight >= threshold {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
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

pub struct HashiNetworkBuilder {
    pub num_nodes: usize,
}

impl HashiNetworkBuilder {
    pub fn new() -> Self {
        Self { num_nodes: 1 }
    }

    pub fn with_num_nodes(mut self, num_nodes: usize) -> Self {
        self.num_nodes = num_nodes;
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
            config.bitcoin_rpc_auth = Some(hashi_btc::config::BtcRpcAuth::UserPass(
                crate::bitcoin_node::RPC_USER.into(),
                crate::bitcoin_node::RPC_PASSWORD.into(),
            ));
            config.bitcoin_trusted_peers = Some(vec![bitcoin.p2p_address()]);
            // Bitcoin regtest chain id, from https://github.com/bitcoin/bips/blob/master/bip-0122.mediawiki
            config.bitcoin_chain_id = Some(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206".to_string(),
            );
            config.sui_chain_id = service_info.chain_id.clone();
            config.db = Some(dir.join(validator_address.to_string()));
            configs.push(config);
        }

        for config in &configs {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }

        // Init the initial committee
        start_reconfig(sui, hashi_ids).await?;
        end_reconfig(sui, hashi_ids).await?;

        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let validator_address = config.validator_address()?;
            let node_handle = HashiNodeHandle::new(config)?;
            node_handle.start();
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

async fn start_reconfig(sui: &SuiNetworkHandle, hashi_ids: HashiIds) -> Result<()> {
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
            module: Identifier::from_static("reconfig"),
            function: Identifier::from_static("start_reconfig"),
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

    if let Some(status) = response.transaction().effects().status().error_opt() {
        dbg!(status);
    }

    assert!(
        response.transaction().effects().status().success(),
        "start_reconfig failed"
    );

    Ok(())
}

async fn end_reconfig(sui: &SuiNetworkHandle, hashi_ids: HashiIds) -> Result<()> {
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
    let _sui_system = system_objects.objects[0].object();
    let hashi_system = system_objects.objects[1].object();

    let pt = ProgrammableTransaction {
        inputs: vec![Input::Shared(SharedInput::new(
            hashi_system.object_id().parse()?,
            hashi_system.owner().version(),
            true,
        ))],
        commands: vec![sui_sdk_types::Command::MoveCall(MoveCall {
            package: hashi_ids.package_id,
            module: Identifier::from_static("reconfig"),
            function: Identifier::from_static("end_reconfig"),
            type_arguments: vec![],
            arguments: vec![Argument::Input(0)],
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
        "end_reconfig failed"
    );

    Ok(())
}
