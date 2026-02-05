use anyhow::Result;
use fastcrypto::serde_helpers::ToFromByteArray;
use hashi::Hashi;
use hashi::ServerVersion;
use hashi::config::Config as HashiConfig;
use hashi::config::HashiIds;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::BlsSignatureAggregator;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::EncryptionPublicKey;
use serde;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use sui_crypto::SuiSigner;
use sui_futures::service::Service;
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReconfigCompletionMessage {
    pub epoch: u64,
    pub mpc_public_key: Vec<u8>,
}

use crate::BitcoinNodeHandle;
use crate::SuiNetworkHandle;

const HTTPS_SCHEME: &str = "https://";
const HTTP_SCHEME: &str = "http://";
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

pub struct HashiNodeHandle {
    config: HashiConfig,
    /// The running service and Hashi instance. Both are dropped together on shutdown
    /// to ensure the database lock is released before a new instance can be created.
    service: Option<(Service, Arc<Hashi>)>,
}

impl HashiNodeHandle {
    pub fn new(config: HashiConfig) -> Result<Self> {
        Ok(Self {
            config,
            service: None,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        if self.service.is_some() {
            anyhow::bail!("Hashi node already started");
        }
        let hashi = Self::create_hashi_retry(&self.config).await?;
        let service = hashi.clone().start().await?;
        self.service = Some((service, hashi));
        Ok(())
    }

    fn create_hashi(config: &HashiConfig) -> Result<Arc<Hashi>> {
        let server_version = ServerVersion::new("test-hashi", "0.1.0");
        let registry = prometheus::Registry::new();
        Hashi::new_with_registry(server_version, config.clone(), &registry)
    }

    /// Create a Hashi instance with retry logic for database lock contention.
    ///
    /// After shutdown, there may be a brief delay before the database lock is released.
    async fn create_hashi_retry(config: &HashiConfig) -> Result<Arc<Hashi>> {
        const MAX_ATTEMPTS: u32 = 3;

        for attempt in 1..=MAX_ATTEMPTS {
            match Self::create_hashi(config) {
                Ok(hashi) => return Ok(hashi),
                Err(e) if attempt == MAX_ATTEMPTS => return Err(e),
                Err(e) => {
                    tracing::debug!(
                        "Failed to create Hashi (attempt {attempt}/{MAX_ATTEMPTS}): {e}"
                    );
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        }
        unreachable!()
    }

    async fn shutdown(&mut self) {
        let Some((service, _hashi)) = self.service.take() else {
            tracing::warn!("Hashi node not running, cannot shutdown");
            return;
        };
        let result = service.shutdown().await;
        if let Err(e) = result {
            tracing::warn!("Hashi shutdown error: {e}");
        }
    }

    pub async fn restart(&mut self) -> Result<()> {
        self.shutdown().await;
        self.start().await
    }

    pub fn hashi(&self) -> &Arc<Hashi> {
        &self.service.as_ref().expect("Hashi node not started").1
    }

    pub fn https_url(&self) -> String {
        format!("{}{}", HTTPS_SCHEME, self.https_address())
    }

    pub fn http_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.http_address())
    }

    pub fn metrics_url(&self) -> String {
        format!("{}{}", HTTP_SCHEME, self.metrics_address())
    }

    pub fn https_address(&self) -> SocketAddr {
        self.config.https_address()
    }

    pub fn http_address(&self) -> SocketAddr {
        self.config.http_address()
    }

    pub fn metrics_address(&self) -> SocketAddr {
        self.config.metrics_http_address()
    }

    pub async fn wait_for_mpc_key(&self, timeout: std::time::Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.wait_for_mpc_key_inner())
            .await
            .map_err(|_| anyhow::anyhow!("MPC key timed out after {:?}", timeout))?
    }

    async fn wait_for_mpc_key_inner(&self) -> Result<()> {
        loop {
            if let Some(mpc_handle) = self.hashi().mpc_handle()
                && mpc_handle.public_key().is_some()
            {
                return Ok(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub async fn wait_for_dkg_completion(&self, timeout: std::time::Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.wait_for_dkg_completion_inner())
            .await
            .map_err(|_| anyhow::anyhow!("DKG completion timed out after {:?}", timeout))
    }

    async fn wait_for_dkg_completion_inner(&self) {
        loop {
            // Wait for hashi to finish initializing
            let onchain_state = match self.hashi().onchain_state_opt() {
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
            let raw_certs = match onchain_state.fetch_certs(epoch).await {
                Ok(Some((_, certs))) => certs,
                Ok(None) | Err(_) => {
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

    pub fn nodes_mut(&mut self) -> &mut [HashiNodeHandle] {
        &mut self.nodes
    }

    pub async fn restart(&mut self) -> Result<()> {
        futures::future::try_join_all(self.nodes.iter_mut().map(|node| node.restart())).await?;
        Ok(())
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

        let bls_keys: Vec<(Address, Bls12381PrivateKey, EncryptionPublicKey)> = configs
            .iter()
            .map(|c| {
                (
                    c.validator_address().unwrap(),
                    c.protocol_private_key().unwrap(),
                    c.encryption_public_key().unwrap(),
                )
            })
            .collect();

        for config in &configs {
            let client = sui.client.clone();
            register_onchain(client, config).await?;
        }

        // Init the initial committee
        start_reconfig(sui, hashi_ids).await?;
        // TODO: Remove this test-only logic once the node service handles committing the
        // MPC public key on-chain after DKG.
        let placeholder_mpc_public_key = vec![0u8; 33];
        end_reconfig(sui, hashi_ids, &bls_keys, placeholder_mpc_public_key).await?;

        let mut nodes = Vec::with_capacity(configs.len());
        for config in configs {
            let validator_address = config.validator_address()?;
            let mut node_handle = HashiNodeHandle::new(config)?;
            node_handle.start().await?;
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
            .to_byte_array()
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

async fn end_reconfig(
    sui: &SuiNetworkHandle,
    hashi_ids: HashiIds,
    bls_keys: &[(Address, Bls12381PrivateKey, EncryptionPublicKey)],
    mpc_public_key: Vec<u8>,
) -> Result<()> {
    let mut client = sui.client.clone();
    let private_key = sui.user_keys.first().unwrap();
    let sender = private_key.public_key().derive_address();
    let price = client.get_reference_gas_price().await?;
    let service_info = client
        .clone()
        .ledger_client()
        .get_service_info(GetServiceInfoRequest::default())
        .await?
        .into_inner();
    let epoch = service_info.epoch.unwrap_or(0);
    let committee_members: Vec<CommitteeMember> = bls_keys
        .iter()
        .map(|(addr, bls_key, enc_key)| {
            CommitteeMember::new(*addr, bls_key.public_key(), enc_key.clone(), 1)
        })
        .collect();
    let committee = Committee::new(committee_members, epoch);
    let message = ReconfigCompletionMessage {
        epoch,
        mpc_public_key: mpc_public_key.clone(),
    };
    let mut aggregator = BlsSignatureAggregator::new(&committee, message.clone());
    for (addr, bls_key, _) in bls_keys {
        let member_sig = bls_key.sign(epoch, *addr, &message);
        aggregator.add_signature(member_sig)?;
    }
    let signed_message = aggregator.finish()?;
    committee
        .verify_signature(&signed_message)
        .expect("Local signature verification failed");
    let signature_bytes = signed_message.signature_bytes();
    let signers_bitmap_bytes = signed_message.signers_bitmap_bytes();
    let gas_objects = client
        .select_coins(&sender, &StructTag::sui().into(), 1_000_000_000, &[])
        .await?;
    let hashi_object = client
        .ledger_client()
        .batch_get_objects(
            BatchGetObjectsRequest::default()
                .with_requests(vec![GetObjectRequest::new(&hashi_ids.hashi_object_id)])
                .with_read_mask(FieldMask::from_str("*")),
        )
        .await?
        .into_inner();
    let hashi_system = hashi_object.objects[0].object();
    let pt = ProgrammableTransaction {
        inputs: vec![
            Input::Shared(SharedInput::new(
                hashi_system.object_id().parse()?,
                hashi_system.owner().version(),
                true,
            )),
            Input::Pure(mpc_public_key.to_bcs()?),
            Input::Pure(signature_bytes.to_vec().to_bcs()?),
            Input::Pure(signers_bitmap_bytes.to_vec().to_bcs()?),
        ],
        commands: vec![sui_sdk_types::Command::MoveCall(MoveCall {
            package: hashi_ids.package_id,
            module: Identifier::from_static("reconfig"),
            function: Identifier::from_static("end_reconfig"),
            type_arguments: vec![],
            arguments: vec![
                Argument::Input(0),
                Argument::Input(1),
                Argument::Input(2),
                Argument::Input(3),
            ],
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
    let tx_signature = private_key.sign_transaction(&transaction)?;
    let response = client
        .execute_transaction_and_wait_for_checkpoint(
            ExecuteTransactionRequest::new(transaction.into())
                .with_signatures(vec![tx_signature.into()])
                .with_read_mask(FieldMask::from_str("*")),
            std::time::Duration::from_secs(10),
        )
        .await?
        .into_inner();
    assert!(
        response.transaction().effects().status().success(),
        "end_reconfig failed: {:?}",
        response.transaction().effects().status().error_opt()
    );
    Ok(())
}
