use anyhow::Result;
use anyhow::anyhow;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use futures::TryStreamExt;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
use sui_futures::service::Service;
use sui_rpc::Client;
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::proto::sui::rpc::v2::ListPackageVersionsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::ToBcs;
use tap::Pipe;
use tokio::sync::broadcast;
use tokio::sync::watch;

use crate::config::HashiIds;
use crate::mpc::fallback_encryption_public_key;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeMember;
use hashi_types::move_types;

const BROADCAST_CHANNEL_CAPACITY: usize = 100;

pub mod types;
mod watcher;

fn parse_encryption_public_key(bytes: &[u8]) -> Option<crate::mpc::EncryptionGroupElement> {
    let array: [u8; 32] = bytes.try_into().ok()?;
    crate::mpc::EncryptionGroupElement::from_byte_array(&array).ok()
}

#[derive(Clone)]
pub struct OnchainState(Arc<Inner>);

impl std::fmt::Debug for OnchainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnchainState").finish_non_exhaustive()
    }
}

//TODO should we just send a HashiEvent here?
#[derive(Clone, Debug)]
pub enum Notification {
    ValidatorInfoUpdated(Address),
    /// Reconfig started, transitioning to the given epoch.
    StartReconfig(u64),
    SuiEpochChanged(u64),
}

/// Information about the latest processed checkpoint
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckpointInfo {
    /// The checkpoint height
    pub height: u64,
    /// The checkpoint timestamp in milliseconds since Unix epoch
    pub timestamp_ms: u64,
    /// The Sui epoch this checkpoint belongs to
    pub epoch: u64,
}

struct Inner {
    #[allow(unused)]
    ids: HashiIds,
    client: Client,
    sender: broadcast::Sender<Notification>,
    /// The checkpoint information that this state is recent to
    checkpoint: watch::Sender<CheckpointInfo>,
    state: RwLock<State>,
    tls_private_key: Option<ed25519_dalek::SigningKey>,
    grpc_max_decoding_message_size: Option<usize>,
}

#[derive(Debug)]
pub struct State {
    package_versions: BTreeMap<u64, Address>,
    package_ids: BTreeSet<Address>,
    hashi: types::Hashi,
}

#[derive(serde_derive::Serialize)]
struct TobKey {
    epoch: u64,
    batch_index: Option<u32>,
}

impl OnchainState {
    pub async fn new(
        sui_rpc_url: &str,
        ids: HashiIds,
        tls_private_key: Option<ed25519_dalek::SigningKey>,
        grpc_max_decoding_message_size: Option<usize>,
        metrics: Option<Arc<crate::metrics::Metrics>>,
    ) -> Result<(Self, Service)> {
        let client = Client::new(sui_rpc_url)?;

        let (mut state, checkpoint) = State::scrape(client.clone(), ids).await?;
        if let Some(tls_private_key) = &tls_private_key {
            state
                .hashi
                .committees
                .set_tls_private_key(tls_private_key.clone());
        }
        if let Some(limit) = grpc_max_decoding_message_size {
            state
                .hashi
                .committees
                .set_grpc_max_decoding_message_size(limit);
        }

        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (checkpoint, _) = watch::channel(checkpoint);
        let state = Inner {
            ids,
            client: client.clone(),
            sender,
            checkpoint,
            state: RwLock::new(state),
            tls_private_key,
            grpc_max_decoding_message_size,
        }
        .pipe(Arc::new)
        .pipe(Self);

        let watcher_state = state.clone();
        let service = Service::new().spawn_aborting(async move {
            watcher::watcher(client, watcher_state, metrics).await;
            Ok(())
        });

        Ok((state, service))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.0.sender.subscribe()
    }

    fn notify(&self, notification: Notification) {
        let _ = self.0.sender.send(notification);
    }

    pub fn state(&self) -> RwLockReadGuard<'_, State> {
        self.0.state.read().unwrap()
    }

    // NOTE: This function must remain private to this module so that only this module and its
    // submodules are able to update the state
    fn state_mut(&self) -> RwLockWriteGuard<'_, State> {
        self.0.state.write().unwrap()
    }

    pub fn subscribe_checkpoint(&self) -> watch::Receiver<CheckpointInfo> {
        self.0.checkpoint.subscribe()
    }

    pub fn latest_checkpoint_height(&self) -> u64 {
        self.0.checkpoint.borrow().height
    }

    pub fn latest_checkpoint_timestamp_ms(&self) -> u64 {
        self.0.checkpoint.borrow().timestamp_ms
    }

    pub fn latest_checkpoint_epoch(&self) -> u64 {
        self.0.checkpoint.borrow().epoch
    }

    fn update_latest_checkpoint_info(&self, info: CheckpointInfo) {
        self.0.checkpoint.send_replace(info);
    }

    /// Apply committee config from `Inner` to the given hashi state and replace the current
    /// state in a single write lock acquisition.
    fn replace_hashi_state(&self, mut hashi: types::Hashi) {
        if let Some(tls_private_key) = &self.0.tls_private_key {
            hashi
                .committees
                .set_tls_private_key(tls_private_key.clone());
        }
        if let Some(limit) = self.0.grpc_max_decoding_message_size {
            hashi.committees.set_grpc_max_decoding_message_size(limit);
        }
        self.state_mut().hashi = hashi;
    }

    fn add_package_version(&self, version: u64, package_id: Address) {
        let mut state = self.state_mut();
        //TODO should we assert that this version is exactly the next one?
        state.package_versions.insert(version, package_id);
        state.package_ids.insert(package_id);
    }

    pub fn client(&self) -> Client {
        self.0.client.clone()
    }

    /// Returns the latest package id (highest version).
    pub fn package_id(&self) -> Option<Address> {
        self.state()
            .package_versions
            .last_key_value()
            .map(|(_, id)| *id)
    }

    pub fn hashi_id(&self) -> Address {
        self.state().hashi.id
    }

    pub fn tob_id(&self) -> Address {
        self.state().hashi.tob_id
    }

    /// Returns the current epoch.
    pub fn epoch(&self) -> u64 {
        self.state().hashi.committees.epoch()
    }

    /// Returns the MPC public key bytes.
    pub fn mpc_public_key(&self) -> Vec<u8> {
        self.state().hashi.committees.mpc_public_key().to_vec()
    }

    /// Returns all active proposals.
    pub fn proposals(&self) -> Vec<types::Proposal> {
        self.state()
            .hashi
            .proposals
            .proposals()
            .values()
            .cloned()
            .collect()
    }

    /// Returns a specific proposal by ID, if it exists.
    pub fn proposal(&self, id: &Address) -> Option<types::Proposal> {
        self.state().hashi.proposals.proposals().get(id).cloned()
    }

    /// Returns all committee members for the current epoch.
    pub fn committee_members(&self) -> Vec<types::MemberInfo> {
        self.state()
            .hashi
            .committees
            .members()
            .values()
            .cloned()
            .collect()
    }

    /// Returns a specific committee member by validator address, if it exists.
    pub fn committee_member(&self, validator: &Address) -> Option<types::MemberInfo> {
        self.state()
            .hashi
            .committees
            .members()
            .get(validator)
            .cloned()
    }

    pub fn current_committee(&self) -> Option<Committee> {
        self.state().hashi.committees.current_committee().cloned()
    }

    pub fn current_committee_members(&self) -> Option<Vec<CommitteeMember>> {
        self.state()
            .hashi()
            .committees
            .current_committee()
            .map(|c| c.members().to_vec())
    }

    pub fn deposit_requests(&self) -> Vec<types::DepositRequest> {
        self.state()
            .hashi()
            .deposit_queue
            .requests()
            .values()
            .cloned()
            .collect()
    }

    pub fn withdrawal_requests(&self) -> Vec<types::WithdrawalRequest> {
        self.state()
            .hashi()
            .withdrawal_queue
            .requests()
            .values()
            .cloned()
            .collect()
    }

    pub fn withdrawal_request(&self, id: &Address) -> Option<types::WithdrawalRequest> {
        self.state()
            .hashi()
            .withdrawal_queue
            .requests()
            .get(id)
            .cloned()
    }

    pub fn pending_withdrawals(&self) -> Vec<types::PendingWithdrawal> {
        self.state()
            .hashi()
            .withdrawal_queue
            .pending_withdrawals()
            .values()
            .cloned()
            .collect()
    }

    pub fn spent_utxos_entries(&self) -> Vec<(types::UtxoId, u64)> {
        self.state()
            .hashi()
            .utxo_pool
            .spent_utxos()
            .iter()
            .map(|(utxo_id, epoch)| (*utxo_id, *epoch))
            .collect()
    }

    pub fn active_utxos(&self) -> Vec<types::Utxo> {
        self.state()
            .hashi()
            .utxo_pool
            .active_utxos()
            .values()
            .cloned()
            .collect()
    }

    pub fn pending_withdrawal(&self, id: &Address) -> Option<types::PendingWithdrawal> {
        self.state()
            .hashi()
            .withdrawal_queue
            .pending_withdrawals()
            .get(id)
            .cloned()
    }

    pub fn active_utxo(&self, id: &types::UtxoId) -> Option<types::Utxo> {
        self.state()
            .hashi()
            .utxo_pool
            .active_utxos()
            .get(id)
            .cloned()
    }

    pub fn withdrawal_fee_btc(&self) -> u64 {
        self.state().hashi().config.withdrawal_fee_btc()
    }

    pub fn max_fee_rate(&self) -> u64 {
        self.state().hashi().config.max_fee_rate()
    }

    pub fn max_inputs(&self) -> u64 {
        self.state().hashi().config.max_inputs()
    }

    pub fn withdrawal_minimum(&self) -> u64 {
        self.state().hashi().config.withdrawal_minimum()
    }

    pub fn bitcoin_confirmation_threshold(&self) -> u32 {
        self.state().hashi().config.bitcoin_confirmation_threshold()
    }

    pub fn bridge_service_client(
        &self,
        validator: &Address,
    ) -> Option<hashi_types::proto::bridge_service_client::BridgeServiceClient<tonic_rustls::Channel>>
    {
        self.state()
            .hashi()
            .committees
            .client(validator)
            .map(|c| c.bridge_service_client())
    }

    pub fn mpc_service_client(
        &self,
        validator: &Address,
    ) -> Option<hashi_types::proto::mpc_service_client::MpcServiceClient<tonic_rustls::Channel>>
    {
        self.state()
            .hashi()
            .committees
            .client(validator)
            .map(|c| c.mpc_service_client())
    }

    /// Fetches the EpochCertsV1 for the given key from on-chain.
    /// Returns None if no certs exist for this key.
    // TODO: Cache this data in State and update via watcher events instead of fetching on-demand.
    pub async fn fetch_epoch_certs(
        &self,
        epoch: u64,
        batch_index: Option<u32>,
    ) -> Result<Option<move_types::EpochCertsV1>> {
        let tob_id = self.tob_id();
        let key = TobKey { epoch, batch_index };
        let key_bcs = bcs::to_bytes(&key)?;
        let mut stream = self
            .0
            .client
            .clone()
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(tob_id)
                    .with_page_size(u32::MAX)
                    .with_read_mask(FieldMask::from_paths([
                        DynamicField::path_builder().name().finish(),
                        DynamicField::path_builder().value().finish(),
                    ])),
            )
            .pipe(Box::pin);
        while let Some(field) = stream.try_next().await? {
            if field.name().value() == key_bcs.as_slice() {
                let epoch_certs: move_types::EpochCertsV1 = field.value().deserialize()?;
                return Ok(Some(epoch_certs));
            }
        }
        Ok(None)
    }

    /// Fetches all certificates for the given key from on-chain.
    /// Returns the protocol type and raw move types; caller is responsible for conversion.
    pub async fn fetch_certs(
        &self,
        epoch: u64,
        batch_index: Option<u32>,
    ) -> Result<
        Option<(
            move_types::ProtocolType,
            Vec<(
                Address,
                move_types::CertifiedMessage<move_types::DealerMessagesHashV1>,
            )>,
        )>,
    > {
        let epoch_certs = match self.fetch_epoch_certs(epoch, batch_index).await? {
            Some(certs) => certs,
            None => return Ok(None),
        };
        let Some(head) = epoch_certs.certs.head else {
            return Ok(Some((epoch_certs.protocol_type, vec![])));
        };
        let mut nodes: std::collections::HashMap<
            Address,
            move_types::LinkedTableNode<
                Address,
                move_types::CertifiedMessage<move_types::DealerMessagesHashV1>,
            >,
        > = std::collections::HashMap::new();
        let mut stream = self
            .0
            .client
            .clone()
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(epoch_certs.certs.id)
                    .with_page_size(u32::MAX)
                    .with_read_mask(FieldMask::from_paths([
                        DynamicField::path_builder().name().finish(),
                        DynamicField::path_builder().value().finish(),
                    ])),
            )
            .pipe(Box::pin);
        while let Some(field) = stream.try_next().await? {
            let dealer: Address = field.name().deserialize()?;
            let node = field.value().deserialize()?;
            nodes.insert(dealer, node);
        }
        // Traverse in insertion order following LinkedTable's linked list
        let mut certificates = Vec::with_capacity(nodes.len());
        let mut current = Some(head);
        while let Some(dealer) = current {
            let Some(node) = nodes.remove(&dealer) else {
                break;
            };
            certificates.push((dealer, node.value));
            current = node.next;
        }
        Ok(Some((epoch_certs.protocol_type, certificates)))
    }
}

impl State {
    pub fn package_versions(&self) -> &BTreeMap<u64, Address> {
        &self.package_versions
    }

    pub fn hashi(&self) -> &types::Hashi {
        &self.hashi
    }

    async fn scrape(client: Client, ids: HashiIds) -> Result<(Self, CheckpointInfo)> {
        let (package_versions, (checkpoint_info, hashi)) = tokio::try_join!(
            scrape_package_versions(client.clone(), ids.package_id),
            scrape_hashi(client, ids.hashi_object_id),
        )?;

        let package_ids = package_versions.values().cloned().collect();

        Ok((
            State {
                package_versions,
                package_ids,
                hashi,
            },
            checkpoint_info,
        ))
    }
}

// List out all the package versions for hashi so that we can stay ontop of upgrades
// dynamically
async fn scrape_package_versions(
    client: Client,
    package_id: Address,
) -> Result<BTreeMap<u64, Address>> {
    let package_versions: BTreeMap<u64, Address> = client
        .list_package_versions(
            ListPackageVersionsRequest::new(&package_id).with_page_size(u32::MAX),
        )
        .and_then(|package_version| async move {
            let storage_id = package_version
                .package_id()
                .parse::<Address>()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            let version = package_version.version();
            Ok((version, storage_id))
        })
        .try_collect()
        .await?;

    Ok(package_versions)
}

async fn scrape_hashi(
    mut client: Client,
    hashi_object_id: Address,
) -> Result<(CheckpointInfo, types::Hashi)> {
    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&hashi_object_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().owner().finish(),
                Object::path_builder().contents().finish(),
                Object::path_builder().object_id(),
                Object::path_builder().version(),
            ])),
        )
        .await?;
    let checkpoint_info = CheckpointInfo {
        height: response
            .checkpoint_height()
            .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?,
        timestamp_ms: response
            .timestamp_ms()
            .ok_or_else(|| anyhow!("response missing X_SUI_TIMESTAMP_MS header"))?,
        epoch: response
            .epoch()
            .ok_or_else(|| anyhow!("response missing X_SUI_EPOCH header"))?,
    };

    let move_types::Hashi {
        id,
        committees,
        config,
        treasury,
        deposit_queue,
        withdrawal_queue,
        utxo_pool,
        proposals,
        tob,
    } = response.get_ref().object().contents().deserialize()?;

    let (
        member_info,
        committees_per_epoch,
        treasury,
        deposit_queue,
        withdrawal_queue,
        utxo_pool,
        proposals,
    ) = tokio::try_join!(
        scrape_all_member_info(client.clone(), committees.members.id),
        scrape_committees(client.clone(), committees.committees.id),
        scrape_treasury(client.clone(), treasury),
        scrape_deposit_requests(client.clone(), deposit_queue.requests.id),
        scrape_withdrawal_queue(client.clone(), withdrawal_queue),
        scrape_utxo_pool(client.clone(), utxo_pool),
        scrape_proposals(client.clone(), proposals),
    )?;

    let mut committee_set =
        types::CommitteeSet::new(committees.members.id, committees.committees.id);
    committee_set
        .set_epoch(committees.epoch)
        .set_pending_epoch_change(committees.pending_epoch_change)
        .set_mpc_public_key(committees.mpc_public_key)
        .set_members(member_info)
        .set_committees(committees_per_epoch);

    Ok((
        checkpoint_info,
        types::Hashi {
            id,
            committees: committee_set,
            config: convert_move_config(config),
            treasury,
            deposit_queue,
            withdrawal_queue,
            utxo_pool,
            proposals,
            tob_id: tob.id,
        },
    ))
}

fn convert_move_config(config: move_types::Config) -> types::Config {
    types::Config {
        config: config
            .config
            .into_iter()
            .map(|(key, value)| (key, convert_move_config_value(value)))
            .collect(),
        enabled_versions: config.enabled_versions.contents.into_iter().collect(),
        upgrade_cap: config.upgrade_cap.map(convert_move_upgrade_cap),
    }
}

fn convert_move_config_value(value: move_types::ConfigValue) -> types::ConfigValue {
    match value {
        move_types::ConfigValue::U64(v) => types::ConfigValue::U64(v),
        move_types::ConfigValue::Address(address) => types::ConfigValue::Address(address),
        move_types::ConfigValue::String(s) => types::ConfigValue::String(s),
        move_types::ConfigValue::Bool(b) => types::ConfigValue::Bool(b),
        move_types::ConfigValue::Bytes(bytes) => types::ConfigValue::Bytes(bytes),
    }
}

fn convert_move_upgrade_cap(cap: move_types::UpgradeCap) -> types::UpgradeCap {
    types::UpgradeCap {
        id: cap.id,
        package: cap.package,
        version: cap.version,
        policy: cap.policy,
    }
}

async fn scrape_treasury(
    client: Client,
    treasury: move_types::Treasury,
) -> Result<types::Treasury> {
    let mut treasury_caps: BTreeMap<TypeTag, types::TreasuryCap> = BTreeMap::new();
    let mut metadata_caps: BTreeMap<TypeTag, types::MetadataCap> = BTreeMap::new();

    let mut stream = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(treasury.objects.id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                    DynamicField::path_builder()
                        .child_object()
                        .contents()
                        .finish(),
                ])),
        )
        .pipe(Box::pin);

    while let Some(field) = stream.try_next().await? {
        let type_tag = field.child_object().contents().name().parse()?;
        let contents = field.child_object().contents().value();

        if let Some(treasury_cap) = types::TreasuryCap::try_from_contents(&type_tag, contents) {
            treasury_caps.insert(treasury_cap.coin_type.clone(), treasury_cap);
        } else if let Some(metadata_cap) =
            types::MetadataCap::try_from_contents(&type_tag, contents)
        {
            metadata_caps.insert(metadata_cap.coin_type.clone(), metadata_cap);
        } else {
            tracing::warn!("unknown type stored in treasury");
        }
    }

    Ok(types::Treasury {
        id: treasury.objects.id,
        treasury_caps,
        metadata_caps,
    })
}

pub(super) async fn fetch_treasury_cap(
    client: &mut Client,
    treasury_cap_id: Address,
) -> Result<types::TreasuryCap> {
    let response =
        client
            .ledger_client()
            .get_object(GetObjectRequest::new(&treasury_cap_id).with_read_mask(
                FieldMask::from_paths([Object::path_builder().contents().finish()]),
            ))
            .await?;

    let object = response.into_inner();
    let type_tag = object.object().contents().name().parse()?;
    let contents = object.object().contents().value();

    types::TreasuryCap::try_from_contents(&type_tag, contents)
        .ok_or_else(|| anyhow!("failed to parse TreasuryCap from object {treasury_cap_id}"))
}

async fn scrape_all_member_info(
    client: Client,
    member_info_id: Address,
) -> Result<BTreeMap<Address, types::MemberInfo>> {
    let member_info: BTreeMap<Address, types::MemberInfo> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(member_info_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let info: move_types::MemberInfo = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;

            Ok(info)
        })
        .map_ok(
            |move_types::MemberInfo {
                 validator_address,
                 operator_address,
                 next_epoch_public_key,
                 endpoint_url,
                 tls_public_key,
                 next_epoch_encryption_public_key,
             }| {
                let info = types::MemberInfo {
                    validator_address,
                    operator_address,
                    next_epoch_public_key: convert_move_uncompressed_g1_pubkey(
                        &next_epoch_public_key,
                    ),
                    endpoint_url: endpoint_url.try_into().ok(),
                    tls_public_key: tls_public_key.as_slice().try_into().ok(),
                    next_epoch_encryption_public_key: parse_encryption_public_key(
                        next_epoch_encryption_public_key.as_slice(),
                    )
                    .map(Into::into),
                };

                (info.validator_address, info)
            },
        )
        .try_collect()
        .await?;
    Ok(member_info)
}

pub(crate) async fn scrape_member_info(
    mut client: Client,
    member_info_id: Address,
    validator: Address,
) -> Result<types::MemberInfo> {
    let field_id =
        member_info_id.derive_dynamic_child_id(&TypeTag::Address, &validator.to_bcs().unwrap());

    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&field_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().owner().finish(),
                Object::path_builder().contents().finish(),
                Object::path_builder().object_id(),
                Object::path_builder().version(),
            ])),
        )
        .await?
        .into_inner();

    let field: move_types::Field<Address, move_types::MemberInfo> = response
        .object()
        .contents()
        .deserialize()
        .map_err(|e| tonic::Status::from_error(e.into()))?;

    let move_types::MemberInfo {
        validator_address,
        operator_address,
        next_epoch_public_key,
        endpoint_url,
        tls_public_key,
        next_epoch_encryption_public_key,
    } = field.value;

    let info = types::MemberInfo {
        validator_address,
        operator_address,
        next_epoch_public_key: convert_move_uncompressed_g1_pubkey(&next_epoch_public_key),
        endpoint_url: endpoint_url.try_into().ok(),
        tls_public_key: tls_public_key.as_slice().try_into().ok(),
        next_epoch_encryption_public_key: parse_encryption_public_key(
            next_epoch_encryption_public_key.as_slice(),
        )
        .map(Into::into),
    };
    Ok(info)
}

async fn scrape_committees(
    client: Client,
    committees_id: Address,
) -> Result<BTreeMap<u64, Committee>> {
    let committees: BTreeMap<u64, Committee> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(committees_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let committee: move_types::Committee = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;

            Ok(committee)
        })
        .map_ok(|move_committee| {
            let members = move_committee
                .members
                .into_iter()
                .map(convert_move_committee_member)
                .collect();
            let committee = Committee::new(members, move_committee.epoch);
            (move_committee.epoch, committee)
        })
        .try_collect()
        .await?;

    Ok(committees)
}

async fn scrape_committee(
    mut client: Client,
    committees_id: Address,
    epoch: u64,
) -> Result<Committee> {
    let field_id = committees_id.derive_dynamic_child_id(&TypeTag::U64, &epoch.to_bcs().unwrap());

    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&field_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().owner().finish(),
                Object::path_builder().contents().finish(),
                Object::path_builder().object_id(),
                Object::path_builder().version(),
            ])),
        )
        .await?
        .into_inner();

    let field: move_types::Field<u64, move_types::Committee> = response
        .object()
        .contents()
        .deserialize()
        .map_err(|e| tonic::Status::from_error(e.into()))?;

    let members = field
        .value
        .members
        .into_iter()
        .map(convert_move_committee_member)
        .collect();
    let committee = Committee::new(members, field.value.epoch);
    Ok(committee)
}

fn convert_move_committee_member(
    move_types::CommitteeMember {
        validator_address,
        public_key,
        encryption_public_key,
        weight,
    }: move_types::CommitteeMember,
) -> CommitteeMember {
    CommitteeMember::new(
        validator_address,
        convert_move_uncompressed_g1_pubkey(&public_key),
        // Use fallback key for nodes without valid encryption key.
        // These nodes cannot decrypt shares but still count toward thresholds.
        parse_encryption_public_key(encryption_public_key.as_slice())
            .map(Into::into)
            .unwrap_or_else(fallback_encryption_public_key),
        weight,
    )
}

fn convert_move_uncompressed_g1_pubkey(uncompressed_g1: &[u8]) -> BLS12381PublicKey {
    use fastcrypto::traits::ToFromBytes;
    let pubkey = blst::min_pk::PublicKey::deserialize(uncompressed_g1)
        .expect("onchain value is uncompressed G1");
    BLS12381PublicKey::from_bytes(pubkey.to_bytes().as_slice()).unwrap()
}

async fn scrape_deposit_requests(
    client: Client,
    deposit_queue_id: Address,
) -> Result<types::DepositRequestQueue> {
    let requests: BTreeMap<Address, types::DepositRequest> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(deposit_queue_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let deposit_request: move_types::DepositRequest = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            Ok(deposit_request)
        })
        .map_ok(
            |move_types::DepositRequest {
                 id,
                 utxo,
                 timestamp_ms,
             }| {
                let utxo = convert_move_utxo(utxo);
                (
                    id,
                    types::DepositRequest {
                        id,
                        utxo,
                        timestamp_ms,
                    },
                )
            },
        )
        .try_collect()
        .await?;

    let deposit_requests = types::DepositRequestQueue {
        id: deposit_queue_id,
        requests,
    };

    Ok(deposit_requests)
}

async fn scrape_withdrawal_queue(
    client: Client,
    withdrawal_queue: move_types::WithdrawalRequestQueue,
) -> Result<types::WithdrawalRequestQueue> {
    let (requests, pending_withdrawals) = tokio::try_join!(
        scrape_withdrawal_requests(client.clone(), withdrawal_queue.requests.id),
        scrape_pending_withdrawals(client.clone(), withdrawal_queue.pending_withdrawals.id),
    )?;

    Ok(types::WithdrawalRequestQueue {
        requests_id: withdrawal_queue.requests.id,
        requests,
        pending_withdrawals_id: withdrawal_queue.pending_withdrawals.id,
        pending_withdrawals,
        num_consumed_presigs: withdrawal_queue.num_consumed_presigs,
    })
}

async fn scrape_withdrawal_requests(
    client: Client,
    requests_id: Address,
) -> Result<BTreeMap<Address, types::WithdrawalRequest>> {
    let requests: BTreeMap<Address, types::WithdrawalRequest> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(requests_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let withdrawal_request: move_types::WithdrawalRequest = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            Ok(withdrawal_request)
        })
        .map_ok(|move_types::WithdrawalRequest { info, approved, .. }| {
            (
                info.id,
                types::WithdrawalRequest {
                    id: info.id,
                    btc_amount: info.btc_amount,
                    bitcoin_address: info.bitcoin_address,
                    timestamp_ms: info.timestamp_ms,
                    requester_address: info.requester_address,
                    sui_tx_digest: info.sui_tx_digest,
                    approved,
                },
            )
        })
        .try_collect()
        .await?;

    Ok(requests)
}

async fn scrape_pending_withdrawals(
    client: Client,
    pending_withdrawals_id: Address,
) -> Result<BTreeMap<Address, types::PendingWithdrawal>> {
    let pending_withdrawals: BTreeMap<Address, types::PendingWithdrawal> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(pending_withdrawals_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let pending: move_types::PendingWithdrawal = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            Ok(pending)
        })
        .map_ok(
            |move_types::PendingWithdrawal {
                 txid,
                 id,
                 requests,
                 inputs,
                 withdrawal_outputs,
                 change_output,
                 timestamp_ms,
                 randomness,
                 signatures,
             }| {
                let requests = requests
                    .into_iter()
                    .map(convert_move_withdrawal_request_info)
                    .collect();
                let inputs = inputs.into_iter().map(convert_move_utxo).collect();
                let withdrawal_outputs = withdrawal_outputs
                    .into_iter()
                    .map(|o| types::OutputUtxo {
                        amount: o.amount,
                        bitcoin_address: o.bitcoin_address,
                    })
                    .collect();
                let change_output = change_output.map(|o| types::OutputUtxo {
                    amount: o.amount,
                    bitcoin_address: o.bitcoin_address,
                });
                (
                    id,
                    types::PendingWithdrawal {
                        id,
                        txid,
                        requests,
                        inputs,
                        withdrawal_outputs,
                        change_output,
                        timestamp_ms,
                        randomness,
                        signatures,
                    },
                )
            },
        )
        .try_collect()
        .await?;

    Ok(pending_withdrawals)
}

fn convert_move_utxo(
    move_types::Utxo {
        id: move_types::UtxoId { txid, vout },
        amount,
        derivation_path,
    }: move_types::Utxo,
) -> types::Utxo {
    types::Utxo {
        id: types::UtxoId { txid, vout },
        amount,
        derivation_path,
    }
}

fn convert_move_withdrawal_request_info(
    info: move_types::WithdrawalRequestInfo,
) -> types::WithdrawalRequestInfo {
    types::WithdrawalRequestInfo {
        id: info.id,
        btc_amount: info.btc_amount,
        bitcoin_address: info.bitcoin_address,
        timestamp_ms: info.timestamp_ms,
        requester_address: info.requester_address,
        sui_tx_digest: info.sui_tx_digest,
    }
}

fn convert_move_pending_withdrawal(
    move_types::PendingWithdrawal {
        id,
        txid,
        requests,
        inputs,
        withdrawal_outputs,
        change_output,
        timestamp_ms,
        randomness,
        signatures,
    }: move_types::PendingWithdrawal,
) -> types::PendingWithdrawal {
    let convert_output = |o: move_types::OutputUtxo| types::OutputUtxo {
        amount: o.amount,
        bitcoin_address: o.bitcoin_address,
    };
    types::PendingWithdrawal {
        id,
        txid,
        requests: requests
            .into_iter()
            .map(convert_move_withdrawal_request_info)
            .collect(),
        inputs: inputs.into_iter().map(convert_move_utxo).collect(),
        withdrawal_outputs: withdrawal_outputs.into_iter().map(convert_output).collect(),
        change_output: change_output.map(convert_output),
        timestamp_ms,
        randomness,
        signatures,
    }
}

pub(super) async fn fetch_pending_withdrawal(
    client: &mut Client,
    pending_withdrawals_id: Address,
    pending_id: Address,
) -> Result<types::PendingWithdrawal> {
    let field_id = pending_withdrawals_id
        .derive_dynamic_child_id(&TypeTag::Address, &pending_id.to_bcs().unwrap());

    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&field_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().contents().finish(),
            ])),
        )
        .await?;

    let field: move_types::Field<Address, move_types::PendingWithdrawal> = response
        .into_inner()
        .object()
        .contents()
        .deserialize()
        .map_err(|e| anyhow!("failed to deserialize PendingWithdrawal: {e}"))?;

    Ok(convert_move_pending_withdrawal(field.value))
}

async fn scrape_utxo_pool(
    client: Client,
    utxo_pool: move_types::UtxoPool,
) -> Result<types::UtxoPool> {
    let (active_utxos, spent_utxos) = tokio::try_join!(
        scrape_active_utxos(client.clone(), utxo_pool.active_utxos.id),
        scrape_spent_utxos(client.clone(), utxo_pool.spent_utxos.id),
    )?;

    Ok(types::UtxoPool {
        active_utxos_id: utxo_pool.active_utxos.id,
        active_utxos,
        spent_utxos_id: utxo_pool.spent_utxos.id,
        spent_utxos,
    })
}

async fn scrape_active_utxos(
    client: Client,
    active_utxos_id: Address,
) -> Result<BTreeMap<types::UtxoId, types::Utxo>> {
    let active_utxos: BTreeMap<types::UtxoId, types::Utxo> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(active_utxos_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let utxo: move_types::Utxo = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            Ok(utxo)
        })
        .map_ok(|utxo| {
            let utxo = convert_move_utxo(utxo);
            (utxo.id, utxo)
        })
        .try_collect()
        .await?;

    Ok(active_utxos)
}

async fn scrape_spent_utxos(
    client: Client,
    spent_utxos_id: Address,
) -> Result<BTreeMap<types::UtxoId, u64>> {
    let spent_utxos: BTreeMap<types::UtxoId, u64> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(spent_utxos_id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ])),
        )
        .and_then(|field| async move {
            let utxo_id: move_types::UtxoId = field
                .name()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            let spent_epoch: u64 = field
                .value()
                .deserialize()
                .map_err(|e| tonic::Status::from_error(e.into()))?;
            Ok((utxo_id, spent_epoch))
        })
        .map_ok(|(utxo_id, spent_epoch): (move_types::UtxoId, u64)| (utxo_id.into(), spent_epoch))
        .try_collect()
        .await?;

    Ok(spent_utxos)
}

async fn scrape_proposals(
    client: Client,
    proposals_bag: move_types::Bag,
) -> Result<types::Proposals> {
    let mut proposals: BTreeMap<Address, types::Proposal> = BTreeMap::new();

    let mut stream = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(proposals_bag.id)
                .with_page_size(u32::MAX)
                .with_read_mask(FieldMask::from_paths([
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder()
                        .child_object()
                        .contents()
                        .finish(),
                ])),
        )
        .pipe(Box::pin);

    while let Some(field) = stream.try_next().await? {
        // Parse the proposal type from the type tag
        // The type will be something like: <package>::proposal::Proposal<<package>::update_deposit_fee::UpdateDepositFee>
        let type_tag: TypeTag = field.child_object().contents().name().parse()?;
        let proposal_type = parse_proposal_type(&type_tag);

        // Deserialize proposal based on the proposal type
        let contents = field.child_object().contents().value();
        let result: Option<(Address, u64)> = match &proposal_type {
            types::ProposalType::UpdateDepositFee => {
                bcs::from_bytes::<move_types::Proposal<move_types::UpdateDepositFee>>(contents)
                    .ok()
                    .map(|p| (p.id, p.timestamp_ms))
            }
            types::ProposalType::EnableVersion => {
                bcs::from_bytes::<move_types::Proposal<move_types::EnableVersion>>(contents)
                    .ok()
                    .map(|p| (p.id, p.timestamp_ms))
            }
            types::ProposalType::DisableVersion => {
                bcs::from_bytes::<move_types::Proposal<move_types::DisableVersion>>(contents)
                    .ok()
                    .map(|p| (p.id, p.timestamp_ms))
            }
            types::ProposalType::Upgrade => {
                bcs::from_bytes::<move_types::Proposal<move_types::Upgrade>>(contents)
                    .ok()
                    .map(|p| (p.id, p.timestamp_ms))
            }
            types::ProposalType::Unknown(_) => None,
        };

        if let Some((id, timestamp_ms)) = result {
            proposals.insert(
                id,
                types::Proposal {
                    id,
                    timestamp_ms,
                    proposal_type,
                },
            );
        } else {
            tracing::warn!("Failed to deserialize proposal with type {:?}", type_tag);
        }
    }

    Ok(types::Proposals {
        id: proposals_bag.id,
        size: proposals_bag.size,
        proposals,
    })
}

fn parse_proposal_type(type_tag: &TypeTag) -> types::ProposalType {
    let TypeTag::Struct(struct_tag) = type_tag else {
        return types::ProposalType::Unknown(format!("{:?}", type_tag));
    };

    // The type is Proposal<T>, we need to extract T
    if struct_tag.module() != "proposal" || struct_tag.name() != "Proposal" {
        return types::ProposalType::Unknown(format!("{:?}", type_tag));
    }

    let Some(type_param) = struct_tag.type_params().first() else {
        return types::ProposalType::Unknown(format!("{:?}", type_tag));
    };

    let TypeTag::Struct(inner_tag) = type_param else {
        return types::ProposalType::Unknown(format!("{:?}", type_param));
    };

    match (inner_tag.module().as_str(), inner_tag.name().as_str()) {
        ("update_deposit_fee", "UpdateDepositFee") => types::ProposalType::UpdateDepositFee,
        ("enable_version", "EnableVersion") => types::ProposalType::EnableVersion,
        ("disable_version", "DisableVersion") => types::ProposalType::DisableVersion,
        ("upgrade", "Upgrade") => types::ProposalType::Upgrade,
        _ => types::ProposalType::Unknown(format!("{}::{}", inner_tag.module(), inner_tag.name())),
    }
}

pub trait MoveType {
    const PACKAGE_VERSION: u64 = 1;
    const MODULE: &'static str;
    const NAME: &'static str;
    const MODULE_NAME: (&'static str, &'static str) = (Self::MODULE, Self::NAME);
}

#[cfg(test)]
mod tests {
    use fastcrypto::serde_helpers::ToFromByteArray;
    use fastcrypto::traits::KeyPair;
    use fastcrypto::traits::ToFromBytes;

    use crate::mpc::EncryptionGroupElement;

    use super::*;

    #[test]
    fn test_convert_move_committee_member() {
        let mut rng = rand::thread_rng();
        let validator_address =
            Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        let signing_keypair = fastcrypto::bls12381::min_pk::BLS12381KeyPair::generate(&mut rng);
        let encryption_private_key =
            fastcrypto_tbls::ecies_v1::PrivateKey::<EncryptionGroupElement>::new(&mut rng);
        let encryption_public_key =
            fastcrypto_tbls::ecies_v1::PublicKey::from_private_key(&encryption_private_key);

        let move_committee_member = move_types::CommitteeMember {
            validator_address,
            public_key: signing_keypair.public().as_bytes().to_owned(),
            encryption_public_key: encryption_public_key.as_element().to_byte_array().into(),
            weight: 1,
        };
        let committee_member = convert_move_committee_member(move_committee_member);

        assert_eq!(committee_member.validator_address(), validator_address);
        assert_eq!(committee_member.public_key(), signing_keypair.public());
        assert_eq!(
            committee_member.encryption_public_key().as_element(),
            encryption_public_key.as_element()
        );
        assert_eq!(committee_member.weight(), 1);
    }

    #[test]
    fn test_convert_move_committee_member_uses_fallback_key() {
        let mut rng = rand::thread_rng();
        let validator_address =
            Address::from_hex("0x1234567890abcdef1234567890abcdef12345678").unwrap();
        let signing_keypair = fastcrypto::bls12381::min_pk::BLS12381KeyPair::generate(&mut rng);
        let mut encryption_key_vec = vec![0u8; 32];
        encryption_key_vec[0] = 1;

        let move_committee_member = move_types::CommitteeMember {
            validator_address,
            public_key: signing_keypair.public().as_bytes().to_owned(),
            encryption_public_key: encryption_key_vec,
            weight: 1,
        };
        let committee_member = convert_move_committee_member(move_committee_member);

        assert_eq!(
            *committee_member.encryption_public_key(),
            fallback_encryption_public_key()
        )
    }
}
