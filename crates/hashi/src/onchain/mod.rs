use anyhow::Result;
use anyhow::anyhow;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use futures::TryStreamExt;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::sync::RwLockWriteGuard;
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
use crate::dkg::fallback_encryption_public_key;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeMember;
use hashi_types::move_types;

const BROADCAST_CHANNEL_CAPACITY: usize = 100;

pub mod types;
mod watcher;

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
}

/// Information about the latest processed checkpoint
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckpointInfo {
    /// The checkpoint height
    pub height: u64,
    /// The checkpoint timestamp in milliseconds since Unix epoch
    pub timestamp_ms: u64,
}

struct Inner {
    #[allow(unused)]
    ids: HashiIds,
    client: Client,
    sender: broadcast::Sender<Notification>,
    /// The checkpoint information that this state is recent to
    checkpoint: watch::Sender<CheckpointInfo>,
    state: RwLock<State>,
}

#[derive(Debug)]
pub struct State {
    package_versions: BTreeMap<u64, Address>,
    package_ids: BTreeSet<Address>,
    hashi: types::Hashi,
}

impl OnchainState {
    pub async fn new(
        sui_rpc_url: &str,
        ids: HashiIds,
        tls_private_key: Option<ed25519_dalek::SigningKey>,
    ) -> Result<Self> {
        let client = Client::new(sui_rpc_url)?;

        let (mut state, checkpoint) = State::scrape(client.clone(), ids).await?;
        if let Some(tls_private_key) = tls_private_key {
            state.hashi.committees.set_tls_private_key(tls_private_key);
        }

        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (checkpoint, _) = watch::channel(checkpoint);
        let state = Inner {
            ids,
            client: client.clone(),
            sender,
            checkpoint,
            state: RwLock::new(state),
        }
        .pipe(Arc::new)
        .pipe(Self);

        tokio::spawn(watcher::watcher(client, state.clone()));

        Ok(state)
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

    fn update_latest_checkpoint_info(&self, info: CheckpointInfo) {
        self.0.checkpoint.send_replace(info);
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

    /// Fetches the EpochCertsV1 for the given epoch from on-chain.
    /// Returns None if no certs exist for this epoch.
    // TODO: Cache this data in State and update via watcher events instead of fetching on-demand.
    pub async fn fetch_epoch_certs(&self, epoch: u64) -> Result<Option<move_types::EpochCertsV1>> {
        let tob_id = self.tob_id();
        let epoch_key_bcs = bcs::to_bytes(&epoch)?;
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
            if field.name().value() == epoch_key_bcs.as_slice() {
                let epoch_certs: move_types::EpochCertsV1 = field.value().deserialize()?;
                return Ok(Some(epoch_certs));
            }
        }
        Ok(None)
    }

    /// Fetches all certificates for the given epoch from on-chain.
    /// Returns the protocol type and raw move types; caller is responsible for conversion.
    pub async fn fetch_certs(
        &self,
        epoch: u64,
    ) -> Result<
        Option<(
            move_types::ProtocolType,
            Vec<(
                Address,
                move_types::CertifiedMessage<move_types::DealerMessagesHashV1>,
            )>,
        )>,
    > {
        let epoch_certs = match self.fetch_epoch_certs(epoch).await? {
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
    };

    // Extract initial shared version from owner
    let initial_shared_version = response.get_ref().object().owner().version();

    let move_types::Hashi {
        id,
        committees,
        config,
        treasury,
        deposit_queue,
        utxo_pool,
        proposals,
        tob,
    } = response.get_ref().object().contents().deserialize()?;

    let (member_info, committees_per_epoch, treasury, deposit_queue, utxo_pool) = tokio::try_join!(
        scrape_all_member_info(client.clone(), committees.members.id),
        scrape_committees(client.clone(), committees.committees.id),
        scrape_treasury(client.clone(), treasury),
        scrape_deposit_requests(client.clone(), deposit_queue.requests.id),
        scrape_utxo_pool(client.clone(), utxo_pool.utxos.id),
    )?;

    let mut committee_set =
        types::CommitteeSet::new(committees.members.id, committees.committees.id);
    committee_set
        .set_epoch(committees.epoch)
        .set_pending_epoch_change(committees.pending_epoch_change)
        .set_members(member_info)
        .set_committees(committees_per_epoch);

    Ok((
        checkpoint_info,
        types::Hashi {
            id,
            initial_shared_version,
            committees: committee_set,
            config: convert_move_config(config),
            treasury,
            deposit_queue,
            utxo_pool,
            proposals: convert_move_proposals(proposals),
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

fn convert_move_proposals(proposals: move_types::Bag) -> types::Proposals {
    types::Proposals {
        id: proposals.id,
        size: proposals.size,
    }
}

async fn scrape_treasury(
    client: Client,
    treasury: move_types::Treasury,
) -> Result<types::Treasury> {
    let mut treasury_caps: BTreeMap<TypeTag, types::TreasuryCap> = BTreeMap::new();
    let mut metadata_caps: BTreeMap<TypeTag, types::MetadataCap> = BTreeMap::new();
    let mut coins: BTreeMap<TypeTag, types::Coin> = BTreeMap::new();

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
        } else if let Some(coin) = types::Coin::try_from_contents(&type_tag, contents) {
            coins.insert(coin.coin_type.clone(), coin);
        } else {
            tracing::warn!("unknown type stored in treasury");
        }
    }

    Ok(types::Treasury {
        id: treasury.objects.id,
        treasury_caps,
        metadata_caps,
        coins,
    })
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
                 https_address,
                 tls_public_key,
                 next_epoch_encryption_public_key,
             }| {
                let info = types::MemberInfo {
                    validator_address,
                    operator_address,
                    next_epoch_public_key: convert_move_uncompressed_g1_pubkey(
                        &next_epoch_public_key,
                    ),
                    https_address: https_address.try_into().ok(),
                    tls_public_key: tls_public_key.as_slice().try_into().ok(),
                    next_epoch_encryption_public_key: crate::dkg::EncryptionGroupElement::try_from(
                        next_epoch_encryption_public_key.as_slice(),
                    )
                    .map(Into::into)
                    .ok(),
                };

                (info.validator_address, info)
            },
        )
        .try_collect()
        .await?;
    Ok(member_info)
}

async fn scrape_member_info(
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
        https_address,
        tls_public_key,
        next_epoch_encryption_public_key,
    } = field.value;

    let info = types::MemberInfo {
        validator_address,
        operator_address,
        next_epoch_public_key: convert_move_uncompressed_g1_pubkey(&next_epoch_public_key),
        https_address: https_address.try_into().ok(),
        tls_public_key: tls_public_key.as_slice().try_into().ok(),
        next_epoch_encryption_public_key: crate::dkg::EncryptionGroupElement::try_from(
            next_epoch_encryption_public_key.as_slice(),
        )
        .map(Into::into)
        .ok(),
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
        crate::dkg::EncryptionGroupElement::try_from(encryption_public_key.as_slice())
            .map(Into::into)
            .unwrap_or_else(|_| fallback_encryption_public_key()),
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

async fn scrape_utxo_pool(client: Client, utxo_pool_id: Address) -> Result<types::UtxoPool> {
    let utxos: BTreeMap<types::UtxoId, types::Utxo> = client
        .list_dynamic_fields(
            ListDynamicFieldsRequest::default()
                .with_parent(utxo_pool_id)
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

    let pool = types::UtxoPool {
        id: utxo_pool_id,
        utxos,
    };

    Ok(pool)
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

    use crate::dkg::EncryptionGroupElement;

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
