use anyhow::Result;
use anyhow::anyhow;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use futures::TryStreamExt;
use std::sync::RwLockReadGuard;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::{
    Client,
    proto::sui::rpc::v2::{GetObjectRequest, ListPackageVersionsRequest, Object},
};
use sui_sdk_types::Address;
use sui_sdk_types::TypeTag;
use tap::Pipe;
use tokio::sync::broadcast;

use crate::bls::BlsCommittee;
use crate::bls::BlsCommitteeMember;
use crate::config::HashiIds;

const BROADCAST_CHANNEL_CAPACITY: usize = 100;

mod move_types;
pub mod types;

#[derive(Clone, Debug)]
pub struct OnchainState(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    #[allow(unused)]
    ids: HashiIds,
    #[allow(unused)]
    sender: broadcast::Sender<()>,
    state: RwLock<State>,
}

#[derive(Debug)]
pub struct State {
    /// The checkpoint height that this state is recent to
    #[allow(unused)]
    checkpoint: u64,
    package_versions: BTreeMap<u64, Address>,
    hashi: types::Hashi,
}

impl OnchainState {
    pub async fn new(sui_rpc_url: &str, ids: HashiIds) -> Result<Self> {
        let client = Client::new(sui_rpc_url)?;

        let (sender, _) = broadcast::channel::<()>(BROADCAST_CHANNEL_CAPACITY);

        let state = State::scrape(client.clone(), ids).await?.pipe(RwLock::new);

        //TODO spawn watcher and enable partial updates and notifications

        Inner { ids, sender, state }
            .pipe(Arc::new)
            .pipe(Self)
            .pipe(Ok)
    }

    pub fn state(&self) -> RwLockReadGuard<'_, State> {
        self.0.state.read().unwrap()
    }
}

impl State {
    pub fn package_versions(&self) -> &BTreeMap<u64, Address> {
        &self.package_versions
    }

    pub fn hashi(&self) -> &types::Hashi {
        &self.hashi
    }

    async fn scrape(client: Client, ids: HashiIds) -> Result<Self> {
        let (package_versions, (checkpoint, hashi)) = tokio::try_join!(
            scrape_package_versions(client.clone(), ids.package_id),
            scrape_hashi(client, ids.hashi_object_id),
        )?;

        Ok(State {
            checkpoint,
            package_versions,
            hashi,
        })
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

async fn scrape_hashi(mut client: Client, hashi_object_id: Address) -> Result<(u64, types::Hashi)> {
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
    let checkpoint = response
        .checkpoint_height()
        .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?;

    let move_types::Hashi {
        id,
        committees,
        config,
        treasury,
        deposit_queue,
        utxo_pool,
    } = response.get_ref().object().contents().deserialize()?;

    let (member_info, committees_per_epoch, treasury, deposit_queue, utxo_pool) = tokio::try_join!(
        scrape_member_info(client.clone(), committees.members.id),
        scrape_committees(client.clone(), committees.committees.id),
        scrape_treasury(client.clone(), treasury),
        scrape_deposit_requests(client.clone(), deposit_queue.requests.id),
        scrape_utxo_pool(client.clone(), utxo_pool.utxos.id),
    )?;

    let committees = types::CommitteeSet {
        members_id: committees.members.id,
        members: member_info,
        epoch: committees.epoch,
        committees_id: committees.committees.id,
        committees: committees_per_epoch,
    };

    Ok((
        checkpoint,
        types::Hashi {
            id,
            committees,
            config: convert_move_config(config),
            treasury,
            deposit_queue,
            utxo_pool,
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

async fn scrape_member_info(
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

async fn scrape_committees(
    client: Client,
    committees_id: Address,
) -> Result<BTreeMap<u64, BlsCommittee>> {
    let committees: BTreeMap<u64, BlsCommittee> = client
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
            let committee = BlsCommittee::new(members, move_committee.epoch);
            (move_committee.epoch, committee)
        })
        .try_collect()
        .await?;

    Ok(committees)
}

fn convert_move_committee_member(
    move_types::CommitteeMember {
        validator_address,
        public_key,
        encryption_key: _,
        weight,
    }: move_types::CommitteeMember,
) -> BlsCommitteeMember {
    BlsCommitteeMember::new(
        validator_address,
        convert_move_uncompressed_g1_pubkey(&public_key),
        weight.into(),
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
    let requests: BTreeMap<types::UtxoId, types::DepositRequest> = client
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
        .map_ok(|move_types::DepositRequest { utxo, timestamp_ms }| {
            let utxo = convert_move_utxo(utxo);
            (utxo.id, types::DepositRequest { utxo, timestamp_ms })
        })
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
