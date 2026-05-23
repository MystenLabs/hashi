// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! ECS-based mirror of [`crate::onchain`].
//!
//! Same observable behavior — bootstrap from gRPC, follow checkpoint
//! updates, serve typed query methods to consumers — built on the
//! `sui-ecs` framework instead of an ad-hoc event-driven state machine.
//!
//! The two modules live side-by-side intentionally: this one is the
//! comparison candidate. The differences worth noting:
//!
//! - **Updates**: the legacy module parses `HashiEvent`s out of each
//!   transaction and dispatches per-event mutations. This one ingests
//!   raw `changed_objects` straight into `Object` components — the
//!   registered Derived components handle every kind of "view" on top.
//!   No event vocabulary; if the chain object changes, the world
//!   reflects it on the next batch.
//!
//! - **Derived values**: each parsed Move struct is a Derived component
//!   (see [`components`]). When an `Object` component is replaced, the
//!   scheduler re-runs its derivations automatically — no manual
//!   refetch-on-event paths.
//!
//! - **Bootstrap**: walks bag dynamic fields and dumps objects into the
//!   world; the framework's Derived registrations decide what to parse.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;

use anyhow::Result;
use sui_ecs::World;
use sui_ecs::base;
use sui_rpc::Client;
use sui_sdk_types::Address;
use tokio::sync::broadcast;
use tokio::sync::watch;

use crate::config::HashiIds;

pub mod bootstrap;
pub mod components;
pub mod watcher;

pub use components::{
    BitcoinStateField, CommitteeByEpoch, CommitteeEntry, DepositRequestEntry, HashiRoot,
    MemberInfoEntry, MetadataCapEntry, ProposalEntry, ProposalType, RichCommittee,
    RichConfig, RichMemberInfo, TlsKeyToAddress, TreasuryCapEntry, UtxoRecordEntry,
    WithdrawalRequestEntry, WithdrawalTransactionEntry,
};

const BROADCAST_CHANNEL_CAPACITY: usize = 100;

/// Mirror of [`crate::onchain::Notification`]. Same variants so the
/// notification surface stays consumer-compatible.
#[derive(Clone, Debug)]
pub enum Notification {
    ValidatorInfoUpdated(Address),
    StartReconfig(u64),
    SuiEpochChanged(u64),
}

/// Mirror of [`crate::onchain::CheckpointInfo`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckpointInfo {
    pub height: u64,
    pub timestamp_ms: u64,
    pub epoch: u64,
}

/// Cloneable handle to the ECS-backed on-chain state. Same shape and
/// concurrency model as [`crate::onchain::OnchainState`] — internal
/// `Arc<Inner>`, all queries take a snapshot read lock.
#[derive(Clone)]
pub struct OnchainState(Arc<Inner>);

impl std::fmt::Debug for OnchainState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnchainState").finish_non_exhaustive()
    }
}

struct Inner {
    ids: HashiIds,
    #[allow(unused)]
    client: Client,
    world: Arc<RwLock<World>>,
    notifications: broadcast::Sender<Notification>,
    checkpoint: watch::Sender<CheckpointInfo>,
    /// Settings used when constructing per-validator gRPC clients.
    /// Held separately from the World because the values come from
    /// the host process, not the chain.
    client_config: RwLock<ClientConfig>,
    /// Per-validator gRPC client pool, rebuilt after each checkpoint.
    /// Mirrors the legacy `CommitteeSet.clients` field; held alongside
    /// the world rather than inside it because the construction
    /// depends on host-side config the framework doesn't see.
    clients: RwLock<BTreeMap<Address, crate::grpc::Client>>,
}

#[derive(Default)]
struct ClientConfig {
    tls_private_key: Option<ed25519_dalek::SigningKey>,
    grpc_max_decoding_message_size: Option<usize>,
    metrics: Option<Arc<crate::metrics::Metrics>>,
}

impl OnchainState {
    /// Build a fresh state and a background watcher service. Same
    /// signature as [`crate::onchain::OnchainState::new`] so callers
    /// can swap implementations transparently.
    ///
    /// Bootstraps the world by scraping live objects, populates the
    /// per-validator gRPC client pool from the parsed `MemberInfo`s,
    /// then spawns an abortable background task that follows the
    /// checkpoint stream and applies object effects.
    pub async fn new(
        sui_rpc_url: &str,
        ids: HashiIds,
        tls_private_key: Option<ed25519_dalek::SigningKey>,
        grpc_max_decoding_message_size: Option<usize>,
        metrics: Option<Arc<crate::metrics::Metrics>>,
    ) -> Result<(Self, sui_futures::service::Service)> {
        let client = Client::new(sui_rpc_url)?;
        let mut world = World::new();
        base::install(&mut world);
        components::install(&mut world);

        let world = Arc::new(RwLock::new(world));
        let checkpoint = bootstrap::scrape(
            client.clone(),
            ids.hashi_object_id,
            ids.package_id,
            &world,
        )
        .await?;

        let (notifications, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (checkpoint_tx, _) = watch::channel(checkpoint);

        let state = Self(Arc::new(Inner {
            ids,
            client: client.clone(),
            world: world.clone(),
            notifications: notifications.clone(),
            checkpoint: checkpoint_tx.clone(),
            client_config: RwLock::new(ClientConfig {
                tls_private_key,
                grpc_max_decoding_message_size,
                metrics,
            }),
            clients: RwLock::new(BTreeMap::new()),
        }));
        // Populate the gRPC client pool now that bootstrap has filled
        // RichMemberInfo for every validator. After this, the watcher
        // re-runs `rebuild_clients` every time it applies a
        // checkpoint, so any MemberInfo rotation will refresh the pool
        // on the next chain heartbeat.
        state.rebuild_clients();

        let watcher_state = state.clone();
        let service = sui_futures::service::Service::new().spawn_aborting(async move {
            let _ = watcher_state.run_watcher().await;
            Ok(())
        });

        Ok((state, service))
    }

    /// Drive the checkpoint subscription loop. Stays in [`crate::onchain_ecs`]
    /// to mirror the legacy entry-point shape; normally called via the
    /// `Service` returned from [`Self::new`].
    pub async fn run_watcher(&self) -> Result<()> {
        watcher::run(
            self.0.client.clone(),
            self.0.world.clone(),
            self.0.checkpoint.clone(),
            self.0.notifications.clone(),
            self.clone(),
        )
        .await
    }

    // ---- gRPC client pool & TLS lookup -------------------------------------

    /// Reverse-lookup a validator address by its TLS public key. Backed
    /// by the framework's [`TlsKeyToAddress`] index, which the
    /// scheduler keeps in sync with `MemberInfoEntry` writes.
    pub fn lookup_address_by_tls_public_key(
        &self,
        tls_public_key: &ed25519_dalek::VerifyingKey,
    ) -> Option<Address> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .index::<TlsKeyToAddress>()?
            .get(tls_public_key.as_bytes())
            .copied()
    }

    /// Per-validator gRPC client. Pool is rebuilt eagerly after every
    /// checkpoint commit, so changes to validator endpoints/TLS keys
    /// land in the pool on the next chain heartbeat after their
    /// `MemberInfo` is written.
    pub fn client(&self, validator: &Address) -> Option<crate::grpc::Client> {
        self.0
            .clients
            .read()
            .expect("clients lock poisoned")
            .get(validator)
            .cloned()
    }

    /// Replace the TLS signing key used for outbound client auth.
    /// Rebuilds the entire pool so existing client handles point at
    /// the new key.
    pub fn set_tls_private_key(&self, key: ed25519_dalek::SigningKey) {
        self.0
            .client_config
            .write()
            .expect("client config lock poisoned")
            .tls_private_key = Some(key);
        self.rebuild_clients();
    }

    pub fn set_grpc_max_decoding_message_size(&self, limit: usize) {
        self.0
            .client_config
            .write()
            .expect("client config lock poisoned")
            .grpc_max_decoding_message_size = Some(limit);
        self.rebuild_clients();
    }

    pub fn set_metrics(&self, metrics: Arc<crate::metrics::Metrics>) {
        self.0
            .client_config
            .write()
            .expect("client config lock poisoned")
            .metrics = Some(metrics);
        self.rebuild_clients();
    }

    /// Surgically refresh the gRPC client pool for the entities whose
    /// `RichMemberInfo` was touched in the latest checkpoint commit.
    ///
    /// For each touched entity: if its `RichMemberInfo` still resolves
    /// (the member exists post-batch), build a fresh client and swap
    /// it in. If it no longer resolves, the entry was removed — and we
    /// won't know its validator address from the entity id alone, so
    /// the orphan sweep at the bottom handles those by dropping any
    /// pool entry that isn't backed by *some* `RichMemberInfo`.
    ///
    /// Validators whose info didn't change keep their existing
    /// `Arc<Client>` handles bit-identical across the call —
    /// consumers holding cloned references see no churn.
    pub(crate) fn refresh_clients_for<I>(&self, touched: I)
    where
        I: IntoIterator<Item = Address>,
    {
        let world = self.0.world.read().expect("world lock poisoned");
        let config = self
            .0
            .client_config
            .read()
            .expect("client config lock poisoned");
        let mut clients = self.0.clients.write().expect("clients lock poisoned");

        for entity in touched {
            if let Some(info) = world.get::<RichMemberInfo>(entity) {
                let validator = *info.0.validator_address();
                if let Some(new_client) = build_client(&info.0, &config) {
                    clients.insert(validator, new_client);
                } else {
                    // Member is present but lacks the endpoint/TLS
                    // material we need to build a client. Drop any
                    // stale entry — it's no longer reachable.
                    clients.remove(&validator);
                }
            }
            // If RichMemberInfo isn't present, the entry was removed
            // (or never produced a rich value). The orphan sweep
            // below picks it up.
        }

        // Orphan sweep: drop any pool entry whose validator address no
        // longer appears in any `RichMemberInfo`. Bounded by the size
        // of the pool, which is at most the validator-set size.
        let live: std::collections::BTreeSet<Address> = world
            .iter::<RichMemberInfo>()
            .map(|(_, m)| *m.0.validator_address())
            .collect();
        clients.retain(|addr, _| live.contains(addr));
    }

    /// Walk every `RichMemberInfo` and rebuild the pool from scratch.
    /// Called from [`Self::new`] after bootstrap; the watcher calls
    /// [`Self::refresh_clients_for`] instead so checkpoints don't pay
    /// for a full rebuild.
    pub(crate) fn rebuild_clients(&self) {
        let world = self.0.world.read().expect("world lock poisoned");
        let config = self
            .0
            .client_config
            .read()
            .expect("client config lock poisoned");

        let new_pool: BTreeMap<Address, crate::grpc::Client> = world
            .iter::<RichMemberInfo>()
            .filter_map(|(_, info)| {
                build_client(&info.0, &config).map(|c| (*info.0.validator_address(), c))
            })
            .collect();

        *self.0.clients.write().expect("clients lock poisoned") = new_pool;
    }

    // ---- channel handles (mirror the existing surface) ---------------------

    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.0.notifications.subscribe()
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

    /// Wait until the watcher has processed checkpoint `>= target`.
    pub async fn wait_until_checkpoint(&self, target: u64) -> Result<()> {
        let mut rx = self.0.checkpoint.subscribe();
        while rx.borrow().height < target {
            rx.changed().await?;
        }
        Ok(())
    }

    // ---- queries (mirror the existing surface) -----------------------------

    /// Returns the parsed `Hashi` root, if the bootstrap has run and
    /// the root object's BCS deserialized successfully. Closure form
    /// keeps the lock scope tight.
    pub fn with_hashi<R>(
        &self,
        f: impl FnOnce(Option<&hashi_types::move_types::Hashi>) -> R,
    ) -> R {
        let world = self.0.world.read().expect("world lock poisoned");
        f(world.get::<HashiRoot>(self.0.ids.hashi_object_id).map(|h| &h.0))
    }

    /// All currently-tracked validator `MemberInfo`s, in the same
    /// validated shape (`types::MemberInfo` with parsed BLS pubkey,
    /// `http::Uri`, etc.) that the legacy container produces.
    pub fn committee_members(&self) -> Vec<crate::onchain::types::MemberInfo> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<RichMemberInfo>()
            .map(|(_, m)| m.0.clone())
            .collect()
    }

    /// Look up a single validator by address. Returns `None` if the
    /// validator's BLS key isn't representable; use
    /// [`Self::committee_member_raw`] if you need the wire shape.
    pub fn committee_member(
        &self,
        validator: &Address,
    ) -> Option<crate::onchain::types::MemberInfo> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<RichMemberInfo>()
            .find(|(_, m)| m.0.validator_address() == validator)
            .map(|(_, m)| m.0.clone())
    }

    /// Raw `move_types::MemberInfo` for every validator — same shape
    /// as the on-chain Move struct, no BLS / URI parsing. Useful when
    /// you want every entry regardless of whether its keys validate.
    pub fn committee_members_raw(&self) -> Vec<hashi_types::move_types::MemberInfo> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<MemberInfoEntry>()
            .map(|(_, m)| clone_raw_member(&m.0))
            .collect()
    }

    /// Active proposals (those that still sit in the active bag).
    /// Equivalent to [`crate::onchain::OnchainState::proposals`].
    pub fn proposals(&self) -> Vec<ProposalEntry> {
        let world = self.0.world.read().expect("world lock poisoned");
        let Some(hashi) = world.get::<HashiRoot>(self.0.ids.hashi_object_id) else {
            return Vec::new();
        };
        let active_bag = hashi.0.proposals.active.id;
        proposals_under_bag(&world, active_bag)
    }

    /// Executed proposals (those that have been moved into the
    /// executed bag).
    pub fn executed_proposals(&self) -> Vec<ProposalEntry> {
        let world = self.0.world.read().expect("world lock poisoned");
        let Some(hashi) = world.get::<HashiRoot>(self.0.ids.hashi_object_id) else {
            return Vec::new();
        };
        let executed_bag = hashi.0.proposals.executed.id;
        proposals_under_bag(&world, executed_bag)
    }

    /// Lookup a single proposal by id, regardless of whether it's
    /// active or executed.
    pub fn proposal(&self, id: &Address) -> Option<ProposalEntry> {
        let world = self.0.world.read().expect("world lock poisoned");
        world.get::<ProposalEntry>(*id).cloned()
    }

    /// All currently-pending deposit requests.
    pub fn deposit_requests(&self) -> Vec<hashi_types::move_types::DepositRequest> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<DepositRequestEntry>()
            .map(|(_, d)| d.0.clone())
            .collect()
    }

    /// All cached per-epoch committees, in the rich
    /// `hashi_types::committee::Committee` shape the legacy container
    /// produces.
    pub fn committees(&self) -> Vec<hashi_types::committee::Committee> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<RichCommittee>()
            .map(|(_, c)| c.0.clone())
            .collect()
    }

    /// Committee for the current epoch, resolved via the
    /// `CommitteeByEpoch` index plus the epoch off the parsed
    /// `HashiRoot`. Returns `None` if the world hasn't been
    /// bootstrapped or the committee isn't tracked.
    pub fn current_committee(&self) -> Option<hashi_types::committee::Committee> {
        let world = self.0.world.read().expect("world lock poisoned");
        let epoch = world.get::<HashiRoot>(self.0.ids.hashi_object_id)?.0.committees.epoch;
        let entity = *world.index::<CommitteeByEpoch>()?.get(&epoch)?;
        world.get::<RichCommittee>(entity).map(|c| c.0.clone())
    }

    /// Convenience: the current committee's member list. Mirrors the
    /// legacy method of the same name.
    pub fn current_committee_members(
        &self,
    ) -> Option<Vec<hashi_types::committee::CommitteeMember>> {
        self.current_committee().map(|c| c.members().to_vec())
    }

    // ---- pending bitcoin state ---------------------------------------------

    /// All currently pending withdrawal requests.
    pub fn withdrawal_requests(&self) -> Vec<hashi_types::move_types::WithdrawalRequest> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<WithdrawalRequestEntry>()
            .map(|(_, w)| w.0.clone())
            .collect()
    }

    /// Lookup a single pending withdrawal request by id.
    pub fn withdrawal_request(
        &self,
        id: &Address,
    ) -> Option<hashi_types::move_types::WithdrawalRequest> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<WithdrawalRequestEntry>()
            .find(|(_, w)| w.0.id == *id)
            .map(|(_, w)| w.0.clone())
    }

    /// In-flight withdrawal transactions awaiting confirmation.
    pub fn withdrawal_txns(&self) -> Vec<hashi_types::move_types::WithdrawalTransaction> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<WithdrawalTransactionEntry>()
            .map(|(_, t)| clone_withdrawal_txn(&t.0))
            .collect()
    }

    /// Lookup a single in-flight withdrawal transaction by id.
    pub fn withdrawal_txn(
        &self,
        id: &Address,
    ) -> Option<hashi_types::move_types::WithdrawalTransaction> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<WithdrawalTransactionEntry>()
            .find(|(_, t)| t.0.id == *id)
            .map(|(_, t)| clone_withdrawal_txn(&t.0))
    }

    /// Active UTXOs — every recorded UTXO whose `locked_by` is `None`.
    /// Matches the filter `UtxoPool::active_utxos` applies on the
    /// legacy side.
    pub fn active_utxos(&self) -> Vec<hashi_types::move_types::Utxo> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<UtxoRecordEntry>()
            .filter(|(_, r)| r.0.locked_by.is_none())
            .map(|(_, r)| r.0.utxo.clone())
            .collect()
    }

    // ---- treasury ----------------------------------------------------------

    /// Sui-framework `TreasuryCap`s held inside the hashi treasury,
    /// keyed by coin type.
    pub fn treasury_caps(
        &self,
    ) -> std::collections::BTreeMap<
        sui_sdk_types::TypeTag,
        crate::onchain::types::TreasuryCap,
    > {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<TreasuryCapEntry>()
            .map(|(_, c)| (c.0.coin_type.clone(), clone_treasury_cap(&c.0)))
            .collect()
    }

    /// Sui-framework metadata caps held inside the hashi treasury,
    /// keyed by coin type.
    pub fn metadata_caps(
        &self,
    ) -> std::collections::BTreeMap<sui_sdk_types::TypeTag, crate::onchain::types::MetadataCap>
    {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .iter::<MetadataCapEntry>()
            .map(|(_, c)| (c.0.coin_type.clone(), clone_metadata_cap(&c.0)))
            .collect()
    }

    // ---- top-level scalars + config ----------------------------------------

    /// Address of the top-level Hashi object. Static for the lifetime
    /// of this state container.
    pub fn hashi_id(&self) -> Address {
        self.0.ids.hashi_object_id
    }

    /// Address of the package this container is reading from. We
    /// don't yet track upgrade history in the world, so this returns
    /// the package_id passed at construction.
    pub fn package_id(&self) -> Option<Address> {
        Some(self.0.ids.package_id)
    }

    /// The current Sui-side epoch as the chain object reports it.
    pub fn epoch(&self) -> u64 {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .get::<HashiRoot>(self.0.ids.hashi_object_id)
            .map(|h| h.0.committees.epoch)
            .unwrap_or(0)
    }

    /// MPC threshold public key bytes for the current epoch.
    pub fn mpc_public_key(&self) -> Vec<u8> {
        let world = self.0.world.read().expect("world lock poisoned");
        world
            .get::<HashiRoot>(self.0.ids.hashi_object_id)
            .map(|h| h.0.committees.mpc_public_key.clone())
            .unwrap_or_default()
    }

    /// Run a closure against the rich [`crate::onchain::types::Config`]
    /// view. The closure form keeps the read lock scope tight; for
    /// one-shot readers prefer the convenience accessors below.
    pub fn with_config<R>(
        &self,
        f: impl FnOnce(Option<&crate::onchain::types::Config>) -> R,
    ) -> R {
        let world = self.0.world.read().expect("world lock poisoned");
        f(world.get::<RichConfig>(self.0.ids.hashi_object_id).map(|c| &c.0))
    }

    pub fn bitcoin_deposit_minimum(&self) -> u64 {
        self.with_config(|c| c.map(|c| c.bitcoin_deposit_minimum()).unwrap_or(0))
    }

    pub fn bitcoin_withdrawal_minimum(&self) -> u64 {
        self.with_config(|c| c.map(|c| c.bitcoin_withdrawal_minimum()).unwrap_or(0))
    }

    pub fn paused(&self) -> bool {
        self.with_config(|c| c.map(|c| c.paused()).unwrap_or(false))
    }
}

// ---- internal helpers --------------------------------------------------

/// Collect every `ProposalEntry` whose underlying field/object is owned
/// (directly) by `bag_id`. Used to scope proposals to "active" vs
/// "executed" — both ride on `OwnedByObject`, which is keyed by the
/// raw `Owner::Object(uid)` so the lookup is a single hash hit.
fn proposals_under_bag(world: &World, bag_id: Address) -> Vec<ProposalEntry> {
    let Some(owned) = world.index::<base::OwnedByObject>() else {
        return Vec::new();
    };
    owned
        .get(&bag_id)
        .filter_map(|child| world.get::<ProposalEntry>(*child).cloned())
        .collect()
}

/// `move_types::MemberInfo` doesn't derive `Clone`, so we copy
/// field-by-field. Kept internal because it duplicates a small amount
/// of boilerplate; if the upstream type ever gets a `Clone` derive,
/// this can go away.
fn clone_raw_member(
    m: &hashi_types::move_types::MemberInfo,
) -> hashi_types::move_types::MemberInfo {
    hashi_types::move_types::MemberInfo {
        validator_address: m.validator_address,
        operator_address: m.operator_address,
        next_epoch_public_key: m.next_epoch_public_key.clone(),
        endpoint_url: m.endpoint_url.clone(),
        tls_public_key: m.tls_public_key.clone(),
        next_epoch_encryption_public_key: m.next_epoch_encryption_public_key.clone(),
    }
}

/// `move_types::WithdrawalTransaction` doesn't derive `Clone`; round
/// trip through BCS so the query API can hand out owned copies. Same
/// trick we use for `Committee`.
fn clone_withdrawal_txn(
    t: &hashi_types::move_types::WithdrawalTransaction,
) -> hashi_types::move_types::WithdrawalTransaction {
    let bytes = bcs::to_bytes(t).expect("WithdrawalTransaction serializes");
    bcs::from_bytes(&bytes).expect("WithdrawalTransaction round-trips")
}

/// `TreasuryCap` and `MetadataCap` aren't `Clone` either; copy field
/// by field. Both are tiny (one TypeTag + Address + maybe a u64) so
/// this is cheap.
fn clone_treasury_cap(c: &crate::onchain::types::TreasuryCap) -> crate::onchain::types::TreasuryCap {
    crate::onchain::types::TreasuryCap {
        coin_type: c.coin_type.clone(),
        id: c.id,
        supply: c.supply,
    }
}

fn clone_metadata_cap(c: &crate::onchain::types::MetadataCap) -> crate::onchain::types::MetadataCap {
    crate::onchain::types::MetadataCap {
        coin_type: c.coin_type.clone(),
        id: c.id,
    }
}

/// Build a single validator's gRPC client from a parsed `MemberInfo`
/// and the per-process client config. Returns `None` if the member
/// lacks an endpoint or TLS key, or if `grpc::Client::new` rejects the
/// URI/TLS pair. Shared between full rebuilds (`rebuild_clients`) and
/// the surgical, per-touched-entity path
/// (`refresh_clients_for`).
fn build_client(
    info: &crate::onchain::types::MemberInfo,
    config: &ClientConfig,
) -> Option<crate::grpc::Client> {
    let endpoint = info.endpoint_url()?;
    let tls_public_key = info.tls_public_key()?;
    let tls_config = match &config.tls_private_key {
        Some(priv_key) => {
            crate::tls::make_client_config_with_client_auth(priv_key, tls_public_key)
        }
        None => crate::tls::make_client_config(tls_public_key),
    };
    let mut client = crate::grpc::Client::new(endpoint, tls_config).ok()?;
    if let Some(limit) = config.grpc_max_decoding_message_size {
        client = client.max_decoding_message_size(limit);
    }
    if let Some(metrics) = &config.metrics {
        client = client.with_metrics(metrics.clone());
    }
    Some(client)
}

#[cfg(test)]
mod tests {
    //! End-to-end smoke tests for the parallel state container.
    //!
    //! These don't talk to gRPC — they construct synthetic Sui
    //! `Object`s with the right `StructTag` and BCS contents, push them
    //! into the world directly, and verify that the registered Derived
    //! components materialize the expected parsed values + that the
    //! consumer-facing query API surfaces them.

    use super::*;
    use hashi_types::move_types;
    use sui_sdk_types::{
        Digest, Identifier, MoveStruct, Object as SuiObject, ObjectData, Owner, StructTag,
    };

    // Synthesize Addresses cheaply. Each byte yields a deterministic id.
    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; Address::LENGTH]).unwrap()
    }

    /// Build a `Field<K, V>` move-object whose BCS contents serialize
    /// `field`, tagged with the given `value_struct_tag` as the V type
    /// param. `id` becomes the object's own id (which BCS-encodes as
    /// the first 32 bytes of the contents — Field's `id` field).
    fn make_field_object<K, V>(
        id: Address,
        name: K,
        value: V,
        value_struct_tag: StructTag,
        parent_uid: Address,
    ) -> SuiObject
    where
        K: serde::Serialize,
        V: serde::Serialize,
    {
        let field = move_types::Field { id, name, value };
        let contents = bcs::to_bytes(&field).expect("Field serializes");
        let field_tag = StructTag::new(
            addr(0x02),
            Identifier::new("dynamic_field").unwrap(),
            Identifier::new("Field").unwrap(),
            vec![
                sui_sdk_types::TypeTag::Address, // K is Address in our test cases
                sui_sdk_types::TypeTag::Struct(Box::new(value_struct_tag)),
            ],
        );
        let ms = MoveStruct::new(field_tag, true, 1, contents).expect("contents have id prefix");
        SuiObject::new(
            ObjectData::Struct(ms),
            Owner::Object(parent_uid),
            Digest::ZERO,
            0,
        )
    }

    fn hashi_struct_tag(pkg: Address) -> StructTag {
        StructTag::new(
            pkg,
            Identifier::new("hashi").unwrap(),
            Identifier::new("Hashi").unwrap(),
            vec![],
        )
    }

    fn member_info_struct_tag(pkg: Address) -> StructTag {
        StructTag::new(
            pkg,
            Identifier::new("committee_set").unwrap(),
            Identifier::new("MemberInfo").unwrap(),
            vec![],
        )
    }

    /// Bag ids referenced by a synthetic Hashi object. Grouped into
    /// one struct so the test fixtures don't tip over the
    /// `clippy::too_many_arguments` heuristic.
    struct HashiBags {
        members: Address,
        committees: Address,
        proposals_active: Address,
        proposals_executed: Address,
        treasury: Address,
        tob: Address,
    }

    /// Build a synthetic Hashi top-level object with the given bag
    /// ids. The Move struct shape mirrors `move_types::Hashi`.
    fn make_hashi_object(
        hashi_id: Address,
        bags: HashiBags,
        pkg: Address,
    ) -> SuiObject {
        let HashiBags {
            members: members_bag,
            committees: committees_bag,
            proposals_active,
            proposals_executed,
            treasury: treasury_bag,
            tob: tob_bag,
        } = bags;
        let hashi = move_types::Hashi {
            id: hashi_id,
            committees: move_types::CommitteeSet {
                members: move_types::Bag {
                    id: members_bag,
                    size: 0,
                },
                committees: move_types::Bag {
                    id: committees_bag,
                    size: 0,
                },
                epoch: 7,
                pending_epoch_change: None,
                mpc_public_key: vec![1, 2, 3, 4],
            },
            config: move_types::Config {
                config: vec![],
                enabled_versions: move_types::VecSet { contents: vec![1] },
                upgrade_cap: None,
            },
            treasury: move_types::Treasury {
                objects: move_types::Bag {
                    id: treasury_bag,
                    size: 0,
                },
            },
            proposals: move_types::Proposals {
                active: move_types::Bag {
                    id: proposals_active,
                    size: 0,
                },
                executed: move_types::Bag {
                    id: proposals_executed,
                    size: 0,
                },
            },
            tob: move_types::Bag {
                id: tob_bag,
                size: 0,
            },
            num_consumed_presigs: 0,
        };
        let contents = bcs::to_bytes(&hashi).expect("Hashi serializes");
        let ms = MoveStruct::new(hashi_struct_tag(pkg), true, 1, contents)
            .expect("contents include valid object id");
        SuiObject::new(
            ObjectData::Struct(ms),
            Owner::Address(addr(0xAA)),
            Digest::ZERO,
            0,
        )
    }

    fn make_member_info(validator: Address) -> move_types::MemberInfo {
        move_types::MemberInfo {
            validator_address: validator,
            operator_address: validator,
            next_epoch_public_key: vec![],
            endpoint_url: format!("https://node-{}.example", validator),
            tls_public_key: vec![],
            next_epoch_encryption_public_key: vec![],
        }
    }

    /// Build a state container without going through gRPC bootstrap.
    /// Manually push the same objects bootstrap would have pushed.
    fn synthetic_state(
        hashi_id: Address,
        ids: HashiIds,
        objects: Vec<(Address, SuiObject)>,
    ) -> OnchainState {
        let mut world = World::new();
        base::install(&mut world);
        components::install(&mut world);
        {
            let mut batch = world.batch();
            for (id, obj) in objects {
                batch.insert::<SuiObject>(id, obj);
            }
            batch.commit();
        }
        let _ = hashi_id;

        let world = Arc::new(RwLock::new(world));
        let (notifications, _) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);
        let (checkpoint, _) = watch::channel(CheckpointInfo::default());

        OnchainState(Arc::new(Inner {
            ids,
            client: Client::new("http://localhost:1").unwrap(),
            world,
            notifications,
            checkpoint,
            client_config: RwLock::new(ClientConfig::default()),
            clients: RwLock::new(BTreeMap::new()),
        }))
    }

    #[tokio::test]
    async fn hashi_root_derives_after_insert() {
        let pkg = addr(0x10);
        let hashi_id = addr(0x11);
        let members_bag = addr(0x12);
        let proposals_active = addr(0x13);

        let hashi_obj = make_hashi_object(
            hashi_id,
            HashiBags {
                members: members_bag,
                committees: addr(0x14),
                proposals_active,
                proposals_executed: addr(0x15),
                treasury: addr(0x16),
                tob: addr(0x17),
            },
            pkg,
        );

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(hashi_id, ids, vec![(hashi_id, hashi_obj)]);

        // HashiRoot Derived ran during the batch commit. The query
        // closure should see the parsed value.
        let saw = state.with_hashi(|h| {
            let h = h?;
            Some((
                h.id,
                h.committees.members.id,
                h.proposals.active.id,
                h.committees.epoch,
            ))
        });

        assert_eq!(
            saw,
            Some((hashi_id, members_bag, proposals_active, 7)),
            "HashiRoot Derived should yield the parsed Hashi"
        );
    }

    #[tokio::test]
    async fn members_query_returns_dynamic_field_entries() {
        let pkg = addr(0x20);
        let hashi_id = addr(0x21);
        let members_bag = addr(0x22);

        let hashi_obj = make_hashi_object(
            hashi_id,
            HashiBags {
                members: members_bag,
                committees: addr(0x23),
                proposals_active: addr(0x24),
                proposals_executed: addr(0x25),
                treasury: addr(0x26),
                tob: addr(0x27),
            },
            pkg,
        );

        let validator_a = addr(0xA0);
        let validator_b = addr(0xB0);
        let field_a_id = addr(0xC0);
        let field_b_id = addr(0xC1);

        let member_a = make_member_info(validator_a);
        let member_b = make_member_info(validator_b);

        let field_a = make_field_object(
            field_a_id,
            validator_a,
            member_a,
            member_info_struct_tag(pkg),
            members_bag,
        );
        let field_b = make_field_object(
            field_b_id,
            validator_b,
            member_b,
            member_info_struct_tag(pkg),
            members_bag,
        );

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (hashi_id, hashi_obj),
                (field_a_id, field_a),
                (field_b_id, field_b),
            ],
        );

        let mut endpoints: Vec<_> = state
            .committee_members_raw()
            .into_iter()
            .map(|m| m.endpoint_url)
            .collect();
        endpoints.sort();
        assert_eq!(
            endpoints,
            vec![
                format!("https://node-{validator_a}.example"),
                format!("https://node-{validator_b}.example"),
            ]
        );
    }

    /// When the underlying Object for a member info field is replaced
    /// with a new value, the derived MemberInfoEntry should reflect
    /// the new contents without any manual refresh.
    #[tokio::test]
    async fn member_info_reflects_object_mutations() {
        let pkg = addr(0x30);
        let hashi_id = addr(0x31);
        let members_bag = addr(0x32);
        let validator = addr(0xA0);
        let field_id = addr(0xC0);

        let v1 = {
            let mut m = make_member_info(validator);
            m.endpoint_url = "https://node-v1.example".into();
            make_field_object(
                field_id,
                validator,
                m,
                member_info_struct_tag(pkg),
                members_bag,
            )
        };
        let v2 = {
            let mut m = make_member_info(validator);
            m.endpoint_url = "https://node-v2.example".into();
            make_field_object(
                field_id,
                validator,
                m,
                member_info_struct_tag(pkg),
                members_bag,
            )
        };

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (
                    hashi_id,
                    make_hashi_object(
                        hashi_id,
                        HashiBags {
                            members: members_bag,
                            committees: addr(0x33),
                            proposals_active: addr(0x34),
                            proposals_executed: addr(0x35),
                            treasury: addr(0x36),
                            tob: addr(0x37),
                        },
                        pkg,
                    ),
                ),
                (field_id, v1),
            ],
        );

        let initial: Vec<_> = state
            .committee_members_raw()
            .into_iter()
            .map(|m| m.endpoint_url)
            .collect();
        assert_eq!(initial, vec!["https://node-v1.example"]);

        // Now overwrite the Object — this is the same code path the
        // watcher's ChangeSet would hit.
        {
            let mut w = state.0.world.write().expect("world lock poisoned");
            w.insert::<SuiObject>(field_id, v2);
        }

        let after: Vec<_> = state
            .committee_members_raw()
            .into_iter()
            .map(|m| m.endpoint_url)
            .collect();
        assert_eq!(
            after,
            vec!["https://node-v2.example"],
            "MemberInfoEntry should re-derive after Object mutation"
        );
    }

    /// Make sure undeleted member info goes away when the field
    /// object is removed (mirroring a tx that deletes the dynamic
    /// field).
    #[tokio::test]
    async fn member_info_drops_when_object_removed() {
        let pkg = addr(0x40);
        let hashi_id = addr(0x41);
        let members_bag = addr(0x42);
        let validator = addr(0xA0);
        let field_id = addr(0xC0);

        let field_obj = make_field_object(
            field_id,
            validator,
            make_member_info(validator),
            member_info_struct_tag(pkg),
            members_bag,
        );

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (
                    hashi_id,
                    make_hashi_object(
                        hashi_id,
                        HashiBags {
                            members: members_bag,
                            committees: addr(0x43),
                            proposals_active: addr(0x44),
                            proposals_executed: addr(0x45),
                            treasury: addr(0x46),
                            tob: addr(0x47),
                        },
                        pkg,
                    ),
                ),
                (field_id, field_obj),
            ],
        );
        assert_eq!(state.committee_members_raw().len(), 1);

        {
            let mut w = state.0.world.write().expect("world lock poisoned");
            w.remove::<SuiObject>(field_id);
        }
        assert!(state.committee_members_raw().is_empty());
        // And the MemberInfoEntry Component is removed too — the
        // scheduler dropped it via Derived::compute returning None.
        let w = state.0.world.read().expect("world lock poisoned");
        assert!(!w.contains::<MemberInfoEntry>(field_id));
    }

    /// Sanity check: a derivation that aggregates over children
    /// (e.g. an active-proposals count) shouldn't be needed here —
    /// queries fall back to the OwnedByObject index for filtering.
    /// This test confirms the index is populated as expected so that
    /// later, when proposals are inserted, queries scoped by
    /// active/executed will work.
    #[tokio::test]
    async fn ownership_index_groups_field_objects_under_parent_bag() {
        let pkg = addr(0x50);
        let hashi_id = addr(0x51);
        let members_bag = addr(0x52);
        let validator = addr(0xA0);
        let field_id = addr(0xC0);

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (
                    hashi_id,
                    make_hashi_object(
                        hashi_id,
                        HashiBags {
                            members: members_bag,
                            committees: addr(0x53),
                            proposals_active: addr(0x54),
                            proposals_executed: addr(0x55),
                            treasury: addr(0x56),
                            tob: addr(0x57),
                        },
                        pkg,
                    ),
                ),
                (
                    field_id,
                    make_field_object(
                        field_id,
                        validator,
                        make_member_info(validator),
                        member_info_struct_tag(pkg),
                        members_bag,
                    ),
                ),
            ],
        );

        let w = state.0.world.read().expect("world lock poisoned");
        let owned = w.index::<base::OwnedByObject>().expect("registered");
        let kids: Vec<_> = owned.get(&members_bag).copied().collect();
        assert_eq!(kids, vec![field_id]);
    }

    /// Exercise the TLS reverse index end-to-end: insert a member info
    /// whose `tls_public_key` is 32 bytes and verify
    /// `lookup_address_by_tls_public_key` returns the validator address
    /// — the same surface the legacy `CommitteeSet` exposes.
    #[tokio::test]
    async fn tls_index_resolves_validator_address() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let pkg = addr(0x60);
        let hashi_id = addr(0x61);
        let members_bag = addr(0x62);
        let validator = addr(0xA0);
        let field_id = addr(0xC0);

        // Generate a real ed25519 keypair so VerifyingKey decoding
        // succeeds. We only care about the public bytes — they're what
        // the index keys on and what the lookup matches against.
        let signing = SigningKey::generate(&mut OsRng);
        let verifying: VerifyingKey = signing.verifying_key();

        let mut member = make_member_info(validator);
        member.tls_public_key = verifying.as_bytes().to_vec();

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (
                    hashi_id,
                    make_hashi_object(
                        hashi_id,
                        HashiBags {
                            members: members_bag,
                            committees: addr(0x63),
                            proposals_active: addr(0x64),
                            proposals_executed: addr(0x65),
                            treasury: addr(0x66),
                            tob: addr(0x67),
                        },
                        pkg,
                    ),
                ),
                (
                    field_id,
                    make_field_object(
                        field_id,
                        validator,
                        member,
                        member_info_struct_tag(pkg),
                        members_bag,
                    ),
                ),
            ],
        );

        // Resolves via the framework-maintained TlsKeyToAddress index.
        assert_eq!(
            state.lookup_address_by_tls_public_key(&verifying),
            Some(validator),
        );

        // A different (random) key shouldn't resolve to anyone.
        let other = SigningKey::generate(&mut OsRng).verifying_key();
        assert_eq!(state.lookup_address_by_tls_public_key(&other), None);
    }

    /// When a validator's TLS public key is rotated, the index entry
    /// should follow — the old key no longer resolves, the new one
    /// does. Mirrors the legacy `update_validator` behavior but driven
    /// by the scheduler's automatic re-derivation.
    #[tokio::test]
    async fn tls_index_follows_key_rotation() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use rand::rngs::OsRng;

        let pkg = addr(0x70);
        let hashi_id = addr(0x71);
        let members_bag = addr(0x72);
        let validator = addr(0xA0);
        let field_id = addr(0xC0);

        let old_signing = SigningKey::generate(&mut OsRng);
        let old_key: VerifyingKey = old_signing.verifying_key();
        let new_signing = SigningKey::generate(&mut OsRng);
        let new_key: VerifyingKey = new_signing.verifying_key();

        let mut member_v1 = make_member_info(validator);
        member_v1.tls_public_key = old_key.as_bytes().to_vec();
        let mut member_v2 = make_member_info(validator);
        member_v2.tls_public_key = new_key.as_bytes().to_vec();

        let ids = HashiIds {
            package_id: pkg,
            hashi_object_id: hashi_id,
        };
        let state = synthetic_state(
            hashi_id,
            ids,
            vec![
                (
                    hashi_id,
                    make_hashi_object(
                        hashi_id,
                        HashiBags {
                            members: members_bag,
                            committees: addr(0x73),
                            proposals_active: addr(0x74),
                            proposals_executed: addr(0x75),
                            treasury: addr(0x76),
                            tob: addr(0x77),
                        },
                        pkg,
                    ),
                ),
                (
                    field_id,
                    make_field_object(
                        field_id,
                        validator,
                        member_v1,
                        member_info_struct_tag(pkg),
                        members_bag,
                    ),
                ),
            ],
        );

        assert_eq!(
            state.lookup_address_by_tls_public_key(&old_key),
            Some(validator),
        );

        // Re-write the MemberInfo Object with the new TLS key — same
        // code path the watcher takes when a `ValidatorUpdated`
        // transaction lands.
        {
            let mut w = state.0.world.write().expect("world lock poisoned");
            w.insert::<SuiObject>(
                field_id,
                make_field_object(
                    field_id,
                    validator,
                    member_v2,
                    member_info_struct_tag(pkg),
                    members_bag,
                ),
            );
        }

        assert_eq!(
            state.lookup_address_by_tls_public_key(&old_key),
            None,
            "old key should no longer resolve",
        );
        assert_eq!(
            state.lookup_address_by_tls_public_key(&new_key),
            Some(validator),
            "new key should resolve to the same validator",
        );
    }
}
