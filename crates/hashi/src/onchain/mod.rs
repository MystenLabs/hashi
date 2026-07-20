// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
use fastcrypto::serde_helpers::ToFromByteArray;
use futures::TryStreamExt;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::OnceLock;
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
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::ToBcs;
use tap::Pipe;
use tokio::sync::broadcast;
use tokio::sync::watch;

use crate::config::HashiIds;
use crate::mpc::fallback_encryption_public_key;
use fastcrypto_tbls::threshold_schnorr::G as HashiMasterG;
use hashi_types::committee::Committee;
use hashi_types::committee::CommitteeMember;
use hashi_types::committee::SignedMessage;
use hashi_types::guardian::CommitteeTransitionRequest;
use hashi_types::move_types;

const BROADCAST_CHANNEL_CAPACITY: usize = 100;

/// Bounded so a huge queue isn't returned as one oversized page that overflows
/// the gRPC decode limit; the SDK still pages through every entry.
const SCRAPE_PAGE_SIZE: u32 = 1000;

mod apply;
mod route;
mod shadow;
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
    metrics: Option<Arc<crate::metrics::Metrics>>,
    /// Set once after guardian bootstrap; advanced by the watcher.
    /// `LocalLimiter` carries its own `RwLock<LimiterState>`, so we just
    /// need set-once semantics for the slot itself.
    local_limiter: OnceLock<Arc<crate::guardian_limiter::LocalLimiter>>,
    /// Pinged by the watcher after a reconnect rescrape, so the reconcile
    /// loop can re-align the local limiter immediately.
    guardian_reconcile_notify: Arc<tokio::sync::Notify>,
    /// Checkpoint floor for cleanup-GC scrapes: raised to the checkpoint of
    /// each landed cleanup tx so the next scrape cannot be served state
    /// from before it (the watcher cursor alone may lag that checkpoint).
    utxo_scrape_floor: std::sync::atomic::AtomicU64,
    /// Cadence of the watcher's on-chain config poll.
    config_poll_interval: std::time::Duration,
}

#[derive(Debug)]
pub struct State {
    package_versions: BTreeMap<u64, Address>,
    package_ids: BTreeSet<Address>,
    hashi: types::Hashi,
    withdrawal_signed_at_ms: BTreeMap<Address, u64>,
}

#[derive(serde_derive::Serialize, serde_derive::Deserialize)]
struct TobKey {
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: move_types::ProtocolType,
}

impl OnchainState {
    pub async fn new(
        sui_rpc_url: &str,
        ids: HashiIds,
        tls_private_key: Option<ed25519_dalek::SigningKey>,
        grpc_max_decoding_message_size: Option<usize>,
        metrics: Option<Arc<crate::metrics::Metrics>>,
        config_poll_interval: Option<std::time::Duration>,
    ) -> Result<(Self, Service)> {
        let mut client = crate::sui_rpc_client::new_sui_rpc_client(sui_rpc_url)?;
        // The scrape client reads the full on-chain state (the largest
        // responses), so it needs the decode limit too — not just `committees`.
        if let Some(limit) = grpc_max_decoding_message_size {
            client = client.with_max_decoding_message_size(limit);
        }

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
        if let Some(metrics) = metrics.clone() {
            state.hashi.committees.set_metrics(metrics);
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
            metrics: metrics.clone(),
            local_limiter: OnceLock::new(),
            guardian_reconcile_notify: Arc::new(tokio::sync::Notify::new()),
            config_poll_interval: config_poll_interval.unwrap_or(std::time::Duration::from_millis(
                crate::config::DEFAULT_ONCHAIN_CONFIG_POLL_INTERVAL_MS,
            )),
            utxo_scrape_floor: std::sync::atomic::AtomicU64::new(0),
        }
        .pipe(Arc::new)
        .pipe(Self);

        let watcher_state = state.clone();
        // The watcher rebuilds its client on every reconnect, so hand it the URL.
        let sui_rpc_url = sui_rpc_url.to_owned();
        let service = Service::new().spawn_aborting(async move {
            watcher::watcher(sui_rpc_url, watcher_state, metrics).await;
            Ok(())
        });

        Ok((state, service))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Notification> {
        self.0.sender.subscribe()
    }

    pub(crate) fn grpc_max_decoding_message_size(&self) -> Option<usize> {
        self.0.grpc_max_decoding_message_size
    }

    pub(crate) fn config_poll_interval(&self) -> std::time::Duration {
        self.0.config_poll_interval
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

    /// Scrape the on-chain `utxo_records` table into a task-local snapshot
    /// for the cleanup GC's use. Deliberately does NOT touch the shared
    /// mirror: the watcher task is its sole writer, and installing an
    /// out-of-band snapshot could revert mutations the watcher already
    /// applied from newer checkpoints (e.g. a `spent_by` lock, whose loss
    /// would let coin selection re-pick a locked input and pay for an
    /// aborted tx).
    ///
    /// The GC scans this snapshot instead of the mirror because the mirror
    /// can overstate pending cleanups (`cleanup_spent_utxos` emits no event
    /// the watcher could apply, so another leader's cleanup is invisible),
    /// and every overstated id becomes a paid on-chain no-op. Only
    /// `utxo_records` is fetched — cleanup never consults the ever-growing
    /// `spent_utxos` tombstone history.
    ///
    /// Every response — the `BitcoinState` wrapper AND each pagination page
    /// — must be at or past the watcher's checkpoint cursor, re-sampled per
    /// page; a page served behind it (e.g. a load-balanced endpoint mixing
    /// in a lagging fullnode) errors out so the caller backs off and
    /// retries rather than paying to re-clean records a fresh page would
    /// have shown as already gone.
    /// Raise the cleanup-scrape freshness floor to `checkpoint` (monotonic).
    /// Called after a cleanup tx lands so the next scrape cannot be served
    /// pre-cleanup state and re-pay for records the tx already removed.
    pub(crate) fn raise_utxo_scrape_floor(&self, checkpoint: u64) {
        self.0
            .utxo_scrape_floor
            .fetch_max(checkpoint, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) async fn scrape_utxo_records_snapshot(
        &self,
    ) -> Result<BTreeMap<types::UtxoId, types::UtxoRecord>> {
        let client = self.client();
        let (scrape_height, _version, bitcoin_state) =
            fetch_bitcoin_state(client.clone(), self.hashi_id(), self.package_id_original())
                .await?;
        let floor = self
            .0
            .utxo_scrape_floor
            .load(std::sync::atomic::Ordering::Relaxed)
            .max(self.latest_checkpoint_height());
        if scrape_height < floor {
            anyhow::bail!(
                "stale UTXO pool read: scrape at checkpoint {scrape_height} is behind the \
                 freshness floor {floor}"
            );
        }

        let utxo_records_id = bitcoin_state.utxo_pool.utxo_records.id;
        let mut records = BTreeMap::new();
        let mut page_token: Option<bytes::Bytes> = None;
        // Monotonic floor over every height observed in this scrape,
        // seeded by the wrapper read (already >= the persistent floor):
        // heights must never move backward across responses, or a page
        // could miss a cleanup that an earlier response's serving node had
        // already seen.
        let mut min_height = scrape_height;
        loop {
            let mut request = ListDynamicFieldsRequest::default()
                .with_parent(utxo_records_id)
                .with_page_size(SCRAPE_PAGE_SIZE)
                .with_read_mask(FieldMask::from_paths([
                    // `name` is load-bearing even though we only read
                    // `value`: the fullnode's `should_load_field` does not
                    // recognize a value-only mask and would return fields
                    // with `value` unset (main's scrape_utxo_records
                    // requests both for the same reason).
                    DynamicField::path_builder().name().finish(),
                    DynamicField::path_builder().value().finish(),
                ]));
            if let Some(token) = page_token.take() {
                request = request.with_page_token(token);
            }
            let response = client
                .clone()
                .state_client()
                .list_dynamic_fields(request)
                .await?;
            let page_height = response
                .checkpoint_height()
                .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?;
            // Re-sample the cursor (it advances while we paginate) and
            // fold it into the floor: a page must not predate anything
            // this node — or any earlier response in this scrape — has
            // already seen.
            min_height = min_height.max(self.latest_checkpoint_height());
            if page_height < min_height {
                anyhow::bail!(
                    "stale UTXO pool read: page at checkpoint {page_height} is behind the \
                     freshness floor {min_height}"
                );
            }
            min_height = page_height;
            let page = response.into_inner();
            for field in &page.dynamic_fields {
                let record: types::UtxoRecord = field
                    .value()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize UtxoRecord: {e}"))?;
                records.insert(record.utxo.id, record);
            }
            match page.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        Ok(records)
    }

    pub fn subscribe_checkpoint(&self) -> watch::Receiver<CheckpointInfo> {
        self.0.checkpoint.subscribe()
    }

    pub fn latest_checkpoint_height(&self) -> u64 {
        self.0.checkpoint.borrow().height
    }

    /// Wait until the watcher reaches `target_seq`. Caller wraps with
    /// `tokio::time::timeout` for a bound.
    pub async fn wait_until_checkpoint(&self, target_seq: u64) {
        let mut rx = self.subscribe_checkpoint();
        while rx.borrow().height < target_seq {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn local_limiter(&self) -> Option<Arc<crate::guardian_limiter::LocalLimiter>> {
        self.0.local_limiter.get().cloned()
    }

    pub(crate) fn metrics(&self) -> Option<&Arc<crate::metrics::Metrics>> {
        self.0.metrics.as_ref()
    }

    /// Called once after guardian bootstrap.
    pub fn set_local_limiter(&self, limiter: Arc<crate::guardian_limiter::LocalLimiter>) {
        if self.0.local_limiter.set(limiter).is_err() {
            tracing::warn!("OnchainState::set_local_limiter called twice; ignoring");
        }
    }

    /// Ask the reconcile loop to re-align the local limiter now.
    pub(crate) fn request_limiter_reconcile(&self) {
        self.0.guardian_reconcile_notify.notify_one();
    }

    /// Handle the reconcile loop awaits on.
    pub(crate) fn limiter_reconcile_notify(&self) -> Arc<tokio::sync::Notify> {
        self.0.guardian_reconcile_notify.clone()
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

    fn try_advance_checkpoint(&self, info: CheckpointInfo) -> bool {
        self.0.checkpoint.send_if_modified(|current| {
            if scrape_is_stale(info.height, current.height) {
                return false;
            }
            *current = info;
            true
        })
    }

    fn install_scraped_state(
        &self,
        checkpoint_info: CheckpointInfo,
        hashi: types::Hashi,
    ) -> Result<()> {
        if !self.try_advance_checkpoint(checkpoint_info) {
            anyhow::bail!(
                "stale full-state rescrape: scrape at checkpoint {} is behind the \
                 freshness floor {}",
                checkpoint_info.height,
                self.latest_checkpoint_height(),
            );
        }
        self.replace_hashi_state(hashi);
        Ok(())
    }

    pub fn package_id_original(&self) -> Address {
        self.0.ids.package_id
    }

    pub async fn rescrape(&self) -> Result<()> {
        let (checkpoint_info, hashi, _seed) =
            scrape_hashi(self.client(), self.hashi_id(), self.package_id_original()).await?;
        self.install_scraped_state(checkpoint_info, hashi)
    }

    pub(crate) async fn scrape_committee_for_epoch(&self, epoch: u64) -> Result<Option<Committee>> {
        let committees_id = self.state().hashi().committees.committees_id();
        match scrape_committee(self.client(), committees_id, epoch).await {
            Ok(committee) => Ok(Some(committee)),
            Err(e) => match e.downcast_ref::<tonic::Status>() {
                Some(status) if status.code() == tonic::Code::NotFound => Ok(None),
                _ => Err(e),
            },
        }
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
        if let Some(metrics) = &self.0.metrics {
            hashi.committees.set_metrics(metrics.clone());
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

    pub fn committee_handoff(
        &self,
        from_epoch: u64,
    ) -> Option<SignedMessage<CommitteeTransitionRequest>> {
        self.state()
            .hashi
            .committees
            .committee_handoffs()
            .get(&from_epoch)
            .cloned()
    }

    /// Returns the MPC public key bytes.
    pub fn mpc_public_key(&self) -> Vec<u8> {
        self.state().hashi.committees.mpc_public_key().to_vec()
    }

    /// Deserialize the BCS-encoded MPC group element from on-chain state.
    ///
    /// The on-chain key is stored as `bcs::to_bytes(&G)` in the `CommitteeSet`
    /// and is populated atomically with the `end_reconfig` event.
    pub fn onchain_verifying_key_g(&self) -> Result<HashiMasterG> {
        let bytes = self.mpc_public_key();
        anyhow::ensure!(
            !bytes.is_empty(),
            "MPC public key not yet available on-chain"
        );
        bcs::from_bytes(&bytes).context("failed to deserialize on-chain MPC public key")
    }

    /// Returns all active (not-yet-executed) proposals.
    pub fn proposals(&self) -> Vec<types::Proposal> {
        self.state()
            .hashi
            .proposals
            .active()
            .values()
            .cloned()
            .collect()
    }

    /// Returns all executed proposals.
    pub fn executed_proposals(&self) -> Vec<types::Proposal> {
        self.state()
            .hashi
            .proposals
            .executed()
            .values()
            .cloned()
            .collect()
    }

    /// Returns a specific proposal by ID, looking in active first then
    /// executed.
    pub fn proposal(&self, id: &Address) -> Option<types::Proposal> {
        let state = self.state();
        state
            .hashi
            .proposals
            .active()
            .get(id)
            .or_else(|| state.hashi.proposals.executed().get(id))
            .cloned()
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

    pub fn has_deposit_request(&self, deposit_id: &Address) -> bool {
        self.state()
            .hashi()
            .deposit_queue
            .requests()
            .contains_key(deposit_id)
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

    pub fn withdrawal_txns(&self) -> Vec<types::WithdrawalTransaction> {
        self.state()
            .hashi()
            .withdrawal_queue
            .withdrawal_txns()
            .values()
            .cloned()
            .collect()
    }

    /// True if any `WithdrawalTransaction` is still awaiting witness signatures.
    pub fn has_unsigned_withdrawal_txn(&self) -> bool {
        self.state()
            .hashi()
            .withdrawal_queue
            .withdrawal_txns()
            .values()
            .any(|t| !t.is_fully_signed())
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
            .map(|(_, utxo)| utxo.clone())
            .collect()
    }

    pub fn withdrawal_txn(&self, id: &Address) -> Option<types::WithdrawalTransaction> {
        self.state()
            .hashi()
            .withdrawal_queue
            .withdrawal_txns()
            .get(id)
            .cloned()
    }

    pub fn active_utxo(&self, id: &types::UtxoId) -> Option<types::Utxo> {
        self.state()
            .hashi()
            .utxo_pool
            .active_utxos()
            .find(|(utxo_id, _)| *utxo_id == id)
            .map(|(_, utxo)| utxo.clone())
    }

    pub fn utxo_records(&self) -> std::collections::BTreeMap<types::UtxoId, types::UtxoRecord> {
        self.state().hashi().utxo_pool.utxo_records().clone()
    }

    pub fn bitcoin_deposit_minimum(&self) -> u64 {
        self.state().hashi().config.bitcoin_deposit_minimum()
    }

    pub fn bitcoin_withdrawal_minimum(&self) -> u64 {
        self.state().hashi().config.bitcoin_withdrawal_minimum()
    }

    pub fn worst_case_network_fee(&self) -> u64 {
        self.state().hashi().config.worst_case_network_fee()
    }

    pub fn bitcoin_confirmation_threshold(&self) -> u32 {
        self.state().hashi().config.bitcoin_confirmation_threshold()
    }

    pub fn bitcoin_deposit_time_delay_ms(&self) -> u64 {
        self.state().hashi().config.bitcoin_deposit_time_delay_ms()
    }

    pub fn mpc_threshold_in_basis_points(&self) -> u16 {
        self.state().hashi().config.mpc_threshold_in_basis_points()
    }

    pub fn mpc_nonce_generation_protocol(&self) -> u16 {
        self.state().hashi().config.mpc_nonce_generation_protocol()
    }

    pub fn mpc_weight_reduction_allowed_delta(&self) -> u16 {
        self.state()
            .hashi()
            .config
            .mpc_weight_reduction_allowed_delta()
    }

    pub fn mpc_max_faulty_in_basis_points(&self) -> u16 {
        self.state().hashi().config.mpc_max_faulty_in_basis_points()
    }

    pub fn guardian_url(&self) -> Option<String> {
        self.state()
            .hashi()
            .config
            .guardian_url()
            .map(str::to_string)
    }

    pub fn guardian_btc_public_key(&self) -> Option<Vec<u8>> {
        self.state()
            .hashi()
            .config
            .guardian_btc_public_key()
            .map(<[u8]>::to_vec)
    }

    pub fn bridge_service_client(
        &self,
        validator: &Address,
    ) -> Option<
        hashi_types::proto::bridge_service_client::BridgeServiceClient<crate::grpc::BoxedChannel>,
    > {
        self.state()
            .hashi()
            .committees
            .client(validator)
            .map(|c| c.bridge_service_client())
    }

    pub fn mpc_service_client(
        &self,
        validator: &Address,
    ) -> Option<hashi_types::proto::mpc_service_client::MpcServiceClient<crate::grpc::BoxedChannel>>
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
        protocol_type: move_types::ProtocolType,
    ) -> Result<Option<move_types::EpochCertsV1>> {
        let tob_id = self.tob_id();
        let key = TobKey {
            epoch,
            batch_index,
            protocol_type,
        };
        let key_bcs = bcs::to_bytes(&key)?;
        let mut stream = self
            .0
            .client
            .clone()
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(tob_id)
                    .with_page_size(SCRAPE_PAGE_SIZE)
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

    /// Fetches all raw certificates for the given `(epoch, batch_index, protocol_type)`
    /// bucket from on-chain; caller is responsible for conversion.
    pub async fn fetch_certs(
        &self,
        epoch: u64,
        batch_index: Option<u32>,
        protocol_type: move_types::ProtocolType,
    ) -> Result<Option<Vec<(Address, move_types::DealerSubmissionV1)>>> {
        let epoch_certs = match self
            .fetch_epoch_certs(epoch, batch_index, protocol_type)
            .await?
        {
            Some(certs) => certs,
            None => return Ok(None),
        };
        let Some(head) = epoch_certs.certs.head else {
            return Ok(Some(vec![]));
        };
        let mut nodes: std::collections::HashMap<
            Address,
            move_types::LinkedTableNode<Address, move_types::DealerSubmissionV1>,
        > = std::collections::HashMap::new();
        let mut stream = self
            .0
            .client
            .clone()
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(epoch_certs.certs.id)
                    .with_page_size(SCRAPE_PAGE_SIZE)
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
        Ok(Some(certificates))
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
        // The mirror seed is dropped here for now; the object-driven
        // watcher takes ownership of it when it wires in.
        let (package_versions, (checkpoint_info, hashi, _seed)) = tokio::try_join!(
            scrape_package_versions(client.clone(), ids.package_id),
            scrape_hashi(client, ids.hashi_object_id, ids.package_id),
        )?;

        let package_ids = package_versions.values().cloned().collect();

        Ok((
            State {
                package_versions,
                package_ids,
                hashi,
                withdrawal_signed_at_ms: BTreeMap::new(),
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
            ListPackageVersionsRequest::new(&package_id).with_page_size(SCRAPE_PAGE_SIZE),
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

/// Page through `list_dynamic_fields` manually, collecting every field
/// and the minimum checkpoint height across the responses. The height
/// feeds the mirror's replay floor, which the auto-paginating stream
/// helper cannot surface.
async fn scrape_dynamic_field_pages(
    client: &Client,
    parent: Address,
    mask: FieldMask,
) -> Result<(u64, Vec<DynamicField>)> {
    let mut fields = Vec::new();
    let mut min_height = u64::MAX;
    let mut page_token: Option<bytes::Bytes> = None;
    loop {
        let mut request = ListDynamicFieldsRequest::default()
            .with_parent(parent)
            .with_page_size(SCRAPE_PAGE_SIZE)
            .with_read_mask(mask.clone());
        if let Some(token) = page_token.take() {
            request = request.with_page_token(token);
        }
        let response = client
            .clone()
            .state_client()
            .list_dynamic_fields(request)
            .await?;
        let height = response
            .checkpoint_height()
            .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?;
        min_height = min_height.min(height);
        let page = response.into_inner();
        fields.extend(page.dynamic_fields);
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }
    Ok((min_height, fields))
}

/// The derived object id of the `BitcoinState` dynamic field hanging
/// off the Hashi root.
fn bitcoin_state_field_id(hashi_object_id: Address, package_id: Address) -> Address {
    let bitcoin_state_key = move_types::BitcoinStateKey { dummy_field: false };
    let bitcoin_state_key_type = TypeTag::Struct(Box::new(StructTag::new(
        package_id,
        Identifier::from_static("bitcoin_state"),
        Identifier::from_static("BitcoinStateKey"),
        vec![],
    )));
    hashi_object_id.derive_dynamic_child_id(
        &bitcoin_state_key_type,
        &bitcoin_state_key.to_bcs().unwrap(),
    )
}

/// Fetch the `BitcoinState` dynamic field hanging off the Hashi object.
/// Returns the checkpoint height the response was served at and the
/// field object's version alongside the state, so callers can judge the
/// read's freshness and seed the mirror's object index.
async fn fetch_bitcoin_state(
    mut client: Client,
    hashi_object_id: Address,
    package_id: Address,
) -> Result<(u64, u64, move_types::BitcoinState)> {
    let field_id = bitcoin_state_field_id(hashi_object_id, package_id);
    let bitcoin_state_response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&field_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().contents().finish(),
                Object::path_builder().version(),
            ])),
        )
        .await?;
    let checkpoint_height = bitcoin_state_response
        .checkpoint_height()
        .ok_or_else(|| anyhow!("response missing X_SUI_CHECKPOINT_HEIGHT header"))?;
    let version = bitcoin_state_response.get_ref().object().version();
    let bitcoin_state_field: move_types::Field<
        move_types::BitcoinStateKey,
        move_types::BitcoinState,
    > = bitcoin_state_response
        .into_inner()
        .object()
        .contents()
        .deserialize()
        .map_err(|e| anyhow!("failed to deserialize BitcoinState: {e}"))?;
    Ok((checkpoint_height, version, bitcoin_state_field.value))
}

fn scrape_is_stale(scrape_height: u64, floor: u64) -> bool {
    scrape_height < floor
}

async fn scrape_hashi(
    mut client: Client,
    hashi_object_id: Address,
    package_id: Address,
) -> Result<(CheckpointInfo, types::Hashi, route::MirrorSeed)> {
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

    let root_version = response.get_ref().object().version();
    let root: move_types::Hashi = response.get_ref().object().contents().deserialize()?;

    let mut seed = route::MirrorSeed::new(
        hashi_object_id,
        bitcoin_state_field_id(hashi_object_id, package_id),
    );
    seed.observe_height(checkpoint_info.height);
    seed.routing.set_root_containers(&root);
    seed.index
        .record(hashi_object_id, root_version, route::TrackedKind::HashiRoot);

    let move_types::Hashi {
        id,
        committees,
        config,
        versioning,
        treasury,
        proposals,
        tob,
        num_consumed_presigs,
    } = root;

    let (bitcoin_state_height, bitcoin_state_version, bitcoin_state) =
        fetch_bitcoin_state(client.clone(), id, package_id).await?;
    seed.observe_height(bitcoin_state_height);
    seed.routing.set_bitcoin_state_containers(&bitcoin_state);
    seed.index.record(
        seed.routing.bitcoin_state_field_id(),
        bitcoin_state_version,
        route::TrackedKind::BitcoinStateField,
    );

    let (
        (member_seed, member_info),
        (committee_seed, (committees_per_epoch, committee_handoffs)),
        (treasury_seed, treasury),
        (deposit_seed, deposit_queue),
        (withdrawal_seed, withdrawal_queue),
        (utxo_seed, utxo_pool),
        (proposal_seed, proposals),
        tob_seed,
    ) = tokio::try_join!(
        scrape_all_member_info(client.clone(), committees.members.id),
        scrape_committees(client.clone(), committees.committees.id),
        scrape_treasury(client.clone(), treasury),
        scrape_deposit_requests(client.clone(), bitcoin_state.deposit_queue),
        scrape_withdrawal_queue(client.clone(), bitcoin_state.withdrawal_queue),
        scrape_utxo_pool(client.clone(), bitcoin_state.utxo_pool),
        scrape_proposals(client.clone(), proposals),
        scrape_tob_entries(client.clone(), tob.id),
    )?;
    for container_seed in [
        member_seed,
        committee_seed,
        treasury_seed,
        deposit_seed,
        withdrawal_seed,
        utxo_seed,
        proposal_seed,
        tob_seed,
    ] {
        seed.absorb(container_seed);
    }

    let mut committee_set =
        types::CommitteeSet::new(committees.members.id, committees.committees.id);
    committee_set
        .set_epoch(committees.epoch)
        .set_pending_epoch_change(committees.pending_epoch_change.map(|pending| pending.epoch))
        .set_mpc_public_key(committees.mpc_public_key)
        .set_members(member_info)
        .set_committees(committees_per_epoch)
        .set_committee_handoffs(committee_handoffs);

    Ok((
        checkpoint_info,
        types::Hashi {
            id,
            committees: committee_set,
            config: convert_move_config(config, versioning),
            treasury,
            deposit_queue,
            withdrawal_queue,
            utxo_pool,
            proposals,
            tob_id: tob.id,
            num_consumed_presigs,
        },
        seed,
    ))
}

/// Enumerate the tob bag's entries only to register each entry's inner
/// `LinkedTable` UID (its children are dealer submission nodes) as a
/// known-ignored container, and to seed the entry field ids.
async fn scrape_tob_entries(client: Client, tob_id: Address) -> Result<route::ContainerSeed> {
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().value().finish(),
        DynamicField::path_builder().field_object().version(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(&client, tob_id, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    for field in &fields {
        let certs: move_types::EpochCertsV1 = field
            .value()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize EpochCertsV1: {e}"))?;
        let field_id: Address = field.field_id().parse()?;
        seed.entries.push((
            field_id,
            field.field_object().version(),
            route::TrackedKind::Ignored,
        ));
        seed.interior.push((certs.certs.id, route::Slot::TobCerts));
    }
    Ok(seed)
}

/// Re-fetch only the `config` field from the Hashi Move object.
///
/// This is a lightweight alternative to the full `scrape_hashi` that avoids
/// re-reading all nested dynamic fields (members, committees, treasury, etc.).
/// Used by the watcher to refresh in-memory config when an `UpdateConfig`
/// proposal is executed.
pub(crate) async fn scrape_hashi_config(
    mut client: Client,
    hashi_object_id: Address,
) -> Result<types::Config> {
    let response =
        client
            .ledger_client()
            .get_object(GetObjectRequest::new(&hashi_object_id).with_read_mask(
                FieldMask::from_paths([Object::path_builder().contents().finish()]),
            ))
            .await?;

    let move_types::Hashi {
        config, versioning, ..
    } = response.get_ref().object().contents().deserialize()?;

    Ok(convert_move_config(config, versioning))
}

fn convert_move_config(
    config: move_types::Config,
    versioning: move_types::Versioning,
) -> types::Config {
    types::Config {
        config: config.into_entries().into_iter().collect(),
        enabled_versions: versioning.enabled_versions.contents.into_iter().collect(),
        upgrade_cap: versioning.upgrade_cap,
    }
}

async fn scrape_treasury(
    client: Client,
    treasury: move_types::Treasury,
) -> Result<(route::ContainerSeed, types::Treasury)> {
    let container = treasury.objects.id;
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
        DynamicField::path_builder().child_object().object_id(),
        DynamicField::path_builder().child_object().version(),
        DynamicField::path_builder().child_object().object_type(),
        DynamicField::path_builder()
            .child_object()
            .contents()
            .finish(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(&client, container, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };

    let mut treasury_caps: BTreeMap<TypeTag, types::TreasuryCap> = BTreeMap::new();
    let mut metadata_caps: BTreeMap<TypeTag, types::MetadataCap> = BTreeMap::new();

    for field in &fields {
        let object_type = field.child_object().object_type();
        let type_tag: TypeTag = match object_type.parse() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    "skipping treasury dynamic field with unparseable type {object_type:?}: {e}"
                );
                continue;
            }
        };
        let contents = field.child_object().contents().value();
        let wrapper_id: Address = field.field_id().parse()?;
        let child_id: Address = field.child_object().object_id().parse()?;
        let child_version = field.child_object().version();

        let kind = if let Some(treasury_cap) =
            types::TreasuryCap::try_from_contents(&type_tag, contents)
        {
            let coin_type = treasury_cap.coin_type.clone();
            treasury_caps.insert(coin_type.clone(), treasury_cap);
            route::TrackedKind::TreasuryCap(coin_type)
        } else if let Some(metadata_cap) =
            types::MetadataCap::try_from_contents(&type_tag, contents)
        {
            let coin_type = metadata_cap.coin_type.clone();
            metadata_caps.insert(coin_type.clone(), metadata_cap);
            route::TrackedKind::MetadataCap(coin_type)
        } else {
            tracing::warn!("unknown type stored in treasury");
            continue;
        };
        seed.entries.push((
            wrapper_id,
            field.field_object().version(),
            route::TrackedKind::DofWrapper { container },
        ));
        seed.entries.push((child_id, child_version, kind));
    }

    Ok((
        seed,
        types::Treasury {
            id: container,
            treasury_caps,
            metadata_caps,
        },
    ))
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

/// Convert the raw Move `MemberInfo` into the enriched mirror shape
/// (parsed BLS key, URI, TLS key, and encryption key).
fn convert_move_member_info(info: move_types::MemberInfo) -> types::MemberInfo {
    let move_types::MemberInfo {
        validator_address,
        operator_address,
        next_epoch_public_key,
        endpoint_url,
        tls_public_key,
        next_epoch_encryption_public_key,
        extra_fields: _,
    } = info;
    types::MemberInfo {
        validator_address,
        operator_address,
        next_epoch_public_key: convert_move_uncompressed_g1_pubkey(&next_epoch_public_key),
        endpoint_url: endpoint_url.try_into().ok(),
        tls_public_key: tls_public_key.as_slice().try_into().ok(),
        next_epoch_encryption_public_key: parse_encryption_public_key(
            next_epoch_encryption_public_key.as_slice(),
        )
        .map(Into::into),
    }
}

async fn scrape_all_member_info(
    client: Client,
    member_info_id: Address,
) -> Result<(route::ContainerSeed, BTreeMap<Address, types::MemberInfo>)> {
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().value().finish(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(&client, member_info_id, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    let mut member_info = BTreeMap::new();
    for field in &fields {
        let info: move_types::MemberInfo = field
            .value()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize MemberInfo: {e}"))?;
        let info = convert_move_member_info(info);
        let field_id: Address = field.field_id().parse()?;
        seed.entries.push((
            field_id,
            field.field_object().version(),
            route::TrackedKind::Member(info.validator_address),
        ));
        member_info.insert(info.validator_address, info);
    }
    Ok((seed, member_info))
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

    Ok(convert_move_member_info(field.value))
}

async fn scrape_committees(
    client: Client,
    committees_id: Address,
) -> Result<(
    route::ContainerSeed,
    (
        BTreeMap<u64, Committee>,
        BTreeMap<u64, SignedMessage<CommitteeTransitionRequest>>,
    ),
)> {
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().value().finish(),
        DynamicField::path_builder().value_type(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(&client, committees_id, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };

    let mut move_committees = BTreeMap::new();
    let mut raw_handoffs = BTreeMap::new();
    for field in &fields {
        let value_type: TypeTag = field
            .value_type_opt()
            .ok_or_else(|| anyhow!("missing dynamic field value_type"))?
            .parse()
            .map_err(|e| anyhow!("invalid value_type: {e}"))?;
        let TypeTag::Struct(struct_tag) = &value_type else {
            anyhow::bail!("unexpected committee bag value type: {value_type:?}");
        };
        let field_id: Address = field.field_id().parse()?;
        let field_version = field.field_object().version();
        match struct_tag.name().as_str() {
            "Committee" => {
                let committee: move_types::Committee = field
                    .value()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize Committee: {e}"))?;
                seed.entries.push((
                    field_id,
                    field_version,
                    route::TrackedKind::Committee(committee.epoch),
                ));
                move_committees.insert(committee.epoch, committee);
            }
            "CommitteeHandoff" => {
                let key: move_types::CommitteeHandoffKey = field
                    .name()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize CommitteeHandoffKey: {e}"))?;
                let handoff: move_types::CommitteeHandoff = field
                    .value()
                    .deserialize()
                    .map_err(|e| anyhow!("failed to deserialize CommitteeHandoff: {e}"))?;
                seed.entries.push((
                    field_id,
                    field_version,
                    route::TrackedKind::CommitteeHandoff(key.epoch),
                ));
                raw_handoffs.insert(key.epoch, handoff);
            }
            _ => anyhow::bail!("unexpected committee bag value type: {value_type:?}"),
        }
    }

    let handoffs = raw_handoffs
        .into_iter()
        .map(|(from_epoch, handoff)| {
            let new_committee = move_committees
                .get(&handoff.next_epoch)
                .ok_or_else(|| {
                    anyhow!(
                        "committee handoff for epoch {from_epoch} references missing committee {}",
                        handoff.next_epoch
                    )
                })?
                .clone();
            let signed = convert_move_committee_handoff(handoff, new_committee)
                .map_err(|e| anyhow!("invalid committee handoff for epoch {from_epoch}: {e}"))?;
            Ok((from_epoch, signed))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let committees = move_committees
        .into_iter()
        .map(|(epoch, committee)| (epoch, convert_move_committee(committee)))
        .collect();

    Ok((seed, (committees, handoffs)))
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

    Ok(convert_move_committee(field.value))
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

fn convert_move_committee(c: move_types::Committee) -> Committee {
    let members = c
        .members
        .into_iter()
        .map(convert_move_committee_member)
        .collect();
    // Carry the pinned config verbatim so the rich committee re-serializes to
    // the exact on-chain bytes (used to verify the signed handoff cert).
    Committee::with_config(members, c.epoch, c.config)
}

fn convert_move_committee_handoff(
    handoff: move_types::CommitteeHandoff,
    new_committee: move_types::Committee,
) -> Result<SignedMessage<CommitteeTransitionRequest>> {
    let transition = CommitteeTransitionRequest { new_committee };
    SignedMessage::new(
        handoff.cert.epoch,
        transition,
        &handoff.cert.signature,
        &handoff.cert.signers_bitmap,
    )
    .map_err(|e| anyhow!("invalid committee handoff cert: {e}"))
}

fn convert_move_uncompressed_g1_pubkey(uncompressed_g1: &[u8]) -> BLS12381PublicKey {
    use fastcrypto::traits::ToFromBytes;
    let pubkey = blst::min_pk::PublicKey::deserialize(uncompressed_g1)
        .expect("onchain value is uncompressed G1");
    BLS12381PublicKey::from_bytes(pubkey.to_bytes().as_slice()).unwrap()
}

/// Scrape an `ObjectBag` whose children all BCS-decode as `T`, seeding
/// the wrapper and child index entries. `kind_of` names what each child
/// means to the mirror.
async fn scrape_object_bag<T, F>(
    client: &Client,
    container: Address,
    kind_of: F,
) -> Result<(route::ContainerSeed, Vec<T>)>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> route::TrackedKind,
{
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
        DynamicField::path_builder().child_object().object_id(),
        DynamicField::path_builder().child_object().version(),
        DynamicField::path_builder()
            .child_object()
            .contents()
            .finish(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(client, container, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    let mut values = Vec::with_capacity(fields.len());
    for field in &fields {
        let value: T = field
            .child_object()
            .contents()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize ObjectBag child: {e}"))?;
        let wrapper_id: Address = field.field_id().parse()?;
        let child_id: Address = field.child_object().object_id().parse()?;
        seed.entries.push((
            wrapper_id,
            field.field_object().version(),
            route::TrackedKind::DofWrapper { container },
        ));
        seed.entries
            .push((child_id, field.child_object().version(), kind_of(&value)));
        values.push(value);
    }
    Ok((seed, values))
}

async fn scrape_deposit_requests(
    client: Client,
    deposit_queue: move_types::DepositRequestQueue,
) -> Result<(route::ContainerSeed, types::DepositRequestQueue)> {
    let deposit_queue_id = deposit_queue.requests.id;
    let (seed, values) =
        scrape_object_bag::<types::DepositRequest, _>(&client, deposit_queue_id, |request| {
            route::TrackedKind::DepositRequest(request.id)
        })
        .await?;
    Ok((
        seed,
        types::DepositRequestQueue {
            id: deposit_queue_id,
            requests: values.into_iter().map(|r| (r.id, r)).collect(),
            processed_id: deposit_queue.processed.id,
        },
    ))
}

async fn scrape_withdrawal_queue(
    client: Client,
    withdrawal_queue: move_types::WithdrawalRequestQueue,
) -> Result<(route::ContainerSeed, types::WithdrawalRequestQueue)> {
    let ((mut requests_seed, requests), (txns_seed, withdrawal_txns)) = tokio::try_join!(
        scrape_object_bag::<types::WithdrawalRequest, _>(
            &client,
            withdrawal_queue.requests.id,
            |request| route::TrackedKind::WithdrawalRequest(request.id),
        ),
        scrape_object_bag::<types::WithdrawalTransaction, _>(
            &client,
            withdrawal_queue.withdrawal_txns.id,
            |txn| route::TrackedKind::WithdrawalTxn(txn.id),
        ),
    )?;
    requests_seed.merge(txns_seed);

    Ok((
        requests_seed,
        types::WithdrawalRequestQueue {
            requests_id: withdrawal_queue.requests.id,
            requests: requests.into_iter().map(|r| (r.id, r)).collect(),
            processed_id: withdrawal_queue.processed.id,
            withdrawal_txns_id: withdrawal_queue.withdrawal_txns.id,
            withdrawal_txns: withdrawal_txns.into_iter().map(|t| (t.id, t)).collect(),
            confirmed_txns_id: withdrawal_queue.confirmed_txns.id,
        },
    ))
}

/// Fetch a single WithdrawalTransaction by its object ID.
/// WithdrawalTransaction has `key`, so it's stored as a child object in the
/// ObjectBag and can be fetched directly by its ID.
pub(super) async fn fetch_withdrawal_txn(
    client: &mut Client,
    withdrawal_txn_id: Address,
) -> Result<types::WithdrawalTransaction> {
    let response = client
        .ledger_client()
        .get_object(GetObjectRequest::new(&withdrawal_txn_id).with_read_mask(
            FieldMask::from_paths([Object::path_builder().contents().finish()]),
        ))
        .await?;

    let txn: types::WithdrawalTransaction = response
        .into_inner()
        .object()
        .contents()
        .deserialize()
        .map_err(|e| anyhow!("failed to deserialize WithdrawalTransaction: {e}"))?;

    Ok(txn)
}

async fn scrape_utxo_pool(
    client: Client,
    utxo_pool: move_types::UtxoPool,
) -> Result<(route::ContainerSeed, types::UtxoPool)> {
    let ((mut records_seed, utxo_records), (spent_seed, spent_utxos)) = tokio::try_join!(
        scrape_utxo_records(client.clone(), utxo_pool.utxo_records.id),
        scrape_spent_utxos(client.clone(), utxo_pool.spent_utxos.id),
    )?;
    records_seed.merge(spent_seed);

    Ok((
        records_seed,
        types::UtxoPool {
            utxo_records_id: utxo_pool.utxo_records.id,
            utxo_records,
            spent_utxos_id: utxo_pool.spent_utxos.id,
            spent_utxos,
        },
    ))
}

fn plain_field_mask() -> FieldMask {
    FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().value().finish(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
    ])
}

async fn scrape_utxo_records(
    client: Client,
    utxo_records_id: Address,
) -> Result<(
    route::ContainerSeed,
    BTreeMap<types::UtxoId, types::UtxoRecord>,
)> {
    let (height, fields) =
        scrape_dynamic_field_pages(&client, utxo_records_id, plain_field_mask()).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    let mut utxo_records = BTreeMap::new();
    for field in &fields {
        let record: types::UtxoRecord = field
            .value()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize UtxoRecord: {e}"))?;
        let field_id: Address = field.field_id().parse()?;
        seed.entries.push((
            field_id,
            field.field_object().version(),
            route::TrackedKind::UtxoRecord(record.utxo.id),
        ));
        utxo_records.insert(record.utxo.id, record);
    }
    Ok((seed, utxo_records))
}

async fn scrape_spent_utxos(
    client: Client,
    spent_utxos_id: Address,
) -> Result<(route::ContainerSeed, BTreeMap<types::UtxoId, u64>)> {
    let (height, fields) =
        scrape_dynamic_field_pages(&client, spent_utxos_id, plain_field_mask()).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    let mut spent_utxos = BTreeMap::new();
    for field in &fields {
        let utxo_id: types::UtxoId = field
            .name()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize UtxoId: {e}"))?;
        let spent_epoch: u64 = field
            .value()
            .deserialize()
            .map_err(|e| anyhow!("failed to deserialize spent epoch: {e}"))?;
        let field_id: Address = field.field_id().parse()?;
        seed.entries.push((
            field_id,
            field.field_object().version(),
            route::TrackedKind::SpentUtxo(utxo_id),
        ));
        spent_utxos.insert(utxo_id, spent_epoch);
    }
    Ok((seed, spent_utxos))
}

async fn scrape_proposals(
    client: Client,
    proposals: move_types::Proposals,
) -> Result<(route::ContainerSeed, types::Proposals)> {
    let active_id = proposals.active.id;
    let executed_id = proposals.executed.id;
    let ((mut active_seed, active), (executed_seed, executed)) = tokio::try_join!(
        scrape_proposal_bag(client.clone(), proposals.active, false),
        scrape_proposal_bag(client, proposals.executed, true),
    )?;
    active_seed.merge(executed_seed);
    Ok((
        active_seed,
        types::Proposals {
            active_id,
            executed_id,
            active,
            executed,
        },
    ))
}

async fn scrape_proposal_bag(
    client: Client,
    bag: move_types::ObjectBag,
    executed: bool,
) -> Result<(route::ContainerSeed, BTreeMap<Address, types::Proposal>)> {
    // Proposals live in a `0x2::object_bag::ObjectBag`, so each entry's
    // payload is a standalone child object. Read `child_object` directly —
    // fullnode gRPC populates `child_object.object_type` + BCS `contents`
    // for dynamic-object-field kinds.
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().field_id(),
        DynamicField::path_builder().field_object().version(),
        DynamicField::path_builder().child_object().object_id(),
        DynamicField::path_builder().child_object().version(),
        DynamicField::path_builder().child_object().object_type(),
        DynamicField::path_builder()
            .child_object()
            .contents()
            .finish(),
    ]);
    let (height, fields) = scrape_dynamic_field_pages(&client, bag.id, mask).await?;
    let mut seed = route::ContainerSeed {
        height,
        ..Default::default()
    };
    let mut proposals: BTreeMap<Address, types::Proposal> = BTreeMap::new();

    for field in &fields {
        // `child_object.object_type` is the fully-qualified type, e.g.
        //   <package>::proposal::Proposal<<package>::update_config::UpdateConfig>
        let object_type = field.child_object().object_type();
        let type_tag: TypeTag = match object_type.parse() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    "skipping proposal dynamic object field with unparseable type \
                     {object_type:?}: {e}"
                );
                continue;
            }
        };
        if let Some(proposal) = decode_proposal(&type_tag, field.child_object().contents().value())
        {
            let wrapper_id: Address = field.field_id().parse()?;
            let child_id: Address = field.child_object().object_id().parse()?;
            seed.entries.push((
                wrapper_id,
                field.field_object().version(),
                route::TrackedKind::DofWrapper { container: bag.id },
            ));
            seed.entries.push((
                child_id,
                field.child_object().version(),
                route::TrackedKind::Proposal {
                    executed,
                    id: proposal.id,
                },
            ));
            proposals.insert(proposal.id, proposal);
        } else {
            tracing::warn!("Failed to deserialize proposal with type {:?}", type_tag);
        }
    }

    Ok((seed, proposals))
}

/// Decode a `Proposal<T>` object into the lightweight mirror shape,
/// dispatching the BCS layout on the type parameter `T`. Returns `None`
/// for unknown proposal types or undecodable contents.
fn decode_proposal(type_tag: &TypeTag, contents: &[u8]) -> Option<types::Proposal> {
    fn parse<T: serde::de::DeserializeOwned>(contents: &[u8]) -> Option<(Address, u64)> {
        bcs::from_bytes::<move_types::Proposal<T>>(contents)
            .ok()
            .map(|p| (p.id, p.created_timestamp_ms))
    }

    let proposal_type = parse_proposal_type(type_tag);
    let (id, timestamp_ms) = match &proposal_type {
        types::ProposalType::UpdateConfig => parse::<move_types::UpdateConfig>(contents),
        types::ProposalType::EnableVersion => parse::<move_types::EnableVersion>(contents),
        types::ProposalType::DisableVersion => parse::<move_types::DisableVersion>(contents),
        types::ProposalType::Upgrade => parse::<move_types::Upgrade>(contents),
        types::ProposalType::EmergencyPause => parse::<move_types::EmergencyPause>(contents),
        types::ProposalType::AbortReconfig => parse::<move_types::AbortReconfig>(contents),
        types::ProposalType::UpdateGuardian => parse::<move_types::UpdateGuardian>(contents),
        types::ProposalType::Unknown(_) => None,
    }?;
    Some(types::Proposal {
        id,
        timestamp_ms,
        proposal_type,
    })
}

pub(crate) fn parse_proposal_type(type_tag: &TypeTag) -> types::ProposalType {
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
        ("update_config", "UpdateConfig") => types::ProposalType::UpdateConfig,
        ("enable_version", "EnableVersion") => types::ProposalType::EnableVersion,
        ("disable_version", "DisableVersion") => types::ProposalType::DisableVersion,
        ("upgrade", "Upgrade") => types::ProposalType::Upgrade,
        ("emergency_pause", "EmergencyPause") => types::ProposalType::EmergencyPause,
        ("abort_reconfig", "AbortReconfig") => types::ProposalType::AbortReconfig,
        ("update_guardian", "UpdateGuardian") => types::ProposalType::UpdateGuardian,
        _ => types::ProposalType::Unknown(format!("{}::{}", inner_tag.module(), inner_tag.name())),
    }
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

    // The Move contract stores the BLS12-381 G1 identity element as a member's
    // default `next_epoch_public_key` until a real key is registered (see
    // `new_member` in committee_set.move), and the scrapers run
    // `convert_move_uncompressed_g1_pubkey` on every member without filtering.
    // The conversion must therefore accept the identity element without
    // panicking: `blst` only rejects the point at infinity in
    // `validate`/`key_validate`, neither of which this path calls. This test
    // pins that behavior so swapping in a validating decoder later cannot
    // silently turn honest onboarding into a node crash.
    #[test]
    fn test_convert_identity_element_key_does_not_panic() {
        use fastcrypto::groups::GroupElement;
        use fastcrypto::groups::bls12381::G1Element;
        use fastcrypto::groups::bls12381::G1ElementUncompressed;

        // Reproduce exactly what `g1_to_uncompressed_g1(g1_identity())` stores
        // on chain: the uncompressed serialization of the G1 point at infinity.
        let onchain_bytes = G1ElementUncompressed::from(&G1Element::zero()).into_byte_array();
        assert_eq!(onchain_bytes.len(), 96);
        assert_eq!(
            onchain_bytes[0], 0x40,
            "blst serializes the point at infinity with the infinity bit set"
        );
        assert!(onchain_bytes[1..].iter().all(|&b| b == 0));

        // The conversion succeeds and yields the compressed encoding of the
        // point at infinity (0xc0 followed by zeros).
        let pubkey = convert_move_uncompressed_g1_pubkey(&onchain_bytes);
        let mut expected = [0u8; 48];
        expected[0] = 0xc0;
        assert_eq!(pubkey.as_bytes(), expected.as_slice());
    }
}
