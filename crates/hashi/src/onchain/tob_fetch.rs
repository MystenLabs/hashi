// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use sui_rpc::Client;
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::ToBcs;
use tokio::sync::mpsc;
use tokio::time::Instant;

use hashi_types::move_types;
use hashi_types::move_types::TobKey;

use super::OnchainState;
use super::TobNode;
use super::route::ObjectIndex;
use super::route::RoutingTable;
use super::route::TrackedKind;
use super::types;

pub(super) const FETCH_INTERVAL: Duration = Duration::from_secs(30);
const ASK_QUEUE: usize = 1024;
const MAX_MISSING_RUN: u32 = 64;
const STALE_RETRIES: u32 = 3;
const STALE_BACKOFF: Duration = Duration::from_millis(250);

pub(super) fn nonce_key(epoch: u64, batch: u32) -> TobKey {
    TobKey {
        epoch,
        batch_index: Some(batch),
        protocol_type: move_types::ProtocolType::NonceGeneration,
    }
}

pub(super) fn missing_batch_run(batch: u32, window: u32, avid_ceiling: u32) -> RangeInclusive<u32> {
    let last = batch
        .saturating_add(window.min(MAX_MISSING_RUN).saturating_sub(1))
        .min(avid_ceiling)
        .max(batch);
    batch..=last
}

pub(super) fn tob_bucket_field_id(
    tob_id: Address,
    package_original: Address,
    key: &TobKey,
) -> Address {
    let key_type = TypeTag::Struct(Box::new(StructTag::new(
        package_original,
        Identifier::from_static("tob"),
        Identifier::from_static("TobKey"),
        vec![],
    )));
    tob_id.derive_dynamic_child_id(
        &key_type,
        &key.to_bcs().expect("TobKey BCS serialization cannot fail"),
    )
}

#[derive(Debug)]
pub(super) struct TobAsk {
    epoch: u64,
    batches: Vec<u32>,
}

#[derive(Debug)]
pub(super) struct TobFetch {
    asks: mpsc::Sender<TobAsk>,
    shared: Mutex<Shared>,
}

#[derive(Debug, Default)]
struct Shared {
    caught_up: bool,
    clocks: BTreeMap<TobKey, Clock>,
    asked: BTreeMap<TobKey, Instant>,
    pending: BTreeSet<TobKey>,
    fetched: BTreeSet<TobKey>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unready {
    Absent,
    Converging,
    Stranded,
}

#[derive(Clone, Copy, Debug)]
struct Clock {
    started: Instant,
    last_read: Instant,
}

impl TobFetch {
    pub(super) fn new() -> (Self, mpsc::Receiver<TobAsk>) {
        let (asks, receiver) = mpsc::channel(ASK_QUEUE);
        let fetch = Self {
            asks,
            shared: Mutex::default(),
        };
        (fetch, receiver)
    }

    pub(super) fn unready(&self, key: TobKey, found: Unready, now: Instant) {
        let due = {
            let mut shared = self.shared.lock().unwrap();
            shared.clocks.retain(|_, clock| {
                now.saturating_duration_since(clock.last_read) <= FETCH_INTERVAL
            });
            let ask_now = found == Unready::Stranded && shared.caught_up;
            let clock = shared.clocks.entry(key).or_insert(Clock {
                started: now,
                last_read: now,
            });
            clock.last_read = now;
            let due = ask_now || now.saturating_duration_since(clock.started) >= FETCH_INTERVAL;
            if due {
                clock.started = now;
            }
            due
        };
        if due && let Some(batch) = key.batch_index {
            self.ask(key.epoch, batch..=batch, now);
        }
    }

    pub(super) fn complete(&self, key: &TobKey) {
        self.shared.lock().unwrap().clocks.remove(key);
    }

    pub(super) fn ask(&self, epoch: u64, batches: RangeInclusive<u32>, now: Instant) {
        let (asked, newly_pending) = {
            let mut shared = self.shared.lock().unwrap();
            shared
                .asked
                .retain(|_, at| now.saturating_duration_since(*at) < FETCH_INTERVAL);
            shared.fetched.retain(|key| key.epoch >= epoch);
            let mut asked = Vec::new();
            let mut newly_pending = Vec::new();
            for batch in batches {
                let key = nonce_key(epoch, batch);
                if shared.asked.contains_key(&key) {
                    continue;
                }
                shared.asked.insert(key, now);
                if !shared.fetched.contains(&key) && shared.pending.insert(key) {
                    newly_pending.push(key);
                }
                asked.push(batch);
            }
            (asked, newly_pending)
        };
        if asked.is_empty() {
            return;
        }
        if let Err(error) = self.asks.try_send(TobAsk {
            epoch,
            batches: asked,
        }) {
            let mut shared = self.shared.lock().unwrap();
            for batch in error.into_inner().batches {
                shared.asked.remove(&nonce_key(epoch, batch));
            }
            for key in &newly_pending {
                shared.pending.remove(key);
            }
        }
    }

    pub(super) fn pending(&self, key: &TobKey) -> bool {
        let shared = self.shared.lock().unwrap();
        !shared.caught_up || shared.pending.contains(key)
    }

    pub(super) fn set_caught_up(&self, caught_up: bool) {
        self.shared.lock().unwrap().caught_up = caught_up;
    }

    fn ended(&self, key: &TobKey) {
        let mut shared = self.shared.lock().unwrap();
        shared.pending.remove(key);
        shared.fetched.insert(*key);
    }

    fn dropped(&self, key: &TobKey) {
        let mut shared = self.shared.lock().unwrap();
        shared.pending.remove(key);
        shared.asked.remove(key);
    }

    fn reset(&self) {
        let mut shared = self.shared.lock().unwrap();
        shared.pending.clear();
        shared.asked.clear();
        shared.fetched.clear();
    }
}

#[derive(Debug)]
pub(super) struct Listing {
    pub(super) field_id: Address,
    pub(super) version: u64,
    pub(super) field: move_types::Field<TobKey, move_types::EpochCertsV1>,
    pub(super) nodes: Vec<TobNode>,
}

#[derive(Debug)]
pub(super) struct Fetched {
    generation: u64,
    key: TobKey,
    listing: Result<Option<Listing>>,
}

pub(super) struct Fetcher {
    generation: u64,
    running: BTreeSet<TobKey>,
    results_sender: mpsc::UnboundedSender<Fetched>,
    pub(super) results: mpsc::UnboundedReceiver<Fetched>,
}

impl Fetcher {
    pub(super) fn new() -> Self {
        let (results_sender, results) = mpsc::unbounded_channel();
        Self {
            generation: 0,
            running: BTreeSet::new(),
            results_sender,
            results,
        }
    }

    pub(super) fn reset(&mut self, state: &OnchainState) {
        self.generation += 1;
        self.running.clear();
        if let Some(fetch) = state.tob_fetch() {
            fetch.reset();
        }
    }

    pub(super) fn ask(&mut self, state: &OnchainState, applied: u64, ask: TobAsk) {
        let Some(fetch) = state.tob_fetch() else {
            return;
        };
        let TobAsk { epoch, batches } = ask;
        let mut started = Vec::new();
        {
            let mut guard = state.state_mut();
            let current = guard.hashi.committees.epoch();
            let mirror = guard.hashi.tob.mirror_mut();
            for batch in batches {
                let key = nonce_key(epoch, batch);
                if self.running.contains(&key) {
                    continue;
                }
                if epoch != current {
                    fetch.dropped(&key);
                    continue;
                }
                mirror.marked.insert(key);
                self.running.insert(key);
                started.push(batch);
            }
        }
        if started.is_empty() {
            return;
        }
        tracing::info!(
            epoch,
            batches = ?started,
            applied,
            "fetching TOB nonce buckets a reader needs"
        );
        let client = state.client();
        let tob_id = state.tob_id();
        let package_original = state.package_id_original();
        let packages = state.state().package_versions.clone();
        for batch in started {
            let key = nonce_key(epoch, batch);
            let client = client.clone();
            let packages = packages.clone();
            let sender = self.results_sender.clone();
            let generation = self.generation;
            tokio::spawn(async move {
                let listing =
                    list_bucket(&client, tob_id, package_original, &packages, key, applied).await;
                let _ = sender.send(Fetched {
                    generation,
                    key,
                    listing,
                });
            });
        }
    }

    pub(super) fn merge(
        &mut self,
        state: &OnchainState,
        routing: &mut RoutingTable,
        index: &mut ObjectIndex,
        fetched: Fetched,
    ) {
        if fetched.generation != self.generation {
            return;
        }
        self.running.remove(&fetched.key);
        match fetched.listing {
            Err(e) => {
                tracing::warn!(key = ?fetched.key, "TOB bucket fetch failed: {e:#}");
            }
            Ok(None) => {
                tracing::debug!(key = ?fetched.key, "fetched TOB bucket does not exist");
            }
            Ok(Some(listing)) => {
                let merged = merge_listing(&mut state.state_mut().hashi, routing, index, listing);
                match merged {
                    None => tracing::info!(
                        key = ?fetched.key,
                        "dropped a fetched TOB bucket: its epoch is no longer current"
                    ),
                    Some(recovered) => {
                        tracing::info!(key = ?fetched.key, recovered, "merged a fetched TOB bucket");
                        if recovered && let Some(metrics) = state.metrics() {
                            metrics.watcher_tob_fetch_recoveries_total.inc();
                        }
                    }
                }
            }
        }
        if let Some(fetch) = state.tob_fetch() {
            fetch.ended(&fetched.key);
        }
    }
}

pub(super) fn merge_listing(
    hashi: &mut types::Hashi,
    routing: &mut RoutingTable,
    index: &mut ObjectIndex,
    listing: Listing,
) -> Option<bool> {
    let key = listing.field.name;
    if key.epoch != hashi.committees.epoch() {
        return None;
    }
    let mirror = hashi.tob.mirror_mut();
    if listing.field.value.seal.is_some() {
        mirror.fold_seal(&key);
    }
    let mut recovered = false;
    if !index.is_stale_write(&listing.field_id, listing.version) {
        recovered |= index.get(&listing.field_id).is_none();
        let kind = super::apply::upsert_tob_bucket(mirror, routing, listing.field);
        index.record(listing.field_id, listing.version, kind);
    }
    let Some(bucket) = mirror.buckets.get_mut(&key) else {
        return Some(recovered);
    };
    for node in listing.nodes {
        if index.is_stale_write(&node.id, node.version) {
            continue;
        }
        recovered |= index.get(&node.id).is_none();
        bucket.nodes.insert(node.dealer, node.node);
        index.record(
            node.id,
            node.version,
            TrackedKind::TobCert {
                key,
                dealer: node.dealer,
            },
        );
    }
    Some(recovered)
}

async fn list_bucket(
    client: &Client,
    tob_id: Address,
    package_original: Address,
    packages: &move_types::PackageVersions,
    key: TobKey,
    applied: u64,
) -> Result<Option<Listing>> {
    let field_id = tob_bucket_field_id(tob_id, package_original, &key);
    let fresh = |height: Option<u64>| height.is_some_and(|height| height > applied);
    let first_attempt = Instant::now();
    let mut backoff = STALE_BACKOFF;
    for attempt in 0..=STALE_RETRIES {
        if attempt > 0 {
            tokio::time::sleep(backoff).await;
            backoff = backoff.saturating_mul(2);
        }
        let response = client
            .clone()
            .ledger_client()
            .get_object(
                GetObjectRequest::new(&field_id).with_read_mask(FieldMask::from_paths([
                    Object::path_builder().object_id(),
                    Object::path_builder().version(),
                    Object::path_builder().object_type(),
                    Object::path_builder().contents().finish(),
                ])),
            )
            .await;
        let response = match response {
            Ok(response) => response,
            Err(status) if status.code() == tonic::Code::NotFound => {
                if fresh(status.checkpoint_height()) {
                    return Ok(None);
                }
                continue;
            }
            Err(status) => {
                let error = anyhow::Error::from(status);
                if super::page_retry_due(attempt, first_attempt.elapsed(), &error) {
                    continue;
                }
                return Err(error);
            }
        };
        if !fresh(response.checkpoint_height()) {
            continue;
        }
        let object = response.get_ref().object();
        let tag: StructTag = object.object_type().parse()?;
        super::apply::known_tob_bucket(packages, &tag)
            .ok_or_else(|| anyhow!("unknown TOB bucket type {tag}"))?;
        let field: move_types::Field<TobKey, move_types::EpochCertsV1> =
            object.contents().deserialize()?;
        anyhow::ensure!(
            field.name == key,
            "the Field at {field_id} holds {:?}, not {key:?}",
            field.name
        );
        let mut nodes = Vec::new();
        let heights =
            super::scrape_tob_nodes(client, field.value.certs.id, "tob_fetch", None, |node| {
                nodes.push(node)
            })
            .await?;
        if heights.floor <= applied {
            continue;
        }
        return Ok(Some(Listing {
            field_id,
            version: object.version(),
            field,
            nodes,
        }));
    }
    Err(anyhow!(
        "TOB bucket {key:?} was never served past checkpoint {applied}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::Arc;

    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_rpc::proto::sui::rpc::v2::DynamicField;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
    use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsResponse;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateService;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateServiceServer;

    #[derive(serde_derive::Serialize)]
    struct FieldEnc<N: serde::Serialize, V: serde::Serialize> {
        id: Address,
        name: N,
        value: V,
    }

    #[tokio::test]
    async fn a_polling_reader_asks_once_its_clock_has_run_the_interval() {
        let (fetch, mut asks) = TobFetch::new();
        let start = Instant::now();
        let key = nonce_key(3, 5);
        fetch.unready(key, Unready::Absent, start);
        fetch.unready(key, Unready::Absent, start + Duration::from_secs(20));
        assert!(asks.try_recv().is_err());
        fetch.unready(key, Unready::Absent, start + FETCH_INTERVAL);
        let ask = asks.try_recv().unwrap();
        assert_eq!((ask.epoch, ask.batches), (3, vec![5]));
        fetch.unready(
            key,
            Unready::Absent,
            start + FETCH_INTERVAL + Duration::from_secs(1),
        );
        assert!(asks.try_recv().is_err());

        let lapsed = nonce_key(3, 6);
        fetch.unready(lapsed, Unready::Absent, start);
        fetch.unready(
            lapsed,
            Unready::Absent,
            start + FETCH_INTERVAL + Duration::from_secs(1),
        );
        assert!(asks.try_recv().is_err());

        let completed = nonce_key(3, 7);
        fetch.unready(completed, Unready::Absent, start);
        fetch.complete(&completed);
        fetch.unready(completed, Unready::Absent, start + FETCH_INTERVAL);
        assert!(asks.try_recv().is_err());

        let stranded = nonce_key(3, 8);
        fetch.unready(stranded, Unready::Stranded, start);
        assert!(asks.try_recv().is_err());
        fetch.set_caught_up(true);
        fetch.unready(nonce_key(3, 9), Unready::Converging, start);
        fetch.unready(nonce_key(3, 10), Unready::Absent, start);
        assert!(asks.try_recv().is_err());
        fetch.unready(stranded, Unready::Stranded, start + Duration::from_secs(1));
        assert_eq!(asks.try_recv().unwrap().batches, vec![8]);
    }

    #[tokio::test]
    async fn repair_waits_only_for_a_buckets_first_fetch() {
        let (fetch, mut asks) = TobFetch::new();
        let start = Instant::now();
        let key = nonce_key(3, 6);
        assert!(fetch.pending(&key));
        fetch.set_caught_up(true);
        assert!(!fetch.pending(&key));

        fetch.ask(3, 5..=8, start);
        assert!(fetch.pending(&key));
        assert_eq!(asks.try_recv().unwrap().batches, vec![5, 6, 7, 8]);
        fetch.ended(&key);
        assert!(!fetch.pending(&key));

        fetch.ask(3, 5..=8, start + Duration::from_secs(10));
        assert!(!fetch.pending(&key));
        assert!(asks.try_recv().is_err());

        fetch.ask(3, 5..=8, start + Duration::from_secs(60));
        assert!(!fetch.pending(&key));
        assert!(fetch.pending(&nonce_key(3, 5)));
        assert_eq!(asks.try_recv().unwrap().batches, vec![5, 6, 7, 8]);

        fetch.ended(&nonce_key(3, 5));
        fetch.ask(2, 1..=1, start + Duration::from_secs(61));
        fetch.ask(3, 5..=5, start + Duration::from_secs(120));
        assert!(!fetch.pending(&nonce_key(3, 5)));
    }

    #[test]
    fn a_missing_batch_asks_for_a_window_or_up_to_the_avid_ceiling() {
        assert_eq!(missing_batch_run(5, 32, 100), 5..=36);
        assert_eq!(missing_batch_run(5, 32, 10), 5..=10);
        assert_eq!(missing_batch_run(5, 32, 3), 5..=5);
        assert_eq!(missing_batch_run(5, 1_000, 10_000), 5..=68);
        assert_eq!(
            missing_batch_run(u32::MAX - 1, 32, u32::MAX),
            u32::MAX - 1..=u32::MAX
        );
        assert_eq!(
            missing_batch_run(u32::MAX, 32, u32::MAX),
            u32::MAX..=u32::MAX
        );
    }

    #[derive(Clone)]
    struct LaggingBucket {
        field: Object,
        nodes: Vec<DynamicField>,
        field_heights: Arc<Mutex<Vec<u64>>>,
        node_height: u64,
    }

    fn with_height<T>(message: T, height: u64) -> tonic::Response<T> {
        let mut response = tonic::Response::new(message);
        response.metadata_mut().insert(
            sui_rpc::headers::X_SUI_CHECKPOINT_HEIGHT,
            height.to_string().parse().unwrap(),
        );
        response
    }

    #[tonic::async_trait]
    impl LedgerService for LaggingBucket {
        async fn get_object(
            &self,
            _request: tonic::Request<sui_rpc::proto::sui::rpc::v2::GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            let height = self.field_heights.lock().unwrap().remove(0);
            Ok(with_height(
                GetObjectResponse::new(self.field.clone()),
                height,
            ))
        }
    }

    #[tonic::async_trait]
    impl StateService for LaggingBucket {
        async fn list_dynamic_fields(
            &self,
            _request: tonic::Request<ListDynamicFieldsRequest>,
        ) -> Result<tonic::Response<ListDynamicFieldsResponse>, tonic::Status> {
            Ok(with_height(
                ListDynamicFieldsResponse::default().with_dynamic_fields(self.nodes.clone()),
                self.node_height,
            ))
        }
    }

    async fn spawn(service: LaggingBucket) -> Client {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let result = listener.accept().await.map(|(stream, _)| stream);
            Some((result, listener))
        });
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(LedgerServiceServer::new(service.clone()))
                .add_service(StateServiceServer::new(service))
                .serve_with_incoming(incoming),
        );
        Client::new(format!("http://{addr}").as_str()).unwrap()
    }

    #[tokio::test]
    async fn a_listing_served_at_the_applied_checkpoint_is_listed_again() {
        let package = Address::from_static("0x7");
        let tob_id = Address::from_static("0x70");
        let key = nonce_key(3, 5);
        let field_id = tob_bucket_field_id(tob_id, package, &key);
        let certs_id = Address::from_static("0x71");
        let dealer = Address::from_static("0xd1");
        let struct_tag = |module: &str, name: &str| {
            TypeTag::Struct(Box::new(StructTag::new(
                package,
                Identifier::new(module).unwrap(),
                Identifier::new(name).unwrap(),
                vec![],
            )))
        };
        let field_type = StructTag::new(
            Address::TWO,
            Identifier::from_static("dynamic_field"),
            Identifier::from_static("Field"),
            vec![
                struct_tag("tob", "TobKey"),
                struct_tag("tob", "EpochCertsV1"),
            ],
        );
        let value = move_types::EpochCertsV1 {
            epoch: 3,
            protocol_type: move_types::ProtocolType::NonceGeneration,
            certs: move_types::LinkedTable {
                id: certs_id,
                size: 1,
                head: Some(dealer),
                tail: Some(dealer),
            },
            seal: None,
        };
        let field = Object::default()
            .with_object_id(field_id.to_string())
            .with_version(4)
            .with_object_type(field_type.to_string())
            .with_contents(
                Bcs::serialize(&FieldEnc {
                    id: field_id,
                    name: key,
                    value,
                })
                .unwrap(),
            );
        let node = move_types::LinkedTableNode::<Address, _> {
            prev: None,
            next: None,
            value: move_types::DealerSubmissionV1 {
                message: move_types::DealerMessagesHashV1 {
                    dealer_address: dealer,
                    messages_hash: vec![0xAB; 32],
                },
                signature: move_types::CommitteeSignature {
                    epoch: 3,
                    signature: vec![0xCD; 96],
                    signers_bitmap: vec![0b1],
                },
                timestamp_ms: 1_000,
            },
        };
        let node_field = DynamicField::default()
            .with_name(Bcs::serialize(&dealer).unwrap())
            .with_field_id("0x72")
            .with_value(Bcs::serialize(&node).unwrap())
            .with_field_object(Object::default().with_version(4));
        let field_heights = Arc::new(Mutex::new(vec![10, 11]));
        let client = spawn(LaggingBucket {
            field,
            nodes: vec![node_field],
            field_heights: field_heights.clone(),
            node_height: 11,
        })
        .await;
        let packages = move_types::PackageVersions::new(BTreeMap::from([(1, package)]));

        let listing = list_bucket(&client, tob_id, package, &packages, key, 10)
            .await
            .unwrap()
            .unwrap();

        assert!(field_heights.lock().unwrap().is_empty());
        assert_eq!(listing.field_id, field_id);
        assert_eq!(listing.version, 4);
        assert_eq!(listing.field.name, key);
        assert_eq!(
            listing
                .nodes
                .iter()
                .map(|node| node.dealer)
                .collect::<Vec<_>>(),
            vec![dealer]
        );
    }
}
