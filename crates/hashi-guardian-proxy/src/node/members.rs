// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The registered TLS keys of the current and pending committee's members,
//! re-read from chain in the background. The member gate
//! ([`crate::node::member_auth`]) only reads the latest snapshot, so no request, and
//! no unknown key, ever waits on or triggers a Sui read.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Context as _;
use hashi_types::guardian::now_timestamp_ms;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::move_types;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use sui_rpc::client::ResponseExt;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::bcs::ToBcs;
use sui_sdk_types::Address;
use sui_sdk_types::TypeTag;
use tonic::transport::Channel;
use tracing::info;
use tracing::warn;

use crate::metrics::ProxyMetrics;

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Once the chain state it was read from is this old, a snapshot admits no one,
/// so a Sui RPC outage or a stalled fullnode fails closed.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(10 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const PAGE_SIZE: u32 = 1000;

#[derive(Debug)]
pub struct MemberSnapshot {
    /// The members' registered TLS public keys.
    pub members: HashSet<[u8; 32]>,
    /// Checkpoint time of the stalest read it was built from.
    pub checkpoint_timestamp_ms: u64,
}

#[tonic::async_trait]
pub trait MemberSource: Send + Sync + 'static {
    async fn fetch(&self) -> anyhow::Result<MemberSnapshot>;
}

pub struct MemberAllowlist {
    latest: RwLock<Option<Arc<MemberSnapshot>>>,
    metrics: Arc<ProxyMetrics>,
}

impl MemberAllowlist {
    pub fn new(metrics: Arc<ProxyMetrics>) -> Self {
        Self {
            latest: RwLock::new(None),
            metrics,
        }
    }

    /// The latest snapshot, unless it is too old to trust.
    pub fn current(&self) -> Option<Arc<MemberSnapshot>> {
        let snapshot = self
            .latest
            .read()
            .expect("allowlist lock poisoned")
            .clone()?;
        let age_ms = now_timestamp_ms().saturating_sub(snapshot.checkpoint_timestamp_ms);
        (u128::from(age_ms) <= MAX_SNAPSHOT_AGE.as_millis()).then_some(snapshot)
    }

    /// Refresh from `source` forever. A failed read keeps the last snapshot
    /// until it ages out.
    pub async fn refresh_forever(self: Arc<Self>, source: impl MemberSource) {
        loop {
            let fetched = tokio::time::timeout(FETCH_TIMEOUT, source.fetch())
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out after {FETCH_TIMEOUT:?}")));
            let delay = match fetched {
                Ok(snapshot) => {
                    self.store(snapshot);
                    REFRESH_INTERVAL
                }
                Err(e) => {
                    self.metrics.member_refresh_failures.inc();
                    warn!(error = %format!("{e:#}"), "Committee member refresh failed.");
                    RETRY_INTERVAL
                }
            };
            tokio::time::sleep(delay).await;
        }
    }

    pub(crate) fn store(&self, snapshot: MemberSnapshot) {
        let mut latest = self.latest.write().expect("allowlist lock poisoned");
        if let Some(previous) = latest.as_ref() {
            // A lagging fullnode behind a load balancer can answer with older state.
            if snapshot.checkpoint_timestamp_ms < previous.checkpoint_timestamp_ms {
                warn!(
                    read_ms = snapshot.checkpoint_timestamp_ms,
                    current_ms = previous.checkpoint_timestamp_ms,
                    "Ignoring a committee member read older than the current snapshot."
                );
                return;
            }
        }
        self.metrics
            .member_allowlist_size
            .set(snapshot.members.len() as i64);
        self.metrics
            .member_snapshot_timestamp_seconds
            .set(unix_millis_to_seconds(snapshot.checkpoint_timestamp_ms) as i64);
        if latest
            .as_ref()
            .is_none_or(|previous| previous.members != snapshot.members)
        {
            info!(
                members = snapshot.members.len(),
                "Committee member allowlist changed."
            );
        }
        *latest = Some(Arc::new(snapshot));
    }
}

/// Reads the Hashi object id from the active guardian and its committees from
/// Sui.
pub struct ChainMemberSource {
    guardian: GuardianServiceClient<Channel>,
    sui: sui_rpc::Client,
    /// Read once: it can't change under a running proxy, and later refreshes
    /// then never queue on the enclave's control lock.
    hashi_object_id: OnceLock<Address>,
}

impl ChainMemberSource {
    pub fn new(guardian: Channel, sui_rpc_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            guardian: GuardianServiceClient::new(guardian),
            sui: sui_rpc::Client::new(sui_rpc_url).context("SUI_RPC_URL")?,
            hashi_object_id: OnceLock::new(),
        })
    }

    async fn hashi_object_id(&self) -> anyhow::Result<Address> {
        if let Some(id) = self.hashi_object_id.get() {
            return Ok(*id);
        }
        let raw = self
            .guardian
            .clone()
            .get_guardian_info(proto::GetGuardianInfoRequest {
                include_attestation: false,
            })
            .await
            .context("GetGuardianInfo")?
            .into_inner();
        let (info, _) = GetGuardianInfoResponse::try_from(raw)
            .map_err(|e| anyhow::anyhow!("decode GetGuardianInfo: {e:?}"))?
            .into_info_unchecked();
        let id = info
            .hashi_object_id
            .context("the guardian has no Hashi object id yet")?;
        Ok(*self.hashi_object_id.get_or_init(|| {
            info!(hashi_object_id = %id, "Following this Hashi object's committees.");
            id
        }))
    }
}

#[tonic::async_trait]
impl MemberSource for ChainMemberSource {
    async fn fetch(&self) -> anyhow::Result<MemberSnapshot> {
        read_snapshot(self.sui.clone(), self.hashi_object_id().await?).await
    }
}

/// Registered TLS keys of the members of the current committee and, during a
/// reconfig, the pending one.
pub async fn read_snapshot(
    mut sui: sui_rpc::Client,
    hashi_object_id: Address,
) -> anyhow::Result<MemberSnapshot> {
    let response = sui
        .ledger_client()
        .get_object(contents_request(&hashi_object_id))
        .await
        .with_context(|| format!("get Hashi object {hashi_object_id}"))?;
    let root_timestamp_ms = response
        .timestamp_ms()
        .context("the Hashi object read has no checkpoint timestamp")?;
    let root: move_types::Hashi = response
        .into_inner()
        .object()
        .contents()
        .deserialize()
        .context("decode the Hashi object")?;
    let committee_set = root.committees;

    let mut committee = HashSet::new();
    match get_committee(&mut sui, committee_set.committees.id, committee_set.epoch).await? {
        Some(current) => committee.extend(current.members.iter().map(|m| m.validator_address)),
        // No committee exists before the first reconfig.
        None if committee_set.epoch == 0 => {}
        None => anyhow::bail!("no committee for current epoch {}", committee_set.epoch),
    }
    // An aborted reconfig can remove the pending committee under us.
    if let Some(pending) = &committee_set.pending_epoch_change {
        if let Some(next) =
            get_committee(&mut sui, committee_set.committees.id, pending.epoch).await?
        {
            committee.extend(next.members.iter().map(|m| m.validator_address));
        }
    }

    let (members, members_timestamp_ms) =
        read_member_keys(&mut sui, committee_set.members.id, &committee).await?;
    Ok(MemberSnapshot {
        members,
        // Each read can reach a different fullnode behind a load balancer.
        checkpoint_timestamp_ms: root_timestamp_ms.min(members_timestamp_ms),
    })
}

/// The registered TLS keys of `committee`'s members, and the checkpoint time of
/// the stalest page they were read from.
async fn read_member_keys(
    sui: &mut sui_rpc::Client,
    members_bag: Address,
    committee: &HashSet<Address>,
) -> anyhow::Result<(HashSet<[u8; 32]>, u64)> {
    // The fullnode returns empty entries for a mask of `value` alone.
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().value().finish(),
    ]);
    let mut members = HashSet::new();
    let mut checkpoint_timestamp_ms = u64::MAX;
    let mut page_token = None;
    loop {
        let mut request = ListDynamicFieldsRequest::default()
            .with_parent(members_bag)
            .with_page_size(PAGE_SIZE)
            .with_read_mask(mask.clone());
        if let Some(token) = page_token.take() {
            request = request.with_page_token(token);
        }
        let response = sui
            .state_client()
            .list_dynamic_fields(request)
            .await
            .context("list committee members")?;
        checkpoint_timestamp_ms = checkpoint_timestamp_ms.min(
            response
                .timestamp_ms()
                .context("a committee member page has no checkpoint timestamp")?,
        );
        let page = response.into_inner();
        for field in &page.dynamic_fields {
            let info: move_types::MemberInfo =
                field.value().deserialize().context("decode MemberInfo")?;
            if !committee.contains(&info.validator_address) {
                continue;
            }
            if let Ok(tls_public_key) = <[u8; 32]>::try_from(info.tls_public_key.as_slice()) {
                members.insert(tls_public_key);
            }
        }
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }
    Ok((members, checkpoint_timestamp_ms))
}

async fn get_committee(
    sui: &mut sui_rpc::Client,
    committees: Address,
    epoch: u64,
) -> anyhow::Result<Option<move_types::Committee>> {
    let field_id = committees.derive_dynamic_child_id(&TypeTag::U64, &epoch.to_bcs()?);
    let field: Option<move_types::Field<u64, move_types::Committee>> =
        get_object(sui, field_id).await?;
    Ok(field.map(|field| field.value))
}

async fn get_object<T: serde::de::DeserializeOwned>(
    sui: &mut sui_rpc::Client,
    id: Address,
) -> anyhow::Result<Option<T>> {
    match sui.ledger_client().get_object(contents_request(&id)).await {
        Ok(response) => {
            let object = response
                .into_inner()
                .object()
                .contents()
                .deserialize()
                .with_context(|| format!("decode object {id}"))?;
            Ok(Some(object))
        }
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(anyhow::Error::new(status).context(format!("get object {id}"))),
    }
}

fn contents_request(id: &Address) -> GetObjectRequest {
    GetObjectRequest::new(id).with_read_mask(FieldMask::from_paths([Object::path_builder()
        .contents()
        .finish()]))
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    /// A snapshot of current chain state.
    pub(crate) fn snapshot(members: &[&ed25519_dalek::SigningKey]) -> MemberSnapshot {
        MemberSnapshot {
            members: members
                .iter()
                .map(|key| key.verifying_key().to_bytes())
                .collect(),
            checkpoint_timestamp_ms: now_timestamp_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::snapshot;
    use super::*;
    use crate::forward::test_utils::spawn_stub;
    use hashi_types::guardian::proto_conversions::get_guardian_info_response_to_pb;
    use hashi_types::guardian::GuardianInfo;
    use hashi_types::guardian::GuardianResponse;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::GuardianSigned;
    use std::collections::VecDeque;
    use std::sync::atomic::Ordering;
    use std::sync::Mutex;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateService;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateServiceServer;
    use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsResponse;

    /// Serves scripted results in order, then errors.
    #[derive(Clone, Default)]
    struct ScriptedSource {
        results: Arc<Mutex<VecDeque<anyhow::Result<MemberSnapshot>>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl ScriptedSource {
        fn new(results: Vec<anyhow::Result<MemberSnapshot>>) -> Self {
            Self {
                results: Arc::new(Mutex::new(results.into())),
                calls: Arc::default(),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    #[tonic::async_trait]
    impl MemberSource for ScriptedSource {
        async fn fetch(&self) -> anyhow::Result<MemberSnapshot> {
            *self.calls.lock().unwrap() += 1;
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(anyhow::anyhow!("sui unavailable")))
        }
    }

    /// Never answers.
    #[derive(Clone, Default)]
    struct StuckSource {
        calls: Arc<Mutex<usize>>,
    }

    #[tonic::async_trait]
    impl MemberSource for StuckSource {
        async fn fetch(&self) -> anyhow::Result<MemberSnapshot> {
            *self.calls.lock().unwrap() += 1;
            std::future::pending().await
        }
    }

    fn one_member() -> MemberSnapshot {
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        snapshot(&[&key])
    }

    /// Let the spawned refresher run up to its next sleep.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_a_failed_read_quickly() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let source = ScriptedSource::new(vec![Err(anyhow::anyhow!("down")), Ok(one_member())]);
        tokio::spawn(allowlist.clone().refresh_forever(source.clone()));

        settle().await;
        assert_eq!(source.calls(), 1);
        assert!(allowlist.current().is_none());

        tokio::time::advance(RETRY_INTERVAL).await;
        settle().await;
        assert_eq!(source.calls(), 2);
        assert_eq!(allowlist.current().unwrap().members, one_member().members);
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_read_times_out_and_is_retried() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let source = StuckSource::default();
        tokio::spawn(allowlist.clone().refresh_forever(source.clone()));
        settle().await;
        assert_eq!(*source.calls.lock().unwrap(), 1);

        tokio::time::advance(FETCH_TIMEOUT).await;
        settle().await;
        tokio::time::advance(RETRY_INTERVAL).await;
        settle().await;
        assert_eq!(*source.calls.lock().unwrap(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_the_last_snapshot_across_failed_reads() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let source = ScriptedSource::new(vec![Ok(one_member())]);
        tokio::spawn(allowlist.clone().refresh_forever(source.clone()));
        settle().await;
        let first = allowlist.current().unwrap();

        // Every later refresh fails.
        tokio::time::advance(REFRESH_INTERVAL).await;
        settle().await;
        for _ in 0..10 {
            tokio::time::advance(RETRY_INTERVAL).await;
            settle().await;
        }
        assert_eq!(source.calls(), 12);
        assert!(Arc::ptr_eq(&allowlist.current().unwrap(), &first));
    }

    #[test]
    fn ages_a_snapshot_by_the_chain_state_it_was_read_from() {
        let limit_ms = MAX_SNAPSHOT_AGE.as_millis() as u64;
        let admits_a_read_of_age = |age_ms: u64| {
            let allowlist = MemberAllowlist::new(Arc::new(ProxyMetrics::new()));
            allowlist.store(MemberSnapshot {
                checkpoint_timestamp_ms: now_timestamp_ms() - age_ms,
                ..one_member()
            });
            allowlist.current().is_some()
        };
        assert!(admits_a_read_of_age(limit_ms - 60_000));
        // A fullnode that stopped syncing answers every refresh with this.
        assert!(!admits_a_read_of_age(limit_ms + 1));
    }

    #[test]
    fn never_goes_back_to_older_chain_state() {
        let allowlist = MemberAllowlist::new(Arc::new(ProxyMetrics::new()));
        let current = one_member();
        let rotated = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let older = MemberSnapshot {
            checkpoint_timestamp_ms: current.checkpoint_timestamp_ms - 1,
            ..snapshot(&[&rotated])
        };
        let members = current.members.clone();

        allowlist.store(current);
        allowlist.store(older);
        assert_eq!(allowlist.current().unwrap().members, members);
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_refresh_replaces_the_snapshot() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let first = one_member();
        let rotated = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let next = MemberSnapshot {
            checkpoint_timestamp_ms: first.checkpoint_timestamp_ms + 1,
            ..snapshot(&[&rotated])
        };
        let first_members = first.members.clone();
        let source = ScriptedSource::new(vec![Ok(first), Ok(next)]);
        tokio::spawn(allowlist.clone().refresh_forever(source));
        settle().await;
        assert_eq!(allowlist.current().unwrap().members, first_members);

        tokio::time::advance(REFRESH_INTERVAL).await;
        settle().await;
        let current = allowlist.current().unwrap();
        assert!(current
            .members
            .contains(&rotated.verifying_key().to_bytes()));
        assert_eq!(current.members.len(), 1);
    }

    #[tokio::test]
    async fn reads_the_hashi_object_id_from_the_guardian_once() {
        let (stub, channel) = spawn_stub().await;
        let signing_key = GuardianSignKeyPair::from([1; 32]);
        let info = GuardianInfo {
            hashi_object_id: Some(Address::new([7; 32])),
            ..GuardianInfo::mock_for_testing()
        };
        *stub.info.lock().unwrap() = Some(get_guardian_info_response_to_pb(
            GetGuardianInfoResponse::new(
                None,
                signing_key.verification_key(),
                GuardianSigned::sign(GuardianResponse::new(info, 1), &signing_key),
            ),
        ));
        // Nothing listens on port 1, so every Sui read fails.
        let source = ChainMemberSource::new(channel, "http://127.0.0.1:1").unwrap();

        source.fetch().await.unwrap_err();
        source.fetch().await.unwrap_err();
        assert_eq!(stub.get_guardian_info_calls.load(Ordering::SeqCst), 1);
    }

    /// Answers each member page from a fullnode at the given checkpoint time, or
    /// without one when `None`. The pages hold no members.
    struct StampedPages(Vec<Option<u64>>);

    #[tonic::async_trait]
    impl StateService for StampedPages {
        async fn list_dynamic_fields(
            &self,
            request: tonic::Request<ListDynamicFieldsRequest>,
        ) -> Result<tonic::Response<ListDynamicFieldsResponse>, tonic::Status> {
            let index = request
                .into_inner()
                .page_token
                .map_or(0, |token| usize::from(token[0]));
            let mut page = ListDynamicFieldsResponse::default();
            if index + 1 < self.0.len() {
                page.next_page_token = Some(vec![index as u8 + 1].into());
            }
            let mut response = tonic::Response::new(page);
            if let Some(timestamp_ms) = self.0[index] {
                response.metadata_mut().insert(
                    sui_rpc::headers::X_SUI_TIMESTAMP_MS,
                    timestamp_ms.to_string().parse().unwrap(),
                );
            }
            Ok(response)
        }
    }

    async fn read_stamped_pages(pages: Vec<Option<u64>>) -> anyhow::Result<u64> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(StateServiceServer::new(StampedPages(pages)))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );
        let mut sui = sui_rpc::Client::new(format!("http://{addr}").as_str()).unwrap();
        let (members, timestamp_ms) =
            read_member_keys(&mut sui, Address::ZERO, &HashSet::new()).await?;
        assert!(members.is_empty());
        Ok(timestamp_ms)
    }

    #[tokio::test]
    async fn member_keys_are_as_old_as_their_stalest_page() {
        let pages = vec![Some(300), Some(100), Some(200)];
        assert_eq!(read_stamped_pages(pages).await.unwrap(), 100);
        read_stamped_pages(vec![Some(300), None]).await.unwrap_err();
    }
}
