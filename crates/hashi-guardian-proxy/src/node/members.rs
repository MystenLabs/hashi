// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The registered TLS keys of the current and pending committee's members,
//! re-read from chain in the background. The member gate
//! ([`crate::node::member_auth`]) only reads the latest snapshot, so no request, and
//! no unknown key, ever waits on or triggers a Sui read.

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;

use anyhow::Context as _;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GetGuardianInfoResponse;
use hashi_types::move_types;
use hashi_types::proto;
use hashi_types::proto::guardian_service_client::GuardianServiceClient;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::bcs::ToBcs;
use sui_sdk_types::Address;
use sui_sdk_types::TypeTag;
use tokio::time::Instant;
use tonic::transport::Channel;
use tracing::info;
use tracing::warn;

use crate::metrics::ProxyMetrics;

const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const FIRST_SNAPSHOT_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// Past this age a snapshot admits no one, so a long Sui RPC outage fails
/// closed instead of trusting a committee that may have changed.
const MAX_SNAPSHOT_AGE: Duration = Duration::from_secs(10 * 60);
const SUI_RPC_TIMEOUT: Duration = Duration::from_secs(30);
const PAGE_SIZE: u32 = 1000;

#[derive(Debug, PartialEq)]
pub struct MemberSnapshot {
    /// The deployment the guardian serves; member tokens are bound to it.
    pub hashi_object_id: Address,
    /// Registered TLS public key to validator address.
    pub members: HashMap<[u8; 32], Address>,
}

#[tonic::async_trait]
pub trait MemberSource: Send + Sync + 'static {
    async fn fetch(&self) -> anyhow::Result<MemberSnapshot>;
}

pub struct MemberAllowlist {
    latest: RwLock<Option<(Instant, Arc<MemberSnapshot>)>>,
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
        self.latest
            .read()
            .expect("allowlist lock poisoned")
            .as_ref()
            .filter(|(at, _)| at.elapsed() <= MAX_SNAPSHOT_AGE)
            .map(|(_, snapshot)| snapshot.clone())
    }

    /// Refresh from `source` forever. A failed read keeps the last snapshot
    /// until it ages out.
    pub async fn refresh_forever(self: Arc<Self>, source: impl MemberSource) {
        loop {
            let delay = match source.fetch().await {
                Ok(snapshot) => {
                    self.store(snapshot);
                    REFRESH_INTERVAL
                }
                Err(e) => {
                    self.metrics.member_refresh_failures.inc();
                    warn!(error = %format!("{e:#}"), "Committee member refresh failed.");
                    if self
                        .latest
                        .read()
                        .expect("allowlist lock poisoned")
                        .is_some()
                    {
                        REFRESH_INTERVAL
                    } else {
                        FIRST_SNAPSHOT_RETRY_INTERVAL
                    }
                }
            };
            tokio::time::sleep(delay).await;
        }
    }

    pub(crate) fn store(&self, snapshot: MemberSnapshot) {
        self.metrics
            .member_allowlist_size
            .set(snapshot.members.len() as i64);
        self.metrics
            .member_snapshot_timestamp_seconds
            .set(now_timestamp_secs() as i64);
        let mut latest = self.latest.write().expect("allowlist lock poisoned");
        if latest
            .as_ref()
            .is_none_or(|(_, previous)| **previous != snapshot)
        {
            info!(
                hashi_object_id = %snapshot.hashi_object_id,
                members = snapshot.members.len(),
                "Committee member allowlist changed."
            );
        }
        *latest = Some((Instant::now(), Arc::new(snapshot)));
    }
}

/// Reads the Hashi object id from the active guardian and its committees from
/// Sui.
pub struct ChainMemberSource {
    guardian: GuardianServiceClient<Channel>,
    sui: sui_rpc::Client,
}

impl ChainMemberSource {
    pub fn new(guardian: Channel, sui_rpc_url: &str) -> anyhow::Result<Self> {
        let sui = sui_rpc::Client::new(sui_rpc_url)
            .context("SUI_RPC_URL")?
            .request_layer(tower::timeout::TimeoutLayer::new(SUI_RPC_TIMEOUT));
        Ok(Self {
            guardian: GuardianServiceClient::new(guardian),
            sui,
        })
    }
}

#[tonic::async_trait]
impl MemberSource for ChainMemberSource {
    async fn fetch(&self) -> anyhow::Result<MemberSnapshot> {
        let raw = self
            .guardian
            .clone()
            .get_guardian_info(proto::GetGuardianInfoRequest {})
            .await
            .context("GetGuardianInfo")?
            .into_inner();
        let (info, _) = GetGuardianInfoResponse::try_from(raw)
            .map_err(|e| anyhow::anyhow!("decode GetGuardianInfo: {e:?}"))?
            .into_info_unchecked();
        let hashi_object_id = info
            .hashi_object_id
            .context("the guardian has no Hashi object id yet")?;
        let members = committee_member_keys(self.sui.clone(), hashi_object_id).await?;
        Ok(MemberSnapshot {
            hashi_object_id,
            members,
        })
    }
}

/// Registered TLS keys of the members of the current committee and, during a
/// reconfig, the pending one.
pub async fn committee_member_keys(
    mut sui: sui_rpc::Client,
    hashi_object_id: Address,
) -> anyhow::Result<HashMap<[u8; 32], Address>> {
    let root: move_types::Hashi = get_object(&mut sui, hashi_object_id)
        .await?
        .with_context(|| format!("Hashi object {hashi_object_id} not found"))?;
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

    // The fullnode returns empty entries for a mask of `value` alone.
    let mask = FieldMask::from_paths([
        DynamicField::path_builder().name().finish(),
        DynamicField::path_builder().value().finish(),
    ]);
    let mut members = HashMap::new();
    let mut page_token = None;
    loop {
        let mut request = ListDynamicFieldsRequest::default()
            .with_parent(committee_set.members.id)
            .with_page_size(PAGE_SIZE)
            .with_read_mask(mask.clone());
        if let Some(token) = page_token.take() {
            request = request.with_page_token(token);
        }
        let page = sui
            .state_client()
            .list_dynamic_fields(request)
            .await
            .context("list committee members")?
            .into_inner();
        for field in &page.dynamic_fields {
            let info: move_types::MemberInfo =
                field.value().deserialize().context("decode MemberInfo")?;
            if !committee.contains(&info.validator_address) {
                continue;
            }
            if let Ok(tls_public_key) = <[u8; 32]>::try_from(info.tls_public_key.as_slice()) {
                members.insert(tls_public_key, info.validator_address);
            }
        }
        match page.next_page_token {
            Some(token) => page_token = Some(token),
            None => break,
        }
    }
    Ok(members)
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
    let request =
        GetObjectRequest::new(&id).with_read_mask(FieldMask::from_paths([Object::path_builder()
            .contents()
            .finish()]));
    match sui.ledger_client().get_object(request).await {
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

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;

    pub(crate) fn snapshot(
        hashi_object_id: Address,
        members: &[(&ed25519_dalek::SigningKey, Address)],
    ) -> MemberSnapshot {
        MemberSnapshot {
            hashi_object_id,
            members: members
                .iter()
                .map(|(key, address)| (key.verifying_key().to_bytes(), *address))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::snapshot;
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

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

    fn one_member() -> MemberSnapshot {
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        snapshot(Address::new([7; 32]), &[(&key, Address::new([2; 32]))])
    }

    /// Let the spawned refresher run up to its next sleep.
    async fn settle() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_quickly_until_the_first_snapshot() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let source = ScriptedSource::new(vec![Err(anyhow::anyhow!("down")), Ok(one_member())]);
        tokio::spawn(allowlist.clone().refresh_forever(source.clone()));

        settle().await;
        assert_eq!(source.calls(), 1);
        assert!(allowlist.current().is_none());

        tokio::time::advance(FIRST_SNAPSHOT_RETRY_INTERVAL).await;
        settle().await;
        assert_eq!(source.calls(), 2);
        assert_eq!(*allowlist.current().unwrap(), one_member());
    }

    #[tokio::test(start_paused = true)]
    async fn keeps_the_last_snapshot_until_it_ages_out() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let source = ScriptedSource::new(vec![Ok(one_member())]);
        tokio::spawn(allowlist.clone().refresh_forever(source.clone()));
        settle().await;
        assert!(allowlist.current().is_some());

        // Every later refresh fails; the snapshot keeps admitting until it is
        // older than the limit, and never after.
        let failed_refreshes = MAX_SNAPSHOT_AGE.as_secs() / REFRESH_INTERVAL.as_secs();
        for _ in 0..failed_refreshes {
            tokio::time::advance(REFRESH_INTERVAL).await;
            settle().await;
            assert_eq!(*allowlist.current().unwrap(), one_member());
        }
        assert_eq!(source.calls() as u64, 1 + failed_refreshes);

        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(allowlist.current().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_refresh_replaces_the_snapshot() {
        let allowlist = Arc::new(MemberAllowlist::new(Arc::new(ProxyMetrics::new())));
        let rotated = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let next = snapshot(Address::new([7; 32]), &[(&rotated, Address::new([2; 32]))]);
        let source = ScriptedSource::new(vec![Ok(one_member()), Ok(next)]);
        tokio::spawn(allowlist.clone().refresh_forever(source));
        settle().await;
        assert_eq!(*allowlist.current().unwrap(), one_member());

        tokio::time::advance(REFRESH_INTERVAL).await;
        settle().await;
        let current = allowlist.current().unwrap();
        assert!(current
            .members
            .contains_key(&rotated.verifying_key().to_bytes()));
        assert_eq!(current.members.len(), 1);
    }
}
