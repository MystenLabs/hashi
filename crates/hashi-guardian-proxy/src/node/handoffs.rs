// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy checks committee transitions against completed Sui handoffs.
//!
//! Why it exists:
//! A compromised committee can sign a different committee for the same epoch.
//! A pending reconfiguration can also abort before Sui activates its committee.
//!
//! How it works:
//! 1. Read the completed handoff from Sui.
//! 2. Read its destination committee.
//! 3. Compare the request committee with the stored committee.
//! 4. Forward the request only when the committees match.
//!
//! Assumptions:
//! - Sui preserves completed handoffs and their destination committees.
//! - The enclave verifies the request certificate.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::time::Duration;

use anyhow::Context as _;
use hashi_types::move_types;
use hashi_types::proto;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::bcs::ToBcs;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use tonic::Status;
use tracing::warn;

use crate::metrics::ProxyMetrics;
use crate::node::members::get_committee;
use crate::node::members::get_object;
use crate::node::members::ChainSource;

/// Nodes set no deadline on a committee update, so a stalled fullnode would
/// otherwise hold the request open.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

#[tonic::async_trait]
pub trait HandoffSource: Send + Sync + 'static {
    /// Read the completed handoff and its destination committee.
    async fn handoff(&self, from_epoch: u64) -> anyhow::Result<Option<move_types::Committee>>;
}

pub struct HandoffGate {
    source: Box<dyn HandoffSource>,
    /// Map each source epoch to its completed destination committee.
    stored: Mutex<HashMap<u64, Arc<move_types::Committee>>>,
    metrics: Arc<ProxyMetrics>,
}

impl HandoffGate {
    pub fn new(source: impl HandoffSource, metrics: Arc<ProxyMetrics>) -> Self {
        Self {
            source: Box::new(source),
            stored: Mutex::default(),
            metrics,
        }
    }

    /// Require equal committees and consecutive completed handoffs.
    pub async fn admit(
        &self,
        transitions: &[proto::SignedCommitteeTransition],
    ) -> Result<(), Status> {
        self.check(transitions).await.map_err(|refusal| {
            self.metrics
                .handoff_refused
                .with_label_values(&[refusal.reason()])
                .inc();
            refusal.status()
        })
    }

    async fn check(&self, transitions: &[proto::SignedCommitteeTransition]) -> Result<(), Refusal> {
        let mut reached = None;
        for transition in transitions {
            let (from_epoch, to_epoch) = epochs(transition).ok_or(Refusal::Malformed)?;
            // A handoff reaches a later epoch, so consecutive ones are distinct
            // stored ones, which bounds how many a request can send the enclave.
            if reached.is_some_and(|reached| reached != from_epoch) {
                return Err(Refusal::NotConsecutive);
            }
            let Some(stored) = self.stored_committee(from_epoch).await? else {
                return Err(Refusal::NotOnChain {
                    from_epoch,
                    to_epoch,
                });
            };
            if stored.epoch != to_epoch {
                warn!(
                    from_epoch,
                    to_epoch,
                    stored = stored.epoch,
                    "Refusing a committee handoff the chain does not store."
                );
                return Err(Refusal::Superseded {
                    from_epoch,
                    to_epoch,
                    stored: stored.epoch,
                });
            }
            let committee = transition
                .data
                .as_ref()
                .and_then(|data| data.new_committee.as_ref())
                .cloned()
                .ok_or(Refusal::Malformed)?;
            let committee =
                move_types::Committee::try_from(committee).map_err(|_| Refusal::Malformed)?;
            if committee != *stored {
                warn!(
                    from_epoch,
                    to_epoch, "Refusing a committee that differs from Sui."
                );
                return Err(Refusal::CommitteeMismatch);
            }
            reached = Some(to_epoch);
        }
        Ok(())
    }

    /// Stored handoffs are remembered, so replaying the chain's history costs no
    /// reads, and each request at most one lookup that finds nothing.
    async fn stored_committee(
        &self,
        from_epoch: u64,
    ) -> Result<Option<Arc<move_types::Committee>>, Refusal> {
        let known = self.stored().get(&from_epoch).cloned();
        if known.is_some() {
            return Ok(known);
        }
        let read = tokio::time::timeout(LOOKUP_TIMEOUT, self.source.handoff(from_epoch))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out after {LOOKUP_TIMEOUT:?}")))
            .map_err(|e| {
                warn!(from_epoch, error = %format!("{e:#}"), "Committee handoff read failed.");
                Refusal::ChainUnavailable
            })?;
        let read = read.map(Arc::new);
        if let Some(handoff) = &read {
            self.stored().insert(from_epoch, handoff.clone());
        }
        Ok(read)
    }

    fn stored(&self) -> MutexGuard<'_, HashMap<u64, Arc<move_types::Committee>>> {
        self.stored.lock().expect("stored handoffs mutex poisoned")
    }
}

/// The epochs a handoff leaves and reaches: the one its certificate was signed
/// in and its new committee's. The enclave applies it by the same two fields.
fn epochs(transition: &proto::SignedCommitteeTransition) -> Option<(u64, u64)> {
    let from_epoch = transition.committee_signature.as_ref()?.epoch?;
    let to_epoch = transition.data.as_ref()?.new_committee.as_ref()?.epoch?;
    Some((from_epoch, to_epoch))
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    Malformed,
    NotConsecutive,
    /// Nothing is stored out of this epoch yet: its reconfig is pending, or
    /// the read is stale.
    NotOnChain {
        from_epoch: u64,
        to_epoch: u64,
    },
    /// Another handoff is stored out of this epoch, so this one's reconfig
    /// aborted. No stale read can show that.
    Superseded {
        from_epoch: u64,
        to_epoch: u64,
        stored: u64,
    },
    CommitteeMismatch,
    ChainUnavailable,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotConsecutive => "not_consecutive",
            Self::NotOnChain { .. } => "not_on_chain",
            Self::Superseded { .. } => "superseded",
            Self::CommitteeMismatch => "committee_mismatch",
            Self::ChainUnavailable => "chain_unavailable",
        }
    }

    fn status(self) -> Status {
        match self {
            Self::Malformed => Status::invalid_argument("malformed committee transition"),
            Self::NotConsecutive => Status::invalid_argument(
                "committee transitions are not consecutive: each must leave the epoch the one \
                 before it reached",
            ),
            Self::NotOnChain {
                from_epoch,
                to_epoch,
            } => Status::unavailable(format!(
                "no handoff from epoch {from_epoch} to epoch {to_epoch} is stored on chain yet; \
                 retry"
            )),
            Self::Superseded {
                from_epoch,
                to_epoch,
                stored,
            } => Status::failed_precondition(format!(
                "the chain stores a handoff from epoch {from_epoch} to epoch {stored}, not to \
                 epoch {to_epoch}"
            )),
            Self::CommitteeMismatch => Status::failed_precondition(
                "request committee differs from the completed Sui handoff's committee",
            ),
            Self::ChainUnavailable => Status::unavailable("committee handoffs unavailable; retry"),
        }
    }
}

#[tonic::async_trait]
impl HandoffSource for ChainSource {
    async fn handoff(&self, from_epoch: u64) -> anyhow::Result<Option<move_types::Committee>> {
        read_handoff(self.sui.clone(), self.hashi_object_id().await?, from_epoch).await
    }
}

/// Read a completed handoff and its destination committee from Sui.
async fn read_handoff(
    mut sui: sui_rpc::Client,
    hashi_object_id: Address,
    from_epoch: u64,
) -> anyhow::Result<Option<move_types::Committee>> {
    let response = sui
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&hashi_object_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().object_type(),
                Object::path_builder().contents().finish(),
            ])),
        )
        .await
        .with_context(|| format!("get Hashi object {hashi_object_id}"))?
        .into_inner();
    let object = response.object();
    let hashi_type: StructTag = object
        .object_type_opt()
        .context("the Hashi object read has no type")?
        .parse()
        .context("parse the Hashi object's type")?;
    let root: move_types::Hashi = object
        .contents()
        .deserialize()
        .context("decode the Hashi object")?;

    // The key's address is the `Hashi` type's only because both are defined in
    // the original package: a type added by an upgrade keeps that upgrade's.
    let key_type = TypeTag::Struct(Box::new(StructTag::new(
        *hashi_type.address(),
        Identifier::from_static("committee_set"),
        Identifier::from_static("CommitteeHandoffKey"),
        vec![],
    )));
    let key = move_types::CommitteeHandoffKey { epoch: from_epoch };
    let field_id = root
        .committees
        .committees
        .id
        .derive_dynamic_child_id(&key_type, &key.to_bcs()?);
    let field: Option<
        move_types::Field<move_types::CommitteeHandoffKey, move_types::CommitteeHandoff>,
    > = get_object(&mut sui, field_id).await?;
    let Some(field) = field else {
        return Ok(None);
    };
    let next_epoch = field.value.next_epoch;
    let committee = get_committee(&mut sui, root.committees.committees.id, next_epoch)
        .await?
        .with_context(|| format!("no committee for completed handoff to epoch {next_epoch}"))?;
    Ok(Some(committee))
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    /// A chain storing these handoffs, by the epoch each leaves.
    pub(super) struct StoredHandoffs {
        next_epochs: HashMap<u64, u64>,
        pub(super) lookups: Arc<AtomicUsize>,
    }

    impl StoredHandoffs {
        pub(super) fn new(handoffs: &[(u64, u64)]) -> Self {
            Self {
                next_epochs: handoffs.iter().copied().collect(),
                lookups: Arc::default(),
            }
        }
    }

    #[tonic::async_trait]
    impl HandoffSource for StoredHandoffs {
        async fn handoff(&self, from_epoch: u64) -> anyhow::Result<Option<move_types::Committee>> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .next_epochs
                .get(&from_epoch)
                .map(|&next_epoch| committee(next_epoch)))
        }
    }

    /// A gate over a chain storing `handoffs`, each as `(from_epoch, next_epoch)`.
    pub(crate) fn gate_over(handoffs: &[(u64, u64)]) -> Arc<HandoffGate> {
        Arc::new(HandoffGate::new(
            StoredHandoffs::new(handoffs),
            Arc::new(ProxyMetrics::new()),
        ))
    }

    /// Make a committee with deterministic wire fields.
    pub(crate) fn committee(epoch: u64) -> move_types::Committee {
        move_types::Committee {
            epoch,
            members: vec![move_types::CommitteeMember {
                validator_address: Address::ZERO,
                public_key: vec![1; 96],
                encryption_public_key: vec![2; 32],
                weight: 1,
                extra_fields: move_types::Config::default(),
            }],
            total_weight: 1,
            config: move_types::Config::default(),
        }
    }

    /// Make a transition with the deterministic committee.
    pub(crate) fn transition(from_epoch: u64, to_epoch: u64) -> proto::SignedCommitteeTransition {
        proto::SignedCommitteeTransition {
            data: Some(
                hashi_types::guardian::proto_conversions::committee_transition_to_pb(
                    &hashi_types::guardian::CommitteeTransitionRequest {
                        new_committee: committee(to_epoch),
                    },
                ),
            ),
            committee_signature: Some(proto::CommitteeSignature {
                epoch: Some(from_epoch),
                ..Default::default()
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::transition;
    use super::test_utils::StoredHandoffs;
    use super::*;
    use std::sync::atomic::Ordering;
    use tonic::Code;

    /// Every read fails.
    struct Unreadable;

    #[tonic::async_trait]
    impl HandoffSource for Unreadable {
        async fn handoff(&self, _: u64) -> anyhow::Result<Option<move_types::Committee>> {
            Err(anyhow::anyhow!("sui unavailable"))
        }
    }

    /// Never answers.
    struct Stuck;

    #[tonic::async_trait]
    impl HandoffSource for Stuck {
        async fn handoff(&self, _: u64) -> anyhow::Result<Option<move_types::Committee>> {
            std::future::pending().await
        }
    }

    fn gate(source: impl HandoffSource) -> (HandoffGate, Arc<ProxyMetrics>) {
        let metrics = Arc::new(ProxyMetrics::new());
        (HandoffGate::new(source, metrics.clone()), metrics)
    }

    fn refused(metrics: &ProxyMetrics, reason: &str) -> u64 {
        metrics.handoff_refused.with_label_values(&[reason]).get()
    }

    #[tokio::test]
    async fn admits_only_the_handoff_the_chain_stores() {
        // Epoch 7 formed out of 5 and aborted; 8 replaced it and activated.
        let (gate, metrics) = gate(StoredHandoffs::new(&[(5, 8)]));
        gate.admit(&[transition(5, 8)]).await.unwrap();

        let aborted = gate.admit(&[transition(5, 7)]).await.unwrap_err();
        assert_eq!(aborted.code(), Code::FailedPrecondition);
        assert_eq!(refused(&metrics, "superseded"), 1);
        // A reconfig out of 8 is pending at most: nothing is stored for it.
        let pending = gate.admit(&[transition(8, 9)]).await.unwrap_err();
        assert_eq!(pending.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "not_on_chain"), 1);
    }

    #[tokio::test]
    async fn admits_a_chain_only_if_each_handoff_is_stored() {
        let (gate, _) = gate(StoredHandoffs::new(&[(5, 7), (7, 9)]));
        gate.admit(&[]).await.unwrap();
        gate.admit(&[transition(5, 7), transition(7, 9)])
            .await
            .unwrap();

        let unstored = gate
            .admit(&[transition(5, 7), transition(7, 10)])
            .await
            .unwrap_err();
        assert_eq!(unstored.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn refuses_a_chain_that_is_not_consecutive() {
        let (gate, metrics) = gate(StoredHandoffs::new(&[(5, 7), (7, 9)]));

        // Every handoff here is stored, but none follows the one before it.
        let repeated = vec![transition(5, 7); 100];
        let reordered = vec![transition(7, 9), transition(5, 7)];
        for chain in [repeated, reordered] {
            let err = gate.admit(&chain).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        assert_eq!(refused(&metrics, "not_consecutive"), 2);
    }

    #[tokio::test]
    async fn reads_a_stored_committee_once() {
        let chain = StoredHandoffs::new(&[(5, 7)]);
        let lookups = chain.lookups.clone();
        let (gate, _) = gate(chain);

        gate.admit(&[transition(5, 7)]).await.unwrap();
        gate.admit(&[transition(5, 7)]).await.unwrap();
        gate.admit(&[transition(5, 8)]).await.unwrap_err();
        assert_eq!(lookups.load(Ordering::SeqCst), 1);

        // One the chain may yet store is read again each time.
        gate.admit(&[transition(7, 9)]).await.unwrap_err();
        gate.admit(&[transition(7, 9)]).await.unwrap_err();
        assert_eq!(lookups.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn refuses_changed_committee_fields_before_and_after_caching() {
        use hashi_types::guardian::proto_conversions::committee_transition_to_pb;
        use hashi_types::guardian::CommitteeTransitionRequest;
        use move_types::Config;
        use move_types::ConfigValue;

        let original = test_utils::committee(7);
        let mut changed = Vec::new();
        let mut committee = original.clone();
        committee.total_weight += 1;
        changed.push(committee);
        let mut committee = original.clone();
        committee.config = Config::from_entries(vec![("test".into(), ConfigValue::U64(1))]);
        changed.push(committee);
        let mut committee = original.clone();
        committee.members[0].validator_address = Address::new([1; 32]);
        changed.push(committee);
        let mut committee = original.clone();
        committee.members[0].public_key[0] ^= 1;
        changed.push(committee);
        let mut committee = original.clone();
        committee.members[0].encryption_public_key[0] ^= 1;
        changed.push(committee);
        let mut committee = original.clone();
        committee.members[0].weight += 1;
        changed.push(committee);
        let mut committee = original.clone();
        committee.members[0].extra_fields =
            Config::from_entries(vec![("test".into(), ConfigValue::U64(1))]);
        changed.push(committee);
        let mut committee = original.clone();
        committee.members.clear();
        changed.push(committee);

        for committee in changed {
            let chain = StoredHandoffs::new(&[(5, 7)]);
            let lookups = chain.lookups.clone();
            let (gate, metrics) = gate(chain);
            let mut request = transition(5, 7);
            request.data = Some(committee_transition_to_pb(&CommitteeTransitionRequest {
                new_committee: committee,
            }));
            for _ in 0..2 {
                let err = gate
                    .admit(std::slice::from_ref(&request))
                    .await
                    .unwrap_err();
                assert_eq!(err.code(), Code::FailedPrecondition);
            }
            assert_eq!(refused(&metrics, "committee_mismatch"), 2);
            assert_eq!(lookups.load(Ordering::SeqCst), 1);
            gate.admit(&[transition(5, 7)]).await.unwrap();
        }
    }

    #[tokio::test]
    async fn refuses_malformed_committee_bytes() {
        let (gate, metrics) = gate(StoredHandoffs::new(&[(5, 7)]));
        let mut missing_config = transition(5, 7);
        missing_config
            .data
            .as_mut()
            .unwrap()
            .new_committee
            .as_mut()
            .unwrap()
            .config = None;
        let mut invalid_config = transition(5, 7);
        invalid_config
            .data
            .as_mut()
            .unwrap()
            .new_committee
            .as_mut()
            .unwrap()
            .config = Some(vec![255].into());
        let mut missing_member_weight = transition(5, 7);
        missing_member_weight
            .data
            .as_mut()
            .unwrap()
            .new_committee
            .as_mut()
            .unwrap()
            .members[0]
            .weight = None;
        for request in [missing_config, invalid_config, missing_member_weight] {
            let err = gate.admit(&[request]).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        assert_eq!(refused(&metrics, "malformed"), 3);
    }

    #[tokio::test]
    async fn refuses_a_transition_missing_an_epoch_without_a_lookup() {
        let chain = StoredHandoffs::new(&[(5, 7)]);
        let lookups = chain.lookups.clone();
        let (gate, metrics) = gate(chain);

        let mut unsigned = transition(5, 7);
        unsigned.committee_signature = None;
        let mut no_signing_epoch = transition(5, 7);
        no_signing_epoch.committee_signature = Some(Default::default());
        let mut no_data = transition(5, 7);
        no_data.data = None;
        let mut no_committee = transition(5, 7);
        no_committee.data = Some(Default::default());
        let mut no_committee_epoch = transition(5, 7);
        no_committee_epoch.data = Some(proto::CommitteeTransition {
            new_committee: Some(Default::default()),
        });
        for malformed in [
            unsigned,
            no_signing_epoch,
            no_data,
            no_committee,
            no_committee_epoch,
        ] {
            let err = gate.admit(&[malformed]).await.unwrap_err();
            assert_eq!(err.code(), Code::InvalidArgument);
        }
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
        assert_eq!(refused(&metrics, "malformed"), 5);
    }

    #[tokio::test(start_paused = true)]
    async fn fails_closed_when_the_chain_cannot_be_read() {
        let (unreadable, metrics) = gate(Unreadable);
        let err = unreadable.admit(&[transition(5, 7)]).await.unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "chain_unavailable"), 1);

        let (stuck, metrics) = gate(Stuck);
        let err = stuck.admit(&[transition(5, 7)]).await.unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "chain_unavailable"), 1);
    }
}
