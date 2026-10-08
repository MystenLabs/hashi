// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy forwards a committee handoff only once the chain stores it. The
//! outgoing committee certifies a handoff while its reconfig is still pending,
//! and a pending reconfig can abort: a guardian that took the certificate
//! early would follow a committee the chain never activated, with no way
//! back. The chain stores a handoff only when its reconfig completes
//! (`end_reconfig`), and never changes or removes one, so a stored handoff
//! stays stored however stale the read that found it.
//!
//! A handoff is matched by the epochs it leaves and reaches, which is how
//! `submit_committee_handoff` tells a completed one. That pins its committee
//! too: an epoch only ever forms one committee (it is the Sui epoch of its
//! `start_reconfig`, and an abort needs that epoch to have passed), and the
//! enclave verifies the certificate over the committee it is sent.

use std::sync::Arc;
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
use crate::node::members::get_object;
use crate::node::members::ChainSource;

/// Nodes set no deadline on a committee update, so a stalled fullnode would
/// otherwise hold the request open.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

#[tonic::async_trait]
pub trait HandoffSource: Send + Sync + 'static {
    /// The epoch activated by the handoff the chain stores out of `from_epoch`,
    /// if it stores one.
    async fn next_epoch(&self, from_epoch: u64) -> anyhow::Result<Option<u64>>;
}

pub struct HandoffGate {
    source: Box<dyn HandoffSource>,
    metrics: Arc<ProxyMetrics>,
}

impl HandoffGate {
    pub fn new(source: impl HandoffSource, metrics: Arc<ProxyMetrics>) -> Self {
        Self {
            source: Box::new(source),
            metrics,
        }
    }

    /// Admit `transitions` only if each is a handoff the chain stores and each
    /// leaves the epoch the one before it reached.
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
            // Consecutive handoffs are distinct stored ones, which bounds the
            // lookups one request can cost.
            if reached.is_some_and(|reached| reached != from_epoch) {
                return Err(Refusal::NotConsecutive);
            }
            let stored = tokio::time::timeout(LOOKUP_TIMEOUT, self.source.next_epoch(from_epoch))
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out after {LOOKUP_TIMEOUT:?}")))
                .map_err(|e| {
                    warn!(from_epoch, error = %format!("{e:#}"), "Committee handoff read failed.");
                    Refusal::ChainUnavailable
                })?;
            if stored != Some(to_epoch) {
                warn!(
                    from_epoch,
                    to_epoch,
                    ?stored,
                    "Refusing a committee handoff the chain does not store."
                );
                return Err(Refusal::NotOnChain {
                    from_epoch,
                    to_epoch,
                });
            }
            reached = Some(to_epoch);
        }
        Ok(())
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
    NotOnChain { from_epoch: u64, to_epoch: u64 },
    ChainUnavailable,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotConsecutive => "not_consecutive",
            Self::NotOnChain { .. } => "not_on_chain",
            Self::ChainUnavailable => "chain_unavailable",
        }
    }

    fn status(self) -> Status {
        match self {
            Self::Malformed => {
                Status::invalid_argument("malformed committee transition: missing an epoch")
            }
            Self::NotConsecutive => Status::invalid_argument(
                "committee transitions are not consecutive: each must leave the epoch the one \
                 before it reached",
            ),
            Self::NotOnChain {
                from_epoch,
                to_epoch,
            } => Status::failed_precondition(format!(
                "no completed handoff from epoch {from_epoch} to epoch {to_epoch} is stored on \
                 chain"
            )),
            Self::ChainUnavailable => Status::unavailable("committee handoffs unavailable; retry"),
        }
    }
}

#[tonic::async_trait]
impl HandoffSource for ChainSource {
    async fn next_epoch(&self, from_epoch: u64) -> anyhow::Result<Option<u64>> {
        read_next_epoch(self.sui.clone(), self.hashi_object_id().await?, from_epoch).await
    }
}

/// The epoch activated by the handoff out of `from_epoch`, which `end_reconfig`
/// stores in the committee set's `committees` bag.
async fn read_next_epoch(
    mut sui: sui_rpc::Client,
    hashi_object_id: Address,
    from_epoch: u64,
) -> anyhow::Result<Option<u64>> {
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

    // A Move type keeps the address of the package version that defined it,
    // and the key is defined alongside `Hashi`.
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
    Ok(field.map(|field| field.value.next_epoch))
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use std::collections::HashMap;
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
        async fn next_epoch(&self, from_epoch: u64) -> anyhow::Result<Option<u64>> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Ok(self.next_epochs.get(&from_epoch).copied())
        }
    }

    /// A gate over a chain storing `handoffs`, each as `(from_epoch, next_epoch)`.
    pub(crate) fn gate_over(handoffs: &[(u64, u64)]) -> Arc<HandoffGate> {
        Arc::new(HandoffGate::new(
            StoredHandoffs::new(handoffs),
            Arc::new(ProxyMetrics::new()),
        ))
    }

    /// A transition carrying only the epochs the gate reads.
    pub(crate) fn transition(from_epoch: u64, to_epoch: u64) -> proto::SignedCommitteeTransition {
        proto::SignedCommitteeTransition {
            data: Some(proto::CommitteeTransition {
                new_committee: Some(proto::Committee {
                    epoch: Some(to_epoch),
                    ..Default::default()
                }),
            }),
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
        async fn next_epoch(&self, _: u64) -> anyhow::Result<Option<u64>> {
            Err(anyhow::anyhow!("sui unavailable"))
        }
    }

    /// Never answers.
    struct Stuck;

    #[tonic::async_trait]
    impl HandoffSource for Stuck {
        async fn next_epoch(&self, _: u64) -> anyhow::Result<Option<u64>> {
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
        // A reconfig out of 8 is pending at most: nothing is stored for it.
        let pending = gate.admit(&[transition(8, 9)]).await.unwrap_err();
        assert_eq!(pending.code(), Code::FailedPrecondition);
        assert_eq!(refused(&metrics, "not_on_chain"), 2);
    }

    #[tokio::test]
    async fn admits_consecutive_handoffs_only_if_each_is_stored() {
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
    async fn repeating_a_stored_handoff_costs_no_more_lookups() {
        let chain = StoredHandoffs::new(&[(5, 7)]);
        let lookups = chain.lookups.clone();
        let (gate, metrics) = gate(chain);

        let repeated = gate.admit(&vec![transition(5, 7); 100]).await.unwrap_err();
        assert_eq!(repeated.code(), Code::InvalidArgument);
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        assert_eq!(refused(&metrics, "not_consecutive"), 1);
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
