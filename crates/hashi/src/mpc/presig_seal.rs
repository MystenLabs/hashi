// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use fastcrypto::traits::ToFromBytes;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use hashi_types::committee::BLS12381Signature;
use hashi_types::committee::RuntimeCommittee;
use hashi_types::committee::certificate_threshold;
use hashi_types::move_types::PresigDealerSetMessage;
use hashi_types::move_types::PresigSealV1;
use sui_sdk_types::Address;
use tokio::time::Instant;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::Hashi;
use crate::sui_tx_executor::SubmitCertError;

const RPC_TIMEOUT: Duration = Duration::from_secs(5);
const SUBMIT_STAGGER: Duration = Duration::from_secs(5);
const SEAL_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(90);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const OVERDUE_LIMIT: Duration = Duration::from_secs(30);

type SealKey = (u64, u32);

#[derive(Default)]
pub(crate) struct PendingSeals {
    entries: BTreeMap<SealKey, PendingSeal>,
}

struct PendingSeal {
    message: PresigDealerSetMessage,
    signatures: BTreeMap<Address, BLS12381Signature>,
    next_attempt: Option<Instant>,
    backoff: Duration,
    done: bool,
}

struct DueSeal {
    message: PresigDealerSetMessage,
    signatures: Vec<(Address, BLS12381Signature)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    Failed,
    FailedInFlight,
}

impl PendingSeals {
    fn insert_if_absent(
        &mut self,
        message: PresigDealerSetMessage,
        signer: Address,
        signature: BLS12381Signature,
    ) {
        self.entries
            .entry((message.epoch, message.batch_index))
            .or_insert_with(|| PendingSeal {
                message,
                signatures: BTreeMap::from([(signer, signature)]),
                next_attempt: None,
                backoff: INITIAL_BACKOFF,
                done: false,
            });
    }

    fn prune(&mut self, epoch: u64) {
        self.entries
            .retain(|(entry_epoch, _), _| *entry_epoch >= epoch);
    }

    fn has_due(&self, epoch: u64, now: Instant) -> bool {
        self.entries
            .range((epoch, 0)..=(epoch, u32::MAX))
            .any(|(_, seal)| {
                !seal.done
                    && seal
                        .next_attempt
                        .is_none_or(|next_attempt| next_attempt <= now)
            })
    }

    fn select_due(
        &mut self,
        epoch: u64,
        now: Instant,
        chain_seals: &BTreeMap<u32, PresigSealV1>,
        stagger: impl Fn(u32) -> Duration,
    ) -> Option<DueSeal> {
        let mut due: Option<(Instant, SealKey)> = None;
        for (&key, seal) in self.entries.range_mut((epoch, 0)..=(epoch, u32::MAX)) {
            if seal.done {
                continue;
            }
            if let Some(chain_seal) = chain_seals.get(&key.1) {
                warn_if_other_digest(&seal.message, chain_seal);
                seal.done = true;
                seal.signatures.clear();
                continue;
            }
            if seal
                .next_attempt
                .is_some_and(|next_attempt| now > next_attempt + OVERDUE_LIMIT)
            {
                seal.next_attempt = None;
                seal.backoff = INITIAL_BACKOFF;
            }
            let next_attempt = *seal
                .next_attempt
                .get_or_insert_with(|| now + stagger(key.1));
            if next_attempt <= now && due.is_none_or(|(earliest, _)| next_attempt < earliest) {
                due = Some((next_attempt, key));
            }
        }
        let (_, key) = due?;
        let seal = &self.entries[&key];
        Some(DueSeal {
            message: seal.message.clone(),
            signatures: seal
                .signatures
                .iter()
                .map(|(signer, signature)| (*signer, signature.clone()))
                .collect(),
        })
    }

    fn add_signatures(&mut self, key: SealKey, signatures: Vec<(Address, BLS12381Signature)>) {
        if let Some(seal) = self.entries.get_mut(&key) {
            seal.signatures.extend(signatures);
        }
    }

    fn finish(&mut self, key: SealKey, outcome: Outcome, now: Instant, stagger: Duration) {
        let Some(seal) = self.entries.get_mut(&key) else {
            return;
        };
        match outcome {
            Outcome::Done => {
                seal.done = true;
                seal.signatures.clear();
            }
            Outcome::Failed => {
                seal.next_attempt = Some(now + seal.backoff + stagger);
                seal.backoff = (seal.backoff * 2).min(MAX_BACKOFF);
            }
            Outcome::FailedInFlight => {
                seal.backoff = MAX_BACKOFF;
                seal.next_attempt = Some(now + MAX_BACKOFF + stagger);
            }
        }
    }
}

pub(crate) fn record(
    inner: &Hashi,
    pending: &Mutex<PendingSeals>,
    epoch: u64,
    batch_index: u32,
    dealer_set_digest: [u8; 32],
) {
    let message = PresigDealerSetMessage {
        epoch,
        batch_index,
        dealer_set_digest: dealer_set_digest.to_vec(),
    };
    let (signer, signature) = match sign(inner, &message) {
        Ok(signed) => signed,
        Err(e) => {
            warn!("Cannot sign PresigDealerSet for epoch {epoch} batch {batch_index}: {e:#}");
            return;
        }
    };
    inner.store_presig_dealer_set_signature_if_absent(
        epoch,
        batch_index,
        signature.as_bytes().to_vec(),
    );
    pending
        .lock()
        .unwrap()
        .insert_if_absent(message, signer, signature);
}

fn sign(
    inner: &Hashi,
    message: &PresigDealerSetMessage,
) -> anyhow::Result<(Address, BLS12381Signature)> {
    let committee = inner.committee_for_epoch(message.epoch)?;
    let my_address = inner.config.validator_address()?;
    let key = inner.find_signing_key_for_committee(&committee, my_address, message.epoch)?;
    let signature = key
        .sign(
            inner.config.hashi_ids().hashi_object_id,
            message.epoch,
            my_address,
            message,
        )
        .signature()
        .clone();
    Ok((my_address, signature))
}

pub(crate) async fn seal_due(inner: &Arc<Hashi>, pending: &Mutex<PendingSeals>) {
    let onchain_state = inner.onchain_state();
    let epoch = onchain_state.epoch();
    let now = Instant::now();
    {
        let mut seals = pending.lock().unwrap();
        seals.prune(epoch);
        if !seals.has_due(epoch, now) {
            return;
        }
    }
    let (committee, my_address) = match inner
        .committee_for_epoch(epoch)
        .and_then(|committee| Ok((committee, inner.config.validator_address()?)))
    {
        Ok(found) => found,
        Err(e) => {
            debug!("Cannot seal presig batches of epoch {epoch}: {e:#}");
            return;
        }
    };
    let stagger = |batch_index| submit_delay(&committee, my_address, epoch, batch_index);
    let chain_seals = onchain_state.presig_seals(epoch);
    let due = pending
        .lock()
        .unwrap()
        .select_due(epoch, now, &chain_seals, stagger);
    let Some(due) = due else {
        return;
    };
    let batch_index = due.message.batch_index;
    let outcome = tokio::time::timeout(
        SEAL_ATTEMPT_TIMEOUT,
        attempt(inner, pending, &committee, my_address, due),
    )
    .await
    .unwrap_or_else(|_| {
        warn!(
            "Sealing presig batch {batch_index} of epoch {epoch} was cut after \
             {SEAL_ATTEMPT_TIMEOUT:?}"
        );
        Outcome::FailedInFlight
    });
    pending.lock().unwrap().finish(
        (epoch, batch_index),
        outcome,
        Instant::now(),
        stagger(batch_index),
    );
}

async fn attempt(
    inner: &Arc<Hashi>,
    pending: &Mutex<PendingSeals>,
    committee: &RuntimeCommittee,
    my_address: Address,
    due: DueSeal,
) -> Outcome {
    let message = &due.message;
    let (epoch, batch_index) = (message.epoch, message.batch_index);
    let mut aggregator =
        committee.signature_aggregator(inner.config.hashi_ids().hashi_object_id, message.clone());
    let mut collected = HashSet::new();
    for (signer, signature) in due.signatures {
        match aggregator.add_signature_from(signer, signature) {
            Ok(()) => {
                collected.insert(signer);
            }
            Err(e) => warn!(
                "Kept PresigDealerSet signature from {signer} for epoch {epoch} batch \
                 {batch_index} was not accepted: {e}"
            ),
        }
    }
    let required = certificate_threshold(committee.total_weight());
    if aggregator.weight() < required {
        let mut requests: FuturesUnordered<_> = committee
            .members()
            .iter()
            .map(|member| member.validator_address())
            .filter(|address| *address != my_address && !collected.contains(address))
            .map(|address| async move {
                (
                    address,
                    request_signature(inner, address, epoch, batch_index).await,
                )
            })
            .collect();
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        while aggregator.weight() < required
            && let Some((address, response)) = requests.next().await
        {
            let Some(bytes) = response else {
                continue;
            };
            let added = BLS12381Signature::from_bytes(&bytes)
                .map_err(|e| e.to_string())
                .and_then(|signature| {
                    aggregator
                        .add_signature_from(address, signature.clone())
                        .map(|()| signature)
                        .map_err(|e| e.to_string())
                });
            match added {
                Ok(signature) => accepted.push((address, signature)),
                Err(reason) => rejected.push((address, reason)),
            }
        }
        let reached = aggregator.weight();
        pending
            .lock()
            .unwrap()
            .add_signatures((epoch, batch_index), accepted);
        if !rejected.is_empty() {
            info!(
                "Rejected PresigDealerSet signatures for epoch {epoch} batch {batch_index}: \
                 {rejected:?}"
            );
        }
        if reached < required {
            info!(
                "Presig batch {batch_index} of epoch {epoch} is not sealed yet: signatures reach \
                 weight {reached} of {required}"
            );
            return Outcome::Failed;
        }
    }
    if let Some(chain_seal) = inner
        .onchain_state()
        .presig_seals(epoch)
        .remove(&batch_index)
    {
        warn_if_other_digest(message, &chain_seal);
        return Outcome::Done;
    }
    let certificate = match aggregator.finish() {
        Ok(certificate) => certificate,
        Err(e) => {
            warn!(
                "Cannot build the PresigDealerSet certificate for epoch {epoch} batch \
                 {batch_index}: {e}"
            );
            return Outcome::Failed;
        }
    };
    let submitted = async {
        crate::sui_tx_executor::SuiTxExecutor::from_hashi(Arc::clone(inner))
            .map_err(SubmitCertError::NotSubmitted)?
            .execute_submit_presig_dealer_set(message, certificate.committee_signature())
            .await
    }
    .await;
    match submitted {
        Ok(()) => {
            info!("Submitted PresigDealerSet for epoch {epoch} batch {batch_index}");
            Outcome::Done
        }
        Err(e) => {
            warn!("Sealing presig batch {batch_index} of epoch {epoch} failed: {e}");
            match e {
                SubmitCertError::Rejected(_) | SubmitCertError::NotSubmitted(_) => Outcome::Failed,
                SubmitCertError::SubmitFailed(_) | SubmitCertError::Unconfirmed(_) => {
                    Outcome::FailedInFlight
                }
            }
        }
    }
}

async fn request_signature(
    inner: &Hashi,
    address: Address,
    epoch: u64,
    batch_index: u32,
) -> Option<Vec<u8>> {
    tokio::time::timeout(RPC_TIMEOUT, async {
        let client = inner
            .onchain_state()
            .state()
            .hashi()
            .committees
            .client(&address)?;
        client
            .get_presig_dealer_set_signature(epoch, batch_index)
            .await
            .ok()
            .flatten()
    })
    .await
    .ok()
    .flatten()
}

fn warn_if_other_digest(message: &PresigDealerSetMessage, chain_seal: &PresigSealV1) {
    if chain_seal.dealer_set_digest != message.dealer_set_digest {
        warn!(
            "Presig batch {} of epoch {} was sealed over a dealer set this node did not build; \
             this node will not sign from it",
            message.batch_index, message.epoch,
        );
    }
}

fn submit_delay(
    committee: &RuntimeCommittee,
    my_address: Address,
    epoch: u64,
    batch_index: u32,
) -> Duration {
    let members = committee.members();
    let Some(position) = members
        .iter()
        .position(|m| m.validator_address() == my_address)
    else {
        return SUBMIT_STAGGER;
    };
    let len = members.len() as u64;
    let first = (epoch % len + u64::from(batch_index) % len) % len;
    let rank = (position as u64 + len - first) % len;
    SUBMIT_STAGGER * rank as u32
}

#[cfg(test)]
mod tests {
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;

    use super::*;

    fn message(epoch: u64, batch_index: u32) -> PresigDealerSetMessage {
        PresigDealerSetMessage {
            epoch,
            batch_index,
            dealer_set_digest: vec![7; 32],
        }
    }

    fn signature() -> BLS12381Signature {
        Bls12381PrivateKey::generate(&mut rand::thread_rng())
            .sign(
                Address::new([0; 32]),
                1,
                Address::new([0; 32]),
                &message(1, 0),
            )
            .signature()
            .clone()
    }

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn signers(due: &DueSeal) -> Vec<Address> {
        due.signatures.iter().map(|(signer, _)| *signer).collect()
    }

    fn sealed(batch_index: u32) -> BTreeMap<u32, PresigSealV1> {
        BTreeMap::from([(
            batch_index,
            PresigSealV1 {
                randomness: vec![0; 32],
                dealer_set_digest: vec![7; 32],
            },
        )])
    }

    #[test]
    fn pending_seal_schedule() {
        let stagger = |_| secs(10);
        let no_seals = BTreeMap::new();
        let me = Address::new([1; 32]);
        let peer = Address::new([2; 32]);
        let mut pending = PendingSeals::default();
        pending.insert_if_absent(message(5, 0), me, signature());
        pending.insert_if_absent(message(5, 1), me, signature());
        pending.insert_if_absent(message(5, 1), peer, signature());
        pending.insert_if_absent(message(7, 0), me, signature());

        let t0 = Instant::now();
        assert!(pending.select_due(5, t0, &no_seals, stagger).is_none());
        assert!(
            pending
                .select_due(5, t0 + secs(9), &no_seals, stagger)
                .is_none()
        );
        assert!(!pending.has_due(5, t0 + secs(9)));
        assert!(pending.has_due(5, t0 + secs(10)));

        let due = pending
            .select_due(5, t0 + secs(10), &no_seals, stagger)
            .unwrap();
        assert_eq!(due.message, message(5, 0));
        assert_eq!(signers(&due), vec![me]);
        pending.finish((5, 0), Outcome::Failed, t0 + secs(10), secs(10));

        let due = pending
            .select_due(5, t0 + secs(10), &no_seals, stagger)
            .unwrap();
        assert_eq!(due.message, message(5, 1));
        assert_eq!(signers(&due), vec![me]);
        pending.add_signatures((5, 1), vec![(peer, signature())]);
        pending.finish((5, 1), Outcome::FailedInFlight, t0 + secs(10), secs(10));

        assert!(
            pending
                .select_due(5, t0 + secs(20), &no_seals, stagger)
                .is_none()
        );
        let due = pending
            .select_due(5, t0 + secs(21), &no_seals, stagger)
            .unwrap();
        assert_eq!(due.message, message(5, 0));
        pending.finish((5, 0), Outcome::Failed, t0 + secs(21), secs(10));
        assert!(
            pending
                .select_due(5, t0 + secs(32), &no_seals, stagger)
                .is_none()
        );
        let due = pending
            .select_due(5, t0 + secs(33), &no_seals, stagger)
            .unwrap();
        assert_eq!(due.message, message(5, 0));
        pending.finish((5, 0), Outcome::Done, t0 + secs(33), secs(10));

        assert!(
            pending
                .select_due(5, t0 + secs(49), &no_seals, stagger)
                .is_none()
        );
        let due = pending
            .select_due(5, t0 + secs(50), &no_seals, stagger)
            .unwrap();
        assert_eq!(due.message, message(5, 1));
        assert_eq!(signers(&due), vec![me, peer]);

        assert!(
            pending
                .select_due(5, t0 + secs(60), &sealed(1), stagger)
                .is_none()
        );
        assert!(!pending.has_due(5, t0 + secs(1000)));
        assert!(pending.entries[&(5, 1)].signatures.is_empty());

        pending.prune(6);
        assert!(pending.entries.keys().all(|(epoch, _)| *epoch == 7));
        assert!(!pending.has_due(6, t0 + secs(1000)));
        assert!(
            pending
                .select_due(6, t0 + secs(100), &no_seals, stagger)
                .is_none()
        );
        assert!(pending.entries[&(7, 0)].next_attempt.is_none());
        assert!(pending.has_due(7, t0 + secs(100)));
        assert!(
            pending
                .select_due(7, t0 + secs(100), &no_seals, stagger)
                .is_none()
        );
        assert!(
            pending
                .select_due(7, t0 + secs(110), &no_seals, stagger)
                .is_some()
        );
    }

    #[test]
    fn overdue_entry_staggers_again() {
        let stagger = |_| secs(10);
        let no_seals = BTreeMap::new();
        let mut pending = PendingSeals::default();
        pending.insert_if_absent(message(5, 0), Address::new([1; 32]), signature());
        let t0 = Instant::now();
        assert!(pending.select_due(5, t0, &no_seals, stagger).is_none());
        assert!(
            pending
                .select_due(5, t0 + secs(40), &no_seals, stagger)
                .is_some()
        );
        pending.finish((5, 0), Outcome::FailedInFlight, t0 + secs(40), secs(10));
        assert!(
            pending
                .select_due(5, t0 + secs(79), &no_seals, stagger)
                .is_none()
        );

        assert!(
            pending
                .select_due(5, t0 + secs(200), &no_seals, stagger)
                .is_none()
        );
        assert!(
            pending
                .select_due(5, t0 + secs(209), &no_seals, stagger)
                .is_none()
        );
        let due = pending.select_due(5, t0 + secs(210), &no_seals, stagger);
        assert!(due.is_some());
        pending.finish((5, 0), Outcome::Failed, t0 + secs(210), secs(10));
        assert!(
            pending
                .select_due(5, t0 + secs(220), &no_seals, stagger)
                .is_none()
        );
        assert!(
            pending
                .select_due(5, t0 + secs(221), &no_seals, stagger)
                .is_some()
        );
    }

    #[test]
    fn first_sealer_rotates_by_epoch_and_batch() {
        let mut rng = rand::thread_rng();
        let members: Vec<_> = (0..4u8)
            .map(|i| {
                CommitteeMember::new(
                    Address::new([i; 32]),
                    Bls12381PrivateKey::generate(&mut rng).public_key(),
                    EncryptionPrivateKey::new(&mut rng).public_key(),
                    1,
                )
            })
            .collect();
        let committee = RuntimeCommittee::from(Committee::new(members, 3, 0, 5_000));
        let first = |epoch, batch_index| {
            (0..4u8)
                .map(|i| Address::new([i; 32]))
                .find(|address| submit_delay(&committee, *address, epoch, batch_index).is_zero())
                .unwrap()
        };
        assert_eq!(first(0, 0), Address::new([0; 32]));
        assert_eq!(first(1, 0), Address::new([1; 32]));
        assert_eq!(first(2, 1), Address::new([3; 32]));
        assert_eq!(first(4, 0), Address::new([0; 32]));
        assert_eq!(
            submit_delay(&committee, Address::new([9; 32]), 0, 0),
            SUBMIT_STAGGER
        );
    }
}
