// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Sui-backed Total Order Broadcast (TOB) Channel

use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use hashi_types::move_types::ProtocolType;
use sui_crypto::simple::SimpleKeypair;
use sui_sdk_types::Address;
use thiserror::Error;

use super::ChannelError;
use super::ChannelResult;
use super::OrderedBroadcastChannel;
use super::PublishOutcome;
use crate::config::HashiIds;
use crate::mpc::types::CertificateV1;
use crate::mpc::types::DealerMessagesHash;
use crate::mpc::types::MessagesHash;
use crate::onchain::OnchainState;
use crate::onchain::TobCertLayout;
use crate::sui_tx_executor::SubmitCertError;
use crate::sui_tx_executor::SuiTxExecutor;

/// Pace of the receive loop's mirror polls. The read itself is a local
/// lookup; the interval just paces the wait for new submissions to
/// stream into the mirror.
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum TobError {
    #[error("Invalid certificate data: {0}")]
    InvalidCertificate(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("incomplete cert table read: {0}")]
    IncompleteRead(String),

    #[error("unordered cert table read: {0}")]
    UnorderedRead(String),
}

impl From<TobError> for ChannelError {
    fn from(e: TobError) -> Self {
        ChannelError::Other(e.to_string())
    }
}

pub struct SuiTobSessionChannel {
    hashi_ids: HashiIds,
    onchain_state: OnchainState,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
    signer: SimpleKeypair,
    idle_timeout: Option<Duration>,
    /// Dealers we've already returned certificates for
    seen_dealers: HashSet<Address>,
    /// Cached certificates not yet returned
    pending_certs: VecDeque<CertificateV1>,
    wait_started: Option<tokio::time::Instant>,
}

impl SuiTobSessionChannel {
    pub fn new(
        hashi_ids: HashiIds,
        onchain_state: OnchainState,
        epoch: u64,
        batch_index: Option<u32>,
        protocol_type: ProtocolType,
        signer: SimpleKeypair,
    ) -> Self {
        Self {
            hashi_ids,
            onchain_state,
            epoch,
            batch_index,
            protocol_type,
            signer,
            idle_timeout: None,
            seen_dealers: HashSet::new(),
            pending_certs: VecDeque::new(),
            wait_started: None,
        }
    }

    pub fn with_idle_timeout(mut self, idle_timeout: Duration) -> Self {
        self.idle_timeout = Some(idle_timeout);
        self
    }

    fn create_executor(&self) -> SuiTxExecutor {
        SuiTxExecutor::new(
            self.onchain_state.client(),
            self.signer.clone(),
            self.hashi_ids,
        )
        .with_timeout(TX_CONFIRMATION_TIMEOUT)
        .with_onchain_state(&self.onchain_state)
    }
}

fn tob_read_error(e: anyhow::Error) -> TobError {
    if crate::onchain::is_inconsistent_listing(&e) {
        TobError::IncompleteRead(e.to_string())
    } else if e
        .downcast_ref::<crate::onchain::UnorderedCertTableRead>()
        .is_some()
    {
        TobError::UnorderedRead(e.to_string())
    } else {
        TobError::InvalidState(e.to_string())
    }
}

/// Read one TOB bucket's certificates from the object mirror, in TOB
/// order. Returns an empty vector when the bucket does not exist (yet):
/// a lagging mirror shows up as certificates arriving slightly later,
/// and every caller sits in a retry or poll loop, so freshness needs no
/// extra gating here.
pub fn tob_certificates(
    onchain_state: &OnchainState,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) -> Result<Vec<(Address, CertificateV1)>, TobError> {
    Ok(
        tob_certificates_if_present(onchain_state, epoch, batch_index, protocol_type)?
            .unwrap_or_default(),
    )
}

fn tob_certificates_if_present(
    onchain_state: &OnchainState,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) -> Result<Option<Vec<(Address, CertificateV1)>>, TobError> {
    let Some((layout, raw)) = onchain_state
        .tob_certs(epoch, batch_index, protocol_type)
        .map_err(tob_read_error)?
    else {
        return Ok(None);
    };
    // Only nonce buckets ever carry the stamped layout on-chain; the
    // mirror hands every submission back in stamped form regardless (a
    // bare one carries `timestamp_ms: 0`), so the layout only needs a
    // sanity gate, not a decode dispatch.
    if protocol_type != ProtocolType::NonceGeneration && layout != TobCertLayout::Bare {
        return Err(TobError::InvalidState(format!(
            "TOB bucket (epoch {epoch}, batch {batch_index:?}, {protocol_type:?}) uses the \
             {layout:?} cert layout, which only nonce buckets may carry"
        )));
    }
    let mut certificates = Vec::with_capacity(raw.len());
    for (dealer, stamped) in raw {
        let (submission, timestamp_ms) = (stamped.submission, stamped.timestamp_ms);
        let inner_cert = match DealerMessagesHash::from_onchain_cert(&submission, epoch) {
            Ok(inner_cert) => inner_cert,
            Err(e) => {
                tracing::warn!(
                    "Skipping malformed {protocol_type:?} dealer cert from {dealer} for epoch \
                     {epoch} batch {batch_index:?}: {e}"
                );
                continue;
            }
        };
        let cert = CertificateV1::new(protocol_type, batch_index, inner_cert, timestamp_ms);
        certificates.push((dealer, cert));
    }
    Ok(Some(certificates))
}

pub struct PrefetchedTobChannel {
    certs: Vec<(Address, CertificateV1)>,
    next: usize,
    supersede: Option<(OnchainState, u64)>,
}

impl PrefetchedTobChannel {
    pub fn new(certs: Vec<(Address, CertificateV1)>) -> Self {
        Self {
            certs,
            next: 0,
            supersede: None,
        }
    }

    pub fn with_supersede_check(mut self, onchain_state: OnchainState, epoch: u64) -> Self {
        self.supersede = Some((onchain_state, epoch));
        self
    }
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for PrefetchedTobChannel {
    async fn publish(&self, _cert: CertificateV1) -> ChannelResult<PublishOutcome> {
        Err(ChannelError::Other(
            "replayed certificate stream is receive-only".into(),
        ))
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        if let Some((onchain_state, epoch)) = &self.supersede {
            let (onchain_epoch, pending) = {
                let state = onchain_state.state();
                let committees = &state.hashi().committees;
                (committees.epoch(), committees.pending_epoch_change())
            };
            if tob_wait_superseded(
                ProtocolType::NonceGeneration,
                *epoch,
                onchain_epoch,
                pending,
            ) {
                return Err(ChannelError::Other(format!(
                    "nonce cert replay for epoch {epoch} superseded (onchain epoch \
                     {onchain_epoch}, pending epoch change {pending:?})"
                )));
            }
        }
        let (_, cert) = self.certs.get(self.next).ok_or(ChannelError::Exhausted)?;
        self.next += 1;
        Ok(cert.clone())
    }

    async fn certified_dealers(&mut self) -> Vec<(Address, CertificateV1)> {
        self.certs.clone()
    }
}

pub fn key_generation_certificates(
    onchain_state: &OnchainState,
    epoch: u64,
) -> Result<Vec<(Address, CertificateV1)>, TobError> {
    let earliest_committee_epoch = onchain_state.earliest_committee_epoch();
    let protocol_type = key_generation_protocol(earliest_committee_epoch, epoch);
    let certificates = tob_certificates_if_present(onchain_state, epoch, None, protocol_type)?
        .ok_or_else(|| {
            TobError::InvalidState(format!(
                "epoch {epoch}: {protocol_type:?} certificate bucket not found — either absent or \
                 the tob listing was incomplete (earliest committee epoch \
                 {earliest_committee_epoch:?})"
            ))
        })?;
    if certificates.is_empty() {
        return Err(TobError::InvalidState(format!(
            "epoch {epoch}: {protocol_type:?} certificate bucket exists but is empty \
             (earliest committee epoch {earliest_committee_epoch:?})"
        )));
    }
    Ok(certificates)
}

fn key_generation_protocol(earliest_committee_epoch: Option<u64>, epoch: u64) -> ProtocolType {
    if OnchainState::epoch_after_first_committee(earliest_committee_epoch, epoch) {
        ProtocolType::KeyRotation
    } else {
        ProtocolType::Dkg
    }
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for SuiTobSessionChannel {
    async fn publish(&self, cert: CertificateV1) -> ChannelResult<PublishOutcome> {
        let ours = cert.message();
        // The dedup read is a local mirror lookup; a lagging mirror at
        // worst resubmits, which `submit_cert`'s first-submission-wins
        // turns into a paid on-chain no-op.
        let existing = match tob_certificates(
            &self.onchain_state,
            self.epoch,
            self.batch_index,
            self.protocol_type,
        ) {
            Ok(existing) => existing,
            Err(e @ (TobError::IncompleteRead(_) | TobError::UnorderedRead(_))) => {
                tracing::warn!(
                    "{:?} dedup read for epoch {} batch {:?} unusable ({e}); submitting anyway",
                    self.protocol_type,
                    self.epoch,
                    self.batch_index,
                );
                Vec::new()
            }
            Err(e) => return Err(ChannelError::from(e)),
        };
        let published: Vec<(Address, MessagesHash)> = existing
            .iter()
            .map(|(d, c)| (*d, c.message().messages_hash))
            .collect();
        let classified =
            classify_published_cert(&published, &ours.dealer_address, ours.messages_hash);
        if let PublishedCert::Diverged { on_chain } = &classified {
            tracing::warn!(
                "{:?} epoch {} batch {:?}: dealer {} already has a certificate over \
                 different messages (on chain {}, ours {}); regenerated messages or an \
                 AVID optimistic/pessimistic flip",
                self.protocol_type,
                self.epoch,
                self.batch_index,
                ours.dealer_address,
                hex::encode(<MessagesHash as AsRef<[u8; 32]>>::as_ref(on_chain)),
                hex::encode(<MessagesHash as AsRef<[u8; 32]>>::as_ref(
                    &ours.messages_hash
                )),
            );
        }
        if let Some(outcome) = short_circuit_outcome(&classified) {
            return Ok(outcome);
        }
        let mut executor = self.create_executor();
        let inserted = executor
            .execute_submit_certificate(&cert)
            .await
            // Only `Rejected` is the chain's answer; the rest are failures reaching it or reading
            // the result back, and must not share a bucket with a conclusive rejection.
            .map_err(|e| match &e {
                SubmitCertError::Rejected(_) => ChannelError::Other(e.to_string()),
                SubmitCertError::NotSubmitted(_)
                | SubmitCertError::SubmitFailed(_)
                | SubmitCertError::Unconfirmed(_) => ChannelError::RequestFailed(e.to_string()),
            })?;
        if inserted {
            return Ok(PublishOutcome::Landed);
        }
        // Nothing inserted means a certificate for this dealer already
        // holds the slot on-chain, but the mirror may not have applied
        // the transaction that beat ours yet — poll briefly for it
        // rather than misreading the lag as divergence.
        let settled_deadline = tokio::time::Instant::now() + TX_CONFIRMATION_TIMEOUT;
        let classified = loop {
            match tob_certificates(
                &self.onchain_state,
                self.epoch,
                self.batch_index,
                self.protocol_type,
            ) {
                Ok(settled) => {
                    let settled: Vec<(Address, MessagesHash)> = settled
                        .iter()
                        .map(|(d, c)| (*d, c.message().messages_hash))
                        .collect();
                    let classified =
                        classify_published_cert(&settled, &ours.dealer_address, ours.messages_hash);
                    if !matches!(classified, PublishedCert::Absent)
                        || tokio::time::Instant::now() >= settled_deadline
                    {
                        break classified;
                    }
                }
                Err(e @ (TobError::IncompleteRead(_) | TobError::UnorderedRead(_)))
                    if tokio::time::Instant::now() < settled_deadline =>
                {
                    tracing::debug!(
                        "{:?} settled read for epoch {} batch {:?} unusable ({e}); retrying",
                        self.protocol_type,
                        self.epoch,
                        self.batch_index,
                    );
                }
                Err(e) => return Err(ChannelError::from(e)),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        let outcome = raced_outcome(&classified);
        tracing::warn!(
            "{:?} epoch {} batch {:?}: this submission for dealer {} inserted nothing; a \
             certificate already held the slot (ours {}), outcome {:?}",
            self.protocol_type,
            self.epoch,
            self.batch_index,
            ours.dealer_address,
            hex::encode(<MessagesHash as AsRef<[u8; 32]>>::as_ref(
                &ours.messages_hash
            )),
            outcome,
        );
        Ok(outcome)
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        let wait_started = *self
            .wait_started
            .get_or_insert_with(tokio::time::Instant::now);
        loop {
            if let Some(cert) = self.pending_certs.pop_front() {
                self.wait_started = None;
                return Ok(cert);
            }
            let all_certs = match tob_certificates(
                &self.onchain_state,
                self.epoch,
                self.batch_index,
                self.protocol_type,
            ) {
                Ok(certs) => certs,
                Err(TobError::IncompleteRead(msg)) => {
                    tracing::debug!(
                        "{:?} TOB cert read for epoch {} raced the mirror's replay ({msg}); \
                         retrying",
                        self.protocol_type,
                        self.epoch,
                    );
                    Vec::new()
                }
                Err(e) => {
                    self.wait_started = None;
                    return Err(ChannelError::from(e));
                }
            };
            for (dealer, cert) in all_certs {
                if !self.seen_dealers.contains(&dealer) {
                    self.seen_dealers.insert(dealer);
                    self.pending_certs.push_back(cert);
                }
            }
            if self.pending_certs.is_empty() {
                let (onchain_epoch, pending) = {
                    let state = self.onchain_state.state();
                    let committees = &state.hashi().committees;
                    (committees.epoch(), committees.pending_epoch_change())
                };
                if tob_wait_superseded(self.protocol_type, self.epoch, onchain_epoch, pending) {
                    tracing::info!(
                        "aborting {:?} TOB wait for epoch {}: superseded (onchain epoch \
                         {onchain_epoch}, pending epoch change {pending:?})",
                        self.protocol_type,
                        self.epoch,
                    );
                    self.wait_started = None;
                    return Err(ChannelError::Superseded(format!(
                        "{:?} TOB wait for epoch {} (onchain epoch {onchain_epoch}, \
                         pending epoch change {pending:?})",
                        self.protocol_type, self.epoch,
                    )));
                }
                if let Some(idle_timeout) = self.idle_timeout
                    && wait_started.elapsed() >= idle_timeout
                {
                    tracing::info!(
                        "aborting {:?} TOB wait for epoch {}: no certificate in {:?} \
                         ({} dealers seen)",
                        self.protocol_type,
                        self.epoch,
                        idle_timeout,
                        self.seen_dealers.len(),
                    );
                    self.wait_started = None;
                    return Err(ChannelError::Timeout);
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }

    async fn certified_dealers(&mut self) -> Vec<(Address, CertificateV1)> {
        match tob_certificates(
            &self.onchain_state,
            self.epoch,
            self.batch_index,
            self.protocol_type,
        ) {
            Ok(all_certs) => {
                for (dealer, cert) in &all_certs {
                    if !self.seen_dealers.contains(dealer) {
                        self.seen_dealers.insert(*dealer);
                        self.pending_certs.push_back(cert.clone());
                    }
                }
                all_certs
            }
            Err(e) => {
                tracing::warn!(
                    "{:?} certified_dealers read for epoch {} batch {:?} failed: {e}; \
                     reporting none certified",
                    self.protocol_type,
                    self.epoch,
                    self.batch_index,
                );
                vec![]
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PublishedCert {
    Absent,
    Same,
    Diverged { on_chain: MessagesHash },
}

fn raced_outcome(classified: &PublishedCert) -> PublishOutcome {
    match classified {
        PublishedCert::Same => PublishOutcome::AlreadyPresent,
        PublishedCert::Diverged { .. } | PublishedCert::Absent => PublishOutcome::Diverged,
    }
}

fn short_circuit_outcome(classified: &PublishedCert) -> Option<PublishOutcome> {
    match classified {
        PublishedCert::Same => Some(PublishOutcome::AlreadyPresent),
        PublishedCert::Diverged { .. } => Some(PublishOutcome::Diverged),
        PublishedCert::Absent => None,
    }
}

fn classify_published_cert(
    existing: &[(Address, MessagesHash)],
    dealer: &Address,
    ours: MessagesHash,
) -> PublishedCert {
    let Some((_, on_chain)) = existing.iter().find(|(d, _)| d == dealer) else {
        return PublishedCert::Absent;
    };
    if *on_chain == ours {
        PublishedCert::Same
    } else {
        PublishedCert::Diverged {
            on_chain: *on_chain,
        }
    }
}

pub(crate) fn tob_wait_superseded(
    protocol_type: ProtocolType,
    channel_epoch: u64,
    onchain_epoch: u64,
    pending_epoch_change: Option<u64>,
) -> bool {
    match protocol_type {
        ProtocolType::NonceGeneration => {
            matches!(pending_epoch_change, Some(p) if p != channel_epoch)
                || onchain_epoch > channel_epoch
        }
        ProtocolType::Dkg | ProtocolType::KeyRotation => {
            matches!(pending_epoch_change, Some(p) if p != channel_epoch)
                || (pending_epoch_change.is_none() && onchain_epoch != channel_epoch)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn raced_cert_reads_classify_as_retryable() {
        use crate::onchain::inconsistent_listing;

        let raced = inconsistent_listing("dangling node".into());
        assert!(
            matches!(super::tob_read_error(raced), TobError::IncompleteRead(_)),
            "a raced cert-table read must stay distinguishable from other failures"
        );

        let wrapped = inconsistent_listing("dangling node".into()).context("reading certs");
        assert!(matches!(
            super::tob_read_error(wrapped),
            TobError::IncompleteRead(_)
        ));

        assert!(
            matches!(
                super::tob_read_error(anyhow::anyhow!("unexpected mirror failure")),
                TobError::InvalidState(_)
            ),
            "an unrecognized read failure must not be swallowed as retryable"
        );

        use crate::onchain::UnorderedCertTableRead;
        let unordered = || UnorderedCertTableRead {
            earlier: Address::ZERO,
            earlier_ms: 5_000,
            later: Address::ZERO,
            later_ms: 1_000,
        };
        assert!(
            matches!(
                super::tob_read_error(unordered().into()),
                TobError::UnorderedRead(_)
            ),
            "an unordered read must stay distinguishable: publish tolerates it, the window \
             walks must not"
        );
        assert!(matches!(
            super::tob_read_error(anyhow::Error::from(unordered()).context("reading certs")),
            TobError::UnorderedRead(_)
        ));
    }
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    fn hash(b: u8) -> MessagesHash {
        let mut bytes = [0xAB; 32];
        bytes[17] = b;
        MessagesHash::new(bytes)
    }

    #[test]
    fn raced_outcome_maps_each_classification() {
        assert_eq!(
            raced_outcome(&PublishedCert::Same),
            PublishOutcome::AlreadyPresent
        );
        assert_eq!(
            raced_outcome(&PublishedCert::Absent),
            PublishOutcome::Diverged
        );
        assert_eq!(
            raced_outcome(&PublishedCert::Diverged { on_chain: hash(1) }),
            PublishOutcome::Diverged
        );
    }

    #[test]
    fn short_circuit_outcome_maps_each_classification() {
        assert_eq!(
            short_circuit_outcome(&PublishedCert::Same),
            Some(PublishOutcome::AlreadyPresent)
        );
        assert_eq!(
            short_circuit_outcome(&PublishedCert::Diverged { on_chain: hash(1) }),
            Some(PublishOutcome::Diverged)
        );
        assert_eq!(short_circuit_outcome(&PublishedCert::Absent), None);
    }

    #[test]
    fn republishing_the_same_messages_is_not_a_divergence() {
        let existing = [(addr(1), hash(9)), (addr(2), hash(8))];
        assert_eq!(
            classify_published_cert(&existing, &addr(1), hash(9)),
            PublishedCert::Same
        );
    }

    #[test]
    fn different_messages_under_our_dealer_address_diverge() {
        let existing = [(addr(1), hash(9))];
        assert_eq!(
            classify_published_cert(&existing, &addr(1), hash(7)),
            PublishedCert::Diverged { on_chain: hash(9) }
        );
    }

    #[test]
    fn only_our_own_dealer_slot_is_compared() {
        let existing = [(addr(2), hash(7)), (addr(3), hash(6))];
        assert_eq!(
            classify_published_cert(&existing, &addr(1), hash(9)),
            PublishedCert::Absent
        );
    }

    #[test]
    fn an_empty_tob_slot_is_absent() {
        assert_eq!(
            classify_published_cert(&[], &addr(1), hash(9)),
            PublishedCert::Absent
        );
    }

    #[test]
    fn the_genesis_epoch_selects_dkg() {
        assert_eq!(key_generation_protocol(Some(9), 9), ProtocolType::Dkg);
        assert_eq!(key_generation_protocol(Some(9), 5), ProtocolType::Dkg);
        assert_eq!(key_generation_protocol(None, 9), ProtocolType::Dkg);
    }

    #[test]
    fn an_epoch_after_the_first_committee_selects_rotation() {
        assert_eq!(
            key_generation_protocol(Some(9), 32),
            ProtocolType::KeyRotation
        );
    }

    #[test]
    fn nonce_wait_superseded_only_by_other_reconfig_or_passed_epoch() {
        let p = ProtocolType::NonceGeneration;
        assert!(!tob_wait_superseded(p, 5, 5, None));
        assert!(!tob_wait_superseded(p, 5, 4, Some(5)));
        assert!(!tob_wait_superseded(p, 5, 4, None));
        assert!(tob_wait_superseded(p, 5, 5, Some(6)));
        assert!(tob_wait_superseded(p, 5, 4, Some(6)));
        assert!(tob_wait_superseded(p, 5, 6, None));
    }

    #[test]
    fn rotation_wait_bound_to_its_own_pending_target() {
        for p in [ProtocolType::KeyRotation, ProtocolType::Dkg] {
            assert!(!tob_wait_superseded(p, 6, 5, Some(6)));
            assert!(!tob_wait_superseded(p, 6, 6, None));
            assert!(tob_wait_superseded(p, 6, 6, Some(7)));
            assert!(tob_wait_superseded(p, 6, 5, None));
            assert!(tob_wait_superseded(p, 6, 5, Some(7)));
        }
    }

    #[tokio::test]
    async fn tokio_joinhandle_survives_cancelled_awaits() {
        let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = std::sync::Arc::clone(&polls);
        let mut fetch: tokio::task::JoinHandle<usize> = tokio::spawn(async move {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(300)).await;
            42
        });

        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), &mut fetch)
                    .await
                    .is_err(),
                "expected the short poll to elapse"
            );
        }

        let out = tokio::time::timeout(Duration::from_millis(500), &mut fetch)
            .await
            .expect("fetch must still be progressing, not restarted")
            .expect("task must not have been cancelled by the dropped awaits");
        assert_eq!(out, 42);
        assert_eq!(
            polls.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the fetch must have run once, not restarted per poll"
        );
    }
}
