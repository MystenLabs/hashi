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
use crate::mpc::types::MessageHash;
use crate::onchain::OnchainState;
use crate::sui_tx_executor::SuiTxExecutor;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const TX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);
const FETCH_STALL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum TobError {
    #[error("Sui RPC error: {0}")]
    RpcError(String),

    #[error("Invalid certificate data: {0}")]
    InvalidCertificate(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<TobError> for ChannelError {
    fn from(e: TobError) -> Self {
        match e {
            TobError::RpcError(msg) => ChannelError::RequestFailed(msg),
            _ => ChannelError::Other(e.to_string()),
        }
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
    }
}

pub async fn fetch_certificates(
    onchain_state: &OnchainState,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
) -> Result<Vec<(Address, CertificateV1)>, TobError> {
    let Some(raw_certs) = onchain_state
        .fetch_certs(epoch, batch_index, protocol_type)
        .await
        .map_err(|e| TobError::RpcError(e.to_string()))?
    else {
        return Ok(vec![]);
    };
    let mut certificates = Vec::with_capacity(raw_certs.len());
    for (dealer, cert) in raw_certs {
        let inner_cert = DealerMessagesHash::from_onchain_cert(&cert, epoch)
            .map_err(|e| TobError::InvalidCertificate(e.to_string()))?;
        let cert = CertificateV1::new(protocol_type, batch_index, inner_cert);
        certificates.push((dealer, cert));
    }
    Ok(certificates)
}

pub struct PrefetchedTobChannel {
    certs: Vec<(Address, CertificateV1)>,
    next: usize,
}

impl PrefetchedTobChannel {
    pub fn new(certs: Vec<(Address, CertificateV1)>) -> Self {
        Self { certs, next: 0 }
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
        let (_, cert) = self
            .certs
            .get(self.next)
            .ok_or_else(|| ChannelError::Other("replayed certificate stream exhausted".into()))?;
        self.next += 1;
        Ok(cert.clone())
    }

    async fn certified_dealers(&mut self) -> Vec<(Address, CertificateV1)> {
        self.certs.clone()
    }
}

pub async fn fetch_key_generation_certificates(
    onchain_state: &OnchainState,
    epoch: u64,
) -> Result<Vec<(Address, CertificateV1)>, TobError> {
    let rotation =
        fetch_certificates(onchain_state, epoch, None, ProtocolType::KeyRotation).await?;
    if !rotation.is_empty() {
        return Ok(rotation);
    }
    fetch_certificates(onchain_state, epoch, None, ProtocolType::Dkg).await
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for SuiTobSessionChannel {
    async fn publish(&self, cert: CertificateV1) -> ChannelResult<PublishOutcome> {
        let ours = cert.message();
        let existing = fetch_certificates(
            &self.onchain_state,
            self.epoch,
            self.batch_index,
            self.protocol_type,
        )
        .await
        .map_err(ChannelError::from)?;
        let published: Vec<(Address, MessageHash)> = existing
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
                hex::encode(<MessageHash as AsRef<[u8; 32]>>::as_ref(on_chain)),
                hex::encode(<MessageHash as AsRef<[u8; 32]>>::as_ref(
                    &ours.messages_hash
                )),
            );
        }
        if let Some(outcome) = short_circuit_outcome(&classified) {
            return Ok(outcome);
        }

        let mut executor = self.create_executor();
        executor
            .execute_submit_certificate(&cert)
            .await
            .map_err(|e| ChannelError::Other(e.to_string()))?;
        Ok(PublishOutcome::Landed)
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        let wait_started = tokio::time::Instant::now();
        loop {
            if let Some(cert) = self.pending_certs.pop_front() {
                return Ok(cert);
            }
            // TODO: Optimize by checking table size first to avoid redundant fetches.
            let all_certs = match tokio::time::timeout(
                FETCH_STALL_TIMEOUT,
                fetch_certificates(
                    &self.onchain_state,
                    self.epoch,
                    self.batch_index,
                    self.protocol_type,
                ),
            )
            .await
            {
                Ok(result) => result.map_err(ChannelError::from)?,
                Err(_) => {
                    tracing::warn!(
                        "{:?} TOB cert fetch for epoch {} stalled >{:?}; retrying",
                        self.protocol_type,
                        self.epoch,
                        FETCH_STALL_TIMEOUT,
                    );
                    Vec::new()
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
                    return Err(ChannelError::Timeout);
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }

    async fn certified_dealers(&mut self) -> Vec<(Address, CertificateV1)> {
        let Ok(Ok(all_certs)) = tokio::time::timeout(
            FETCH_STALL_TIMEOUT,
            fetch_certificates(
                &self.onchain_state,
                self.epoch,
                self.batch_index,
                self.protocol_type,
            ),
        )
        .await
        else {
            return vec![];
        };
        for (dealer, cert) in &all_certs {
            if !self.seen_dealers.contains(dealer) {
                self.seen_dealers.insert(*dealer);
                self.pending_certs.push_back(cert.clone());
            }
        }
        all_certs
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PublishedCert {
    Absent,
    Same,
    Diverged { on_chain: MessageHash },
}

fn short_circuit_outcome(classified: &PublishedCert) -> Option<PublishOutcome> {
    match classified {
        PublishedCert::Same => Some(PublishOutcome::AlreadyPresent),
        PublishedCert::Diverged { .. } => Some(PublishOutcome::Diverged),
        PublishedCert::Absent => None,
    }
}

fn classify_published_cert(
    existing: &[(Address, MessageHash)],
    dealer: &Address,
    ours: MessageHash,
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

fn tob_wait_superseded(
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
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    fn hash(b: u8) -> MessageHash {
        let mut bytes = [0xAB; 32];
        bytes[17] = b;
        MessageHash::new(bytes)
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
}
