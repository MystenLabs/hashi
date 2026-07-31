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
use crate::config::HashiIds;
use crate::mpc::types::CertificateV1;
use crate::mpc::types::DealerMessagesHash;
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

pub struct SuiTobChannel {
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

impl SuiTobChannel {
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
    certs: VecDeque<CertificateV1>,
    dealers: Vec<Address>,
}

impl PrefetchedTobChannel {
    pub fn new(certs: Vec<(Address, CertificateV1)>) -> Self {
        let dealers = certs.iter().map(|(dealer, _)| *dealer).collect();
        Self {
            certs: certs.into_iter().map(|(_, cert)| cert).collect(),
            dealers,
        }
    }
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for PrefetchedTobChannel {
    async fn publish(&self, _cert: CertificateV1) -> ChannelResult<()> {
        Err(ChannelError::Other(
            "replayed certificate stream is receive-only".into(),
        ))
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        self.certs
            .pop_front()
            .ok_or_else(|| ChannelError::Other("replayed certificate stream exhausted".into()))
    }

    async fn certified_dealers(&mut self) -> Vec<Address> {
        self.dealers.clone()
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
impl OrderedBroadcastChannel<CertificateV1> for SuiTobChannel {
    async fn publish(&self, cert: CertificateV1) -> ChannelResult<()> {
        let dealer = cert.dealer_address();
        let existing = fetch_certificates(
            &self.onchain_state,
            self.epoch,
            self.batch_index,
            self.protocol_type,
        )
        .await
        .map_err(ChannelError::from)?;
        if existing.iter().any(|(d, _)| *d == dealer) {
            return Ok(());
        }

        let mut executor = self.create_executor();
        executor
            .execute_submit_certificate(&cert)
            .await
            .map_err(|e| ChannelError::Other(e.to_string()))
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

    async fn certified_dealers(&mut self) -> Vec<Address> {
        if let Ok(Ok(all_certs)) = tokio::time::timeout(
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
            for (dealer, cert) in all_certs {
                if !self.seen_dealers.contains(&dealer) {
                    self.seen_dealers.insert(dealer);
                    self.pending_certs.push_back(cert);
                }
            }
        }
        self.seen_dealers.iter().copied().collect()
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
