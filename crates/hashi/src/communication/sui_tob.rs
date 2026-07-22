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

// Ben: It is not a general channel, but per protocol - maybe call it SuiTobChannelPerProtocol
pub struct SuiTobChannel {
    hashi_ids: HashiIds,
    onchain_state: OnchainState,
    epoch: u64,
    batch_index: Option<u32>,
    protocol_type: ProtocolType,
    signer: SimpleKeypair,
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
            seen_dealers: HashSet::new(),
            pending_certs: VecDeque::new(),
        }
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
            // Ben: check it is the same cert or warn
            return Ok(());
        }

        let mut executor = self.create_executor();
        executor
            .execute_submit_certificate(&cert)
            .await
            .map_err(|e| ChannelError::Other(e.to_string()))
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        loop {
            if let Some(cert) = self.pending_certs.pop_front() {
                return Ok(cert);
            }
            // TODO: Optimize by checking table size first to avoid redundant fetches.
            let all_certs = fetch_certificates(
                &self.onchain_state,
                self.epoch,
                self.batch_index,
                self.protocol_type,
            )
            .await
            .map_err(ChannelError::from)?;
            for (dealer, cert) in all_certs {
                if !self.seen_dealers.contains(&dealer) {
                    self.seen_dealers.insert(dealer);
                    self.pending_certs.push_back(cert);
                }
            }
            if self.pending_certs.is_empty() {
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }

    async fn certified_dealers(&mut self) -> Vec<Address> {
        if let Ok(all_certs) = fetch_certificates(
            &self.onchain_state,
            self.epoch,
            self.batch_index,
            self.protocol_type,
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
