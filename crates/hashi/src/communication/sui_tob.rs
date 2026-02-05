//! Sui-backed Total Order Broadcast (TOB) Channel

use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use sui_crypto::ed25519::Ed25519PrivateKey;
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
use hashi_types::committee::Committee;
use hashi_types::committee::certificate_threshold;

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

pub struct SuiTobChannel {
    hashi_ids: HashiIds,
    onchain_state: OnchainState,
    epoch: u64,
    signer: Ed25519PrivateKey,
    /// Dealers we've already returned certificates for
    seen_dealers: HashSet<Address>,
    /// Cached certificates not yet returned
    pending_certs: VecDeque<CertificateV1>,
    committee: Committee,
}

impl SuiTobChannel {
    pub fn new(
        hashi_ids: HashiIds,
        onchain_state: OnchainState,
        epoch: u64,
        signer: Ed25519PrivateKey,
        committee: Committee,
    ) -> Self {
        Self {
            hashi_ids,
            onchain_state,
            epoch,
            signer,
            seen_dealers: HashSet::new(),
            pending_certs: VecDeque::new(),
            committee,
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
    committee: &Committee,
) -> Result<Vec<(Address, CertificateV1)>, TobError> {
    let threshold = certificate_threshold(committee.total_weight());
    let Some((protocol_type, raw_certs)) = onchain_state
        .fetch_certs(epoch)
        .await
        .map_err(|e| TobError::RpcError(e.to_string()))?
    else {
        return Ok(vec![]);
    };
    let mut certificates = Vec::with_capacity(raw_certs.len());
    for (dealer, cert) in raw_certs {
        let inner_cert = DealerMessagesHash::from_onchain_cert(&cert, epoch, committee, threshold)
            .map_err(|e| TobError::InvalidCertificate(e.to_string()))?;
        let cert = CertificateV1::new(protocol_type, inner_cert);
        certificates.push((dealer, cert));
    }
    Ok(certificates)
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for SuiTobChannel {
    async fn publish(&self, cert: CertificateV1) -> ChannelResult<()> {
        let dealer = cert.dealer_address();
        let existing = fetch_certificates(&self.onchain_state, self.epoch, &self.committee)
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
        loop {
            if let Some(cert) = self.pending_certs.pop_front() {
                return Ok(cert);
            }
            // TODO: Optimize by checking table size first to avoid redundant fetches.
            let all_certs = fetch_certificates(&self.onchain_state, self.epoch, &self.committee)
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

    fn existing_certificate_weight(&self) -> u32 {
        self.seen_dealers
            .iter()
            .filter_map(|dealer| self.committee.weight_of(dealer).ok())
            .map(|w| w as u32)
            .sum()
    }
}
