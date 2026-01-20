//! Sui-backed Total Order Broadcast (TOB) Channel

use std::collections::HashSet;
use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::ExecuteTransactionRequest;
use sui_sdk_types::Address;
use sui_sdk_types::Argument;
use sui_sdk_types::Command;
use sui_sdk_types::GasPayment;
use sui_sdk_types::Identifier;
use sui_sdk_types::Input;
use sui_sdk_types::MoveCall;
use sui_sdk_types::ObjectReference;
use sui_sdk_types::ProgrammableTransaction;
use sui_sdk_types::SharedInput;
use sui_sdk_types::StructTag;
use sui_sdk_types::Transaction;
use sui_sdk_types::TransactionExpiration;
use sui_sdk_types::TransactionKind;
use sui_sdk_types::bcs::ToBcs;
use thiserror::Error;

use super::ChannelError;
use super::ChannelResult;
use super::OrderedBroadcastChannel;
use crate::dkg::types::CertificateV1;
use crate::dkg::types::DkgDealerMessageHash;
use crate::onchain::OnchainState;
use hashi_types::committee::Committee;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const GAS_BUDGET: u64 = 50_000_000;
const TX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(30);

// TODO: Read threshold from on-chain config once it is made configurable.
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

#[derive(Debug, Error)]
pub enum TobError {
    #[error("Sui RPC error: {0}")]
    RpcError(String),

    #[error("Transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid certificate data: {0}")]
    InvalidCertificate(String),

    #[error("Wrong epoch: expected {expected}, got {got}")]
    WrongEpoch { expected: u64, got: u64 },

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<TobError> for ChannelError {
    fn from(e: TobError) -> Self {
        match e {
            TobError::RpcError(msg) => ChannelError::RequestFailed(msg),
            TobError::TransactionFailed(msg) => ChannelError::RequestFailed(msg),
            _ => ChannelError::Other(e.to_string()),
        }
    }
}

pub struct SuiTobChannel {
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
        onchain_state: OnchainState,
        epoch: u64,
        signer: Ed25519PrivateKey,
        committee: Committee,
    ) -> Self {
        Self {
            onchain_state,
            epoch,
            signer,
            seen_dealers: HashSet::new(),
            pending_certs: VecDeque::new(),
            committee,
        }
    }

    // This matches the Move contract's threshold computation.
    fn threshold(&self) -> u64 {
        self.committee.total_weight() * THRESHOLD_NUMERATOR / THRESHOLD_DENOMINATOR
    }

    async fn build_certificate_submission_transaction(
        &self,
        cert: &CertificateV1,
    ) -> Result<Transaction, TobError> {
        let sender = self.signer.public_key().derive_address();
        let CertificateV1::Dkg(dkg_cert) = cert else {
            return Err(TobError::InvalidCertificate(
                "Rotation certificates not supported yet".into(),
            ));
        };
        let message = dkg_cert.message();
        let dealer = message.dealer_address;
        let message_hash = message.message_hash.inner().to_vec();
        let epoch = dkg_cert.epoch();
        let signature = dkg_cert.signature_bytes().to_vec();
        let signers_bitmap = dkg_cert.signers_bitmap_bytes().to_vec();
        let mut client = self.onchain_state.client();
        let hashi_id = self.onchain_state.hashi_id();
        let price = client
            .get_reference_gas_price()
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?;
        let gas_objects = client
            .select_coins(&sender, &StructTag::sui().into(), GAS_BUDGET, &[])
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?;
        let gas_object: ObjectReference = (&gas_objects[0].object_reference())
            .try_into()
            .map_err(|e| TobError::RpcError(format!("{e:?}")))?;
        let hashi_obj = client
            .ledger_client()
            .get_object(
                sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&hashi_id)
                    .with_read_mask(FieldMask::from_paths(["object_id", "owner"])),
            )
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?
            .into_inner();
        let pt = self.build_dkg_cert_submission_ptb(
            hashi_obj.object().owner().version(),
            epoch,
            dealer,
            message_hash,
            signature,
            signers_bitmap,
        )?;
        Ok(Transaction {
            kind: TransactionKind::ProgrammableTransaction(pt),
            sender,
            gas_payment: GasPayment {
                objects: vec![gas_object],
                owner: sender,
                price,
                budget: GAS_BUDGET,
            },
            expiration: TransactionExpiration::None,
        })
    }

    fn build_dkg_cert_submission_ptb(
        &self,
        hashi_initial_shared_version: u64,
        epoch: u64,
        dealer: Address,
        message_hash: Vec<u8>,
        signature: Vec<u8>,
        signers_bitmap: Vec<u8>,
    ) -> Result<ProgrammableTransaction, TobError> {
        let hashi_id = self.onchain_state.hashi_id();
        let package_id = self
            .onchain_state
            .package_id()
            .ok_or_else(|| TobError::InvalidState("no package id available".into()))?;
        Ok(ProgrammableTransaction {
            inputs: vec![
                Input::Shared(SharedInput::new(
                    hashi_id,
                    hashi_initial_shared_version,
                    true,
                )),
                Input::Pure(
                    epoch
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                ),
                Input::Pure(
                    dealer
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                ),
                Input::Pure(
                    message_hash
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                ),
                Input::Pure(
                    signature
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                ),
                Input::Pure(
                    signers_bitmap
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                ),
            ],
            commands: vec![Command::MoveCall(MoveCall {
                package: package_id,
                module: Identifier::from_static("cert_submission"),
                function: Identifier::from_static("submit_dkg_cert"),
                type_arguments: vec![],
                arguments: vec![
                    Argument::Input(0),
                    Argument::Input(1),
                    Argument::Input(2),
                    Argument::Input(3),
                    Argument::Input(4),
                    Argument::Input(5),
                ],
            })],
        })
    }

    /// Fetches all certificates in insertion order by following the LinkedTable's linked list.
    async fn fetch_all_certificates(&self) -> Result<Vec<(Address, CertificateV1)>, TobError> {
        let raw_certs = self
            .onchain_state
            .fetch_dkg_certs(self.epoch)
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?;
        let mut certificates = Vec::with_capacity(raw_certs.len());
        for (dealer, dkg_cert) in raw_certs {
            let inner_cert = DkgDealerMessageHash::from_onchain_cert(
                &dkg_cert,
                self.epoch,
                &self.committee,
                self.threshold(),
            )
            .map_err(|e| TobError::InvalidCertificate(e.to_string()))?;
            certificates.push((dealer, CertificateV1::Dkg(inner_cert)));
        }
        Ok(certificates)
    }
}

#[async_trait]
impl OrderedBroadcastChannel<CertificateV1> for SuiTobChannel {
    async fn publish(&self, cert: CertificateV1) -> ChannelResult<()> {
        let tx = self
            .build_certificate_submission_transaction(&cert)
            .await
            .map_err(ChannelError::from)?;
        let signature = self
            .signer
            .sign_transaction(&tx)
            .map_err(|e| ChannelError::Other(e.to_string()))?;
        let mut client = self.onchain_state.client();
        let response = client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(tx.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_paths(["effects.status"])),
                TX_CONFIRMATION_TIMEOUT,
            )
            .await
            .map_err(|e| ChannelError::Other(e.to_string()))?
            .into_inner();
        if !response.transaction().effects().status().success() {
            return Err(ChannelError::Other(format!(
                "Transaction failed: {:?}",
                response.transaction().effects().status()
            )));
        }
        Ok(())
    }

    async fn receive(&mut self) -> ChannelResult<CertificateV1> {
        loop {
            if let Some(cert) = self.pending_certs.pop_front() {
                return Ok(cert);
            }
            // TODO: Optimize by checking table size first to avoid redundant fetches.
            let all_certs = self
                .fetch_all_certificates()
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
