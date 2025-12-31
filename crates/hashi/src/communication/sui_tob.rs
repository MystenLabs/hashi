//! Sui-backed Total Order Broadcast (TOB) Channel

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use sui_crypto::SuiSigner;
use sui_crypto::ed25519::Ed25519PrivateKey;
use sui_rpc::Client;
use sui_rpc::field::{FieldMask, FieldMaskUtil};
use sui_rpc::proto::sui::rpc::v2::{
    DynamicField, ExecuteTransactionRequest, ListDynamicFieldsRequest,
};
use sui_sdk_types::bcs::ToBcs;
use sui_sdk_types::{
    Address, Argument, Command, GasPayment, Identifier, Input, MoveCall, ObjectReference,
    ProgrammableTransaction, StructTag, Transaction, TransactionExpiration, TransactionKind,
};
use tap::Pipe;
use thiserror::Error;

use crate::committee::Committee;
use crate::dkg::types::{Certificate, DkgDealerMessageHash, MpcMessageV1};
use crate::onchain::move_types::{DkgCertV1, EpochCerts, EpochCertsKey, LinkedTableNode};

use super::{ChannelError, ChannelResult, OrderedBroadcastChannel};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const GAS_BUDGET: u64 = 50_000_000;

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
}

// This will be irrelevant after the trait `OrderedBroadcastChannel` is removed.
impl From<TobError> for ChannelError {
    fn from(e: TobError) -> Self {
        match e {
            TobError::RpcError(msg) => ChannelError::Other(msg),
            TobError::TransactionFailed(msg) => ChannelError::Other(msg),
            _ => ChannelError::Other(e.to_string()),
        }
    }
}

pub struct SuiTobChannel {
    client: Client,
    package_id: Address,
    hashi_id: Address,
    epoch: u64,
    signer: Ed25519PrivateKey,
    /// Dealers we've already returned certificates for
    seen_dealers: HashSet<Address>,
    /// Cached certificates not yet returned
    pending_certs: VecDeque<Certificate>,
    committee: Committee,
}

// TODO: Read threshold from on-chain config once it is made configurable.
const THRESHOLD_NUMERATOR: u64 = 2;
const THRESHOLD_DENOMINATOR: u64 = 3;

impl SuiTobChannel {
    pub fn new(
        client: Client,
        package_id: Address,
        hashi_id: Address,
        epoch: u64,
        signer: Ed25519PrivateKey,
        committee: Committee,
    ) -> Self {
        Self {
            client,
            package_id,
            hashi_id,
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
        &mut self,
        cert: &Certificate,
    ) -> Result<Transaction, TobError> {
        let sender = self.signer.public_key().derive_address();
        let (dealer, message_hash) = match cert.message() {
            MpcMessageV1::Dkg(DkgDealerMessageHash {
                dealer_address,
                message_hash,
            }) => (*dealer_address, message_hash.to_vec()),
            MpcMessageV1::Rotation(_) => {
                return Err(TobError::InvalidCertificate(
                    "Rotation certificates not supported yet".into(),
                ));
            }
        };
        let epoch = cert.epoch();
        let signature = cert.signature_bytes().to_vec();
        let signers_bitmap = cert.signers_bitmap_bytes().to_vec();
        let price = self
            .client
            .get_reference_gas_price()
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?;
        let gas_objects = self
            .client
            .select_coins(&sender, &StructTag::sui().into(), GAS_BUDGET, &[])
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?;
        let gas_object: ObjectReference = (&gas_objects[0].object_reference())
            .try_into()
            .map_err(|e| TobError::RpcError(format!("{e:?}")))?;
        let hashi_obj = self
            .client
            .ledger_client()
            .get_object(
                sui_rpc::proto::sui::rpc::v2::GetObjectRequest::new(&self.hashi_id)
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
        Ok(ProgrammableTransaction {
            inputs: vec![
                Input::Shared {
                    object_id: self.hashi_id,
                    initial_shared_version: hashi_initial_shared_version,
                    mutable: true,
                },
                Input::Pure {
                    value: epoch
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                },
                Input::Pure {
                    value: dealer
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                },
                Input::Pure {
                    value: message_hash
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                },
                Input::Pure {
                    value: signature
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                },
                Input::Pure {
                    value: signers_bitmap
                        .to_bcs()
                        .map_err(|e| TobError::SerializationError(e.to_string()))?,
                },
            ],
            commands: vec![Command::MoveCall(MoveCall {
                package: self.package_id,
                module: Identifier::new("cert_submission").unwrap(),
                function: Identifier::new("submit_dkg_cert").unwrap(),
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

    async fn fetch_epoch_certs(&self) -> Result<Option<EpochCerts>, TobError> {
        let epoch_key = EpochCertsKey { epoch: self.epoch };
        let epoch_key_bcs =
            bcs::to_bytes(&epoch_key).map_err(|e| TobError::SerializationError(e.to_string()))?;
        let mut stream = self
            .client
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(self.hashi_id)
                    .with_page_size(u32::MAX)
                    .with_read_mask(FieldMask::from_paths([
                        DynamicField::path_builder().name().finish(),
                        DynamicField::path_builder().value().finish(),
                    ])),
            )
            .pipe(Box::pin);
        while let Some(field) = stream
            .try_next()
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?
        {
            if field.name().value() == epoch_key_bcs.as_slice() {
                let epoch_certs: EpochCerts = field
                    .value()
                    .deserialize()
                    .map_err(|e| TobError::SerializationError(e.to_string()))?;
                return Ok(Some(epoch_certs));
            }
        }
        Ok(None)
    }

    /// Fetches all certificates in insertion order by following the LinkedTable's linked list.
    async fn fetch_all_certificates(&self) -> Result<Vec<(Address, Certificate)>, TobError> {
        let epoch_certs = match self.fetch_epoch_certs().await? {
            Some(certs) => certs,
            None => return Ok(vec![]),
        };
        let Some(head) = epoch_certs.dkg_certs.head else {
            return Ok(vec![]);
        };
        let mut nodes: HashMap<Address, LinkedTableNode<Address, DkgCertV1>> = HashMap::new();
        let mut stream = self
            .client
            .list_dynamic_fields(
                ListDynamicFieldsRequest::default()
                    .with_parent(epoch_certs.dkg_certs.id)
                    .with_page_size(u32::MAX)
                    .with_read_mask(FieldMask::from_paths([
                        DynamicField::path_builder().name().finish(),
                        DynamicField::path_builder().value().finish(),
                    ])),
            )
            .pipe(Box::pin);
        while let Some(field) = stream
            .try_next()
            .await
            .map_err(|e| TobError::RpcError(e.to_string()))?
        {
            let dealer: Address = field
                .name()
                .deserialize()
                .map_err(|e| TobError::SerializationError(e.to_string()))?;
            let node: LinkedTableNode<Address, DkgCertV1> = field
                .value()
                .deserialize()
                .map_err(|e| TobError::SerializationError(e.to_string()))?;
            nodes.insert(dealer, node);
        }
        let mut certificates = Vec::with_capacity(nodes.len());
        let mut current = Some(head);
        while let Some(dealer) = current {
            let Some(node) = nodes.remove(&dealer) else {
                break; // Shouldn't happen, but handle gracefully
            };
            let cert = self.convert_to_internal_cert(dealer, node.value)?;
            certificates.push((dealer, cert));
            current = node.next;
        }
        Ok(certificates)
    }

    fn convert_to_internal_cert(
        &self,
        dealer: Address,
        dkg_cert: DkgCertV1,
    ) -> Result<Certificate, TobError> {
        let message = MpcMessageV1::Dkg(DkgDealerMessageHash {
            dealer_address: dealer,
            message_hash: dkg_cert
                .message_hash
                .try_into()
                .map_err(|_| TobError::InvalidCertificate("invalid message_hash length".into()))?,
        });
        Certificate::from_parts(
            self.epoch,
            message,
            &dkg_cert.signature,
            &dkg_cert.signers_bitmap,
            &self.committee,
            self.threshold(),
        )
        .map_err(|e| TobError::InvalidCertificate(e.to_string()))
    }
}

#[async_trait]
impl OrderedBroadcastChannel<Certificate> for SuiTobChannel {
    async fn publish(&self, cert: Certificate) -> ChannelResult<()> {
        // Clone needed because sui_rpc::Client methods require &mut self,
        // but OrderedBroadcastChannel::publish takes &self.
        let mut channel = SuiTobChannel {
            client: self.client.clone(),
            package_id: self.package_id,
            hashi_id: self.hashi_id,
            epoch: self.epoch,
            signer: self.signer.clone(),
            seen_dealers: HashSet::new(),
            pending_certs: VecDeque::new(),
            committee: self.committee.clone(),
        };
        let tx = channel
            .build_certificate_submission_transaction(&cert)
            .await
            .map_err(ChannelError::from)?;
        let signature = self
            .signer
            .sign_transaction(&tx)
            .map_err(|e| ChannelError::Other(e.to_string()))?;
        let response = channel
            .client
            .execute_transaction_and_wait_for_checkpoint(
                ExecuteTransactionRequest::new(tx.into())
                    .with_signatures(vec![signature.into()])
                    .with_read_mask(FieldMask::from_paths(["effects.status"])),
                Duration::from_secs(30),
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

    async fn receive(&mut self) -> ChannelResult<Certificate> {
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
