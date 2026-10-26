// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy checks each withdrawal against its committed Sui transaction.
//!
//! Why it exists:
//! The enclave checks only the committee certificate on a withdrawal. A
//! compromised committee can certify UTXOs that Move never committed. The
//! guardian limiter bounds that loss, but it does not stop it.
//!
//! How it works:
//! 1. Read the `WithdrawalTransaction` object whose id is the request `wid`.
//! 2. Require the object type from the Hashi package.
//! 3. Build the UTXOs from the object with `TxUTXOs::from_withdrawal_txn`.
//!    Nodes build their request with the same function.
//! 4. Forward the request only when its UTXOs are equal to those UTXOs.
//!
//! Assumptions:
//! - Move commits the object before the leader asks the guardian to sign.
//! - The original Hashi package defines `WithdrawalTransaction`.
//! - The wid log replay runs before this check. Thus the proxy can replay a
//!   signed withdrawal after Sui archives its object.
//! - The enclave checks `timestamp_secs`, `seq` and the certificate. Sui
//!   does not store them.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bitcoin::Network;
use hashi_types::bitcoin::TxUTXOs;
use hashi_types::bitcoin::TxUTXOsWire;
use hashi_types::guardian::WithdrawalID;
use hashi_types::move_types;
use hashi_types::proto;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use tonic::Status;
use tracing::warn;

use crate::metrics::ProxyMetrics;
use crate::node::members::ChainSource;

/// Nodes retry a slow withdrawal, so a stalled fullnode must not hold it open.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

#[tonic::async_trait]
pub trait WithdrawalSource: Send + Sync + 'static {
    /// Read the committed withdrawal transaction with this id.
    async fn withdrawal_txn(
        &self,
        wid: WithdrawalID,
    ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>>;
}

pub struct WithdrawalGate {
    source: Box<dyn WithdrawalSource>,
    network: Network,
    metrics: Arc<ProxyMetrics>,
}

impl WithdrawalGate {
    pub fn new(
        source: impl WithdrawalSource,
        network: Network,
        metrics: Arc<ProxyMetrics>,
    ) -> Self {
        Self {
            source: Box::new(source),
            network,
            metrics,
        }
    }

    /// Require the request UTXOs to equal those of the committed transaction.
    pub async fn admit(
        &self,
        request: &proto::SignedStandardWithdrawalRequest,
    ) -> Result<(), Status> {
        self.check(request).await.map_err(|refusal| {
            self.metrics
                .withdrawal_refused
                .with_label_values(&[refusal.reason()])
                .inc();
            refusal.status()
        })
    }

    async fn check(&self, request: &proto::SignedStandardWithdrawalRequest) -> Result<(), Refusal> {
        let (wid, requested) = self.parse(request).ok_or(Refusal::Malformed)?;
        let txn = tokio::time::timeout(LOOKUP_TIMEOUT, self.source.withdrawal_txn(wid))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("timed out after {LOOKUP_TIMEOUT:?}")))
            .map_err(|e| {
                warn!(%wid, error = %format!("{e:#}"), "Withdrawal transaction read failed.");
                Refusal::ChainUnavailable
            })?
            .ok_or(Refusal::NotOnChain(wid))?;
        let committed = TxUTXOs::from_withdrawal_txn(&txn, self.network).map_err(|e| {
            warn!(%wid, error = %format!("{e:#}"), "Cannot build the committed withdrawal UTXOs.");
            Refusal::CommittedInvalid
        })?;
        if requested != committed {
            warn!(%wid, "Refusing withdrawal UTXOs that differ from Sui.");
            return Err(Refusal::UtxoMismatch);
        }
        Ok(())
    }

    /// The request wid and UTXOs, checked against the network as the enclave does.
    fn parse(
        &self,
        request: &proto::SignedStandardWithdrawalRequest,
    ) -> Option<(WithdrawalID, TxUTXOs)> {
        let data = request.data.as_ref()?;
        let wid = WithdrawalID::from_bytes(data.wid.as_ref()?.as_ref()).ok()?;
        let wire = TxUTXOsWire::try_from(data.utxos.clone()?).ok()?;
        let utxos = TxUTXOs::new(wire.inputs, wire.outputs, self.network).ok()?;
        Some((wid, utxos))
    }
}

#[derive(Clone, Copy, Debug)]
enum Refusal {
    Malformed,
    /// No Hashi withdrawal transaction has this id yet, or the read is stale.
    NotOnChain(WithdrawalID),
    UtxoMismatch,
    /// The proxy cannot build UTXOs from the committed transaction. Check
    /// `BTC_NETWORK`.
    CommittedInvalid,
    ChainUnavailable,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::NotOnChain(_) => "not_on_chain",
            Self::UtxoMismatch => "utxo_mismatch",
            Self::CommittedInvalid => "committed_invalid",
            Self::ChainUnavailable => "chain_unavailable",
        }
    }

    /// Do not use `ABORTED` or `RESOURCE_EXHAUSTED`. Nodes read them as a seq
    /// mismatch or a rate limit (`leader/guardian.rs`).
    fn status(self) -> Status {
        match self {
            Self::Malformed => Status::invalid_argument("malformed withdrawal request"),
            Self::NotOnChain(wid) => Status::unavailable(format!(
                "no withdrawal transaction {wid} is committed on chain yet; retry"
            )),
            Self::UtxoMismatch => Status::failed_precondition(
                "request UTXOs differ from the withdrawal transaction committed on Sui",
            ),
            Self::CommittedInvalid => Status::failed_precondition(
                "the proxy cannot build UTXOs from the withdrawal transaction committed on Sui",
            ),
            Self::ChainUnavailable => {
                Status::unavailable("committed withdrawals unavailable; retry")
            }
        }
    }
}

#[tonic::async_trait]
impl WithdrawalSource for ChainSource {
    async fn withdrawal_txn(
        &self,
        wid: WithdrawalID,
    ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
        read_withdrawal_txn(self.sui.clone(), self.hashi_package().await?, wid).await
    }
}

/// Read a Hashi `WithdrawalTransaction` from Sui. Return `None` for an object
/// of another type.
async fn read_withdrawal_txn(
    mut sui: sui_rpc::Client,
    hashi_package: Address,
    wid: WithdrawalID,
) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
    let request = GetObjectRequest::new(&wid).with_read_mask(FieldMask::from_paths([
        Object::path_builder().object_type(),
        Object::path_builder().contents().finish(),
    ]));
    let response = match sui.ledger_client().get_object(request).await {
        Ok(response) => response.into_inner(),
        Err(status) if status.code() == tonic::Code::NotFound => return Ok(None),
        Err(status) => {
            return Err(anyhow::Error::new(status).context(format!("get object {wid}")));
        }
    };
    let object = response.object();
    let object_type: StructTag = object
        .object_type_opt()
        .with_context(|| format!("object {wid} has no type"))?
        .parse()
        .with_context(|| format!("parse the type of object {wid}"))?;
    let expected = StructTag::new(
        hashi_package,
        Identifier::from_static("withdrawal_queue"),
        Identifier::from_static("WithdrawalTransaction"),
        vec![],
    );
    if object_type != expected {
        warn!(%wid, %object_type, "Object is not a Hashi withdrawal transaction.");
        return Ok(None);
    }
    let txn = object
        .contents()
        .deserialize()
        .with_context(|| format!("decode withdrawal transaction {wid}"))?;
    Ok(Some(txn))
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::*;
    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::guardian::proto_conversions::standard_withdrawal_request_wire_to_pb;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::StandardWithdrawalRequestWire;

    pub(crate) const NETWORK: Network = Network::Regtest;

    /// A chain where every wid is a committed `txn(wid)`.
    struct AllCommitted;

    #[tonic::async_trait]
    impl WithdrawalSource for AllCommitted {
        async fn withdrawal_txn(
            &self,
            wid: WithdrawalID,
        ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
            Ok(Some(txn(wid)))
        }
    }

    /// A gate over a chain where every wid is a committed `txn(wid)`.
    pub(crate) fn all_committed() -> Arc<WithdrawalGate> {
        Arc::new(WithdrawalGate::new(
            AllCommitted,
            NETWORK,
            Arc::new(ProxyMetrics::new()),
        ))
    }

    /// A withdrawal transaction with one input, one payout and one change output.
    pub(crate) fn txn(wid: WithdrawalID) -> move_types::WithdrawalTransaction {
        let output = |amount, bitcoin_address| move_types::OutputUtxo {
            amount,
            bitcoin_address,
        };
        move_types::WithdrawalTransaction {
            id: wid,
            txid: BitcoinTxid::new([0; 32]),
            request_ids: vec![Address::new([1; 32])],
            inputs: vec![move_types::Utxo {
                id: move_types::UtxoId {
                    txid: BitcoinTxid::new([2; 32]),
                    vout: 0,
                },
                amount: 100_000,
                derivation_path: Some(Address::new([3; 32])),
            }],
            withdrawal_outputs: vec![output(60_000, vec![4; 20])],
            change_outputs: vec![output(39_000, vec![5; 32])],
            created_timestamp_ms: 0,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: move_types::SigningBatch {
                signatures: vec![],
                epoch: 0,
            },
            guardian_signatures: None,
        }
    }

    /// A request for `txn` at `seq`, without a certificate.
    pub(crate) fn request(
        txn: &move_types::WithdrawalTransaction,
        seq: u64,
    ) -> proto::SignedStandardWithdrawalRequest {
        let utxos = TxUTXOs::from_withdrawal_txn(txn, NETWORK).unwrap();
        let request = StandardWithdrawalRequest::new(txn.id, utxos, 100, seq);
        proto::SignedStandardWithdrawalRequest {
            data: Some(standard_withdrawal_request_wire_to_pb(
                StandardWithdrawalRequestWire::from(request),
            )),
            committee_signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_utils::request;
    use super::test_utils::txn;
    use super::test_utils::NETWORK;
    use super::*;
    use std::collections::HashMap;
    use tonic::Code;

    /// A chain that stores these transactions.
    struct Stored(HashMap<WithdrawalID, move_types::WithdrawalTransaction>);

    #[tonic::async_trait]
    impl WithdrawalSource for Stored {
        async fn withdrawal_txn(
            &self,
            wid: WithdrawalID,
        ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
            Ok(self.0.get(&wid).cloned())
        }
    }

    /// Every read fails.
    struct Unreadable;

    #[tonic::async_trait]
    impl WithdrawalSource for Unreadable {
        async fn withdrawal_txn(
            &self,
            _: WithdrawalID,
        ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
            Err(anyhow::anyhow!("sui unavailable"))
        }
    }

    /// Never answers.
    struct Stuck;

    #[tonic::async_trait]
    impl WithdrawalSource for Stuck {
        async fn withdrawal_txn(
            &self,
            _: WithdrawalID,
        ) -> anyhow::Result<Option<move_types::WithdrawalTransaction>> {
            std::future::pending().await
        }
    }

    fn gate_over(source: impl WithdrawalSource) -> (WithdrawalGate, Arc<ProxyMetrics>) {
        let metrics = Arc::new(ProxyMetrics::new());
        (
            WithdrawalGate::new(source, NETWORK, metrics.clone()),
            metrics,
        )
    }

    fn stored(txns: &[move_types::WithdrawalTransaction]) -> Stored {
        Stored(txns.iter().map(|txn| (txn.id, txn.clone())).collect())
    }

    fn refused(metrics: &ProxyMetrics, reason: &str) -> u64 {
        metrics
            .withdrawal_refused
            .with_label_values(&[reason])
            .get()
    }

    fn wid(byte: u8) -> WithdrawalID {
        WithdrawalID::new([byte; 32])
    }

    #[tokio::test]
    async fn admits_only_the_committed_utxos() {
        let committed = txn(wid(1));
        let (gate, metrics) = gate_over(stored(&[committed.clone()]));
        gate.admit(&request(&committed, 0)).await.unwrap();

        // A quorum certifies a larger payout than Move committed.
        let mut altered = committed.clone();
        altered.withdrawal_outputs[0].amount += 1_000;
        altered.change_outputs[0].amount -= 1_000;
        let err = gate.admit(&request(&altered, 0)).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);

        // The same payout to another address.
        let mut altered = committed.clone();
        altered.withdrawal_outputs[0].bitcoin_address = vec![6; 20];
        let err = gate.admit(&request(&altered, 0)).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(refused(&metrics, "utxo_mismatch"), 2);

        // The UTXOs of one committed transaction under the wid of another.
        let mut other = committed.clone();
        other.id = wid(2);
        other.withdrawal_outputs[0].amount -= 1_000;
        other.change_outputs[0].amount += 500;
        let (gate, metrics) = gate_over(stored(&[committed.clone(), other]));
        let mut swapped = request(&committed, 0);
        swapped.data.as_mut().unwrap().wid = Some(Vec::from(wid(2)).into());
        let err = gate.admit(&swapped).await.unwrap_err();
        assert_eq!(err.code(), Code::FailedPrecondition);
        assert_eq!(refused(&metrics, "utxo_mismatch"), 1);
    }

    #[tokio::test]
    async fn refuses_an_uncommitted_wid_as_retriable() {
        let (gate, metrics) = gate_over(stored(&[]));
        let err = gate.admit(&request(&txn(wid(1)), 0)).await.unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "not_on_chain"), 1);
    }

    #[tokio::test]
    async fn refuses_a_malformed_request() {
        let (gate, metrics) = gate_over(stored(&[]));
        let mut no_utxos = request(&txn(wid(1)), 0);
        no_utxos.data.as_mut().unwrap().utxos = None;
        let err = gate.admit(&no_utxos).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert_eq!(refused(&metrics, "malformed"), 1);
    }

    #[tokio::test]
    async fn fails_closed_when_sui_cannot_answer() {
        let (gate, metrics) = gate_over(Unreadable);
        let err = gate.admit(&request(&txn(wid(1)), 0)).await.unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "chain_unavailable"), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn times_out_a_stuck_read() {
        let (gate, metrics) = gate_over(Stuck);
        let err = gate.admit(&request(&txn(wid(1)), 0)).await.unwrap_err();
        assert_eq!(err.code(), Code::Unavailable);
        assert_eq!(refused(&metrics, "chain_unavailable"), 1);
    }
}
