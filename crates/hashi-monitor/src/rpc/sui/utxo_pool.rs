// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Reads the Hashi UTXO pool from Sui.
//!
//! Why it exists: the UTXO reconciliation compares Move's view of the pool
//! with Bitcoin. Move keeps the pool in `utxo_records`, a `sui::bag::Bag`
//! inside the `BitcoinState` dynamic field of the Hashi object.
//!
//! How it works:
//! 1. The `BitcoinState` field id is derived once, at startup, from the Hashi
//!    object id and the original package id, the same way Move derives it.
//! 2. A read fetches that field and takes the `utxo_records` bag id from it.
//! 3. The read pages through the bag's dynamic fields and decodes each value
//!    as a `UtxoRecord`.
//!
//! Assumptions:
//! - `spent_utxos` is never walked. It only grows, and an id can enter it only
//!   through a committed withdrawal, which the withdrawal state machine
//!   already requires to confirm on Bitcoin.
//! - Pages are served from different checkpoints. A record inserted or
//!   removed during the walk can be missing or duplicated. The daily
//!   reconciliation tolerates that and reads again on its next run.
//! - A fullnode lists fields from its index and loads each object after. A
//!   field deleted in between comes back without its value. The read fails
//!   and the caller retries on its next run.

use std::future::Future;

use anyhow::Context;
use hashi_types::move_types::BitcoinState;
use hashi_types::move_types::BitcoinStateKey;
use hashi_types::move_types::Field;
use hashi_types::move_types::UtxoRecord;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::DynamicField;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::ToBcs;

use super::INITIAL_RETRY_DELAY;
use super::MAX_LOOKUP_ATTEMPTS;
use super::PAGE_SIZE;
use super::SuiEventsPoller;
use super::is_transient;

/// The id of the `BitcoinState` dynamic field of `hashi_object_id`. Move
/// attaches it under a `BitcoinStateKey` of the original package.
pub fn bitcoin_state_field_id(hashi_object_id: Address, package_id: Address) -> Address {
    let key = BitcoinStateKey { dummy_field: false };
    let key_type = TypeTag::Struct(Box::new(StructTag::new(
        package_id,
        Identifier::from_static("bitcoin_state"),
        Identifier::from_static("BitcoinStateKey"),
        vec![],
    )));
    let key_bytes = key.to_bcs().expect("a bool serializes");
    hashi_object_id.derive_dynamic_child_id(&key_type, &key_bytes)
}

impl SuiEventsPoller {
    /// Every record in the pool's `utxo_records` bag.
    pub async fn read_utxo_records(&mut self) -> anyhow::Result<Vec<UtxoRecord>> {
        let bag_id = self.utxo_records_bag_id().await?;
        // The fullnode returns empty entries for a mask of `value` alone.
        let mask = FieldMask::from_paths([
            DynamicField::path_builder().name().finish(),
            DynamicField::path_builder().value().finish(),
            DynamicField::path_builder().field_id(),
        ]);
        let mut records = Vec::new();
        let mut page_token = None;
        loop {
            let mut request = ListDynamicFieldsRequest::default()
                .with_parent(bag_id.to_string())
                .with_page_size(PAGE_SIZE)
                .with_read_mask(mask.clone());
            if let Some(token) = page_token.take() {
                request = request.with_page_token(token);
            }
            let client = &self.client;
            let page = with_transient_retries("Sui ListDynamicFields", || {
                let mut client = client.clone();
                let request = request.clone();
                async move { client.state_client().list_dynamic_fields(request).await }
            })
            .await?
            .into_inner();
            for field in &page.dynamic_fields {
                records.push(decode_record(field)?);
            }
            match page.next_page_token {
                Some(token) => page_token = Some(token),
                None => break,
            }
        }
        tracing::info!(records = records.len(), "read the UTXO pool from Sui");
        Ok(records)
    }

    /// The id of the `utxo_records` bag, read from the `BitcoinState` field.
    async fn utxo_records_bag_id(&mut self) -> anyhow::Result<Address> {
        let request =
            GetObjectRequest::new(&self.bitcoin_state_id).with_read_mask(FieldMask::from_paths([
                Object::path_builder().contents().finish(),
            ]));
        let client = &self.client;
        let response = with_transient_retries("Sui GetObject of BitcoinState", || {
            let mut client = client.clone();
            let request = request.clone();
            async move { client.ledger_client().get_object(request).await }
        })
        .await?;
        let field: Field<BitcoinStateKey, BitcoinState> = response
            .into_inner()
            .object()
            .contents()
            .deserialize()
            .context("failed to decode the Hashi BitcoinState")?;
        Ok(field.value.utxo_pool.utxo_records.id)
    }
}

/// The `UtxoRecord` a listed field holds.
fn decode_record(field: &DynamicField) -> anyhow::Result<UtxoRecord> {
    let value = field
        .value_opt()
        .filter(|bcs| !bcs.value().is_empty())
        .with_context(|| {
            format!(
                "utxo_records field {} was listed without its object (deleted mid-read)",
                field.field_id()
            )
        })?;
    value
        .deserialize()
        .with_context(|| format!("failed to decode UtxoRecord {}", field.field_id()))
}

/// Run `call`, retrying a transient gRPC failure with backoff.
async fn with_transient_retries<T, Fut>(
    what: &'static str,
    mut call: impl FnMut() -> Fut,
) -> anyhow::Result<T>
where
    Fut: Future<Output = Result<T, tonic::Status>>,
{
    let mut attempt = 0u32;
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(status) if attempt + 1 < MAX_LOOKUP_ATTEMPTS && is_transient(&status) => {
                let delay = INITIAL_RETRY_DELAY.saturating_mul(1 << attempt);
                attempt += 1;
                tracing::warn!(
                    what,
                    attempt,
                    ?delay,
                    ?status,
                    "Sui request failed; retrying"
                );
                tokio::time::sleep(delay).await;
            }
            Err(status) => return Err(status).with_context(|| format!("{what} failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::approval::tests::HASHI_OBJECT_ID;
    use super::super::approval::tests::PACKAGE_ID;
    use super::super::tests::poller_for_router;
    use super::*;

    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;

    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::Utxo;
    use hashi_types::move_types::UtxoId;
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::ListDynamicFieldsResponse;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateService;
    use sui_rpc::proto::sui::rpc::v2::state_service_server::StateServiceServer;

    const RECORDS_BAG_ID: Address = Address::new([0x33; 32]);

    /// The `UtxoRecord` BCS of a confirmed deposit, with `fill` in every field.
    fn record_bcs(fill: u8) -> Bcs {
        // `UtxoRecord` fields in declaration order.
        Bcs::serialize(&(
            Utxo {
                id: UtxoId {
                    txid: BitcoinTxid::from(Address::new([fill; 32])),
                    vout: fill as u32,
                },
                amount: 1_000 * fill as u64,
                derivation_path: None,
            },
            None::<Address>,
            None::<Address>,
            None::<u64>,
        ))
        .unwrap()
    }

    /// The `BitcoinState` field object of `HASHI_OBJECT_ID`, whose
    /// `utxo_records` bag is `RECORDS_BAG_ID`.
    fn bitcoin_state_object() -> Object {
        let bag = |fill: u8| (Address::new([fill; 32]), 0u64);
        // `BitcoinState` fields in declaration order. Each queue is its bags
        // in order, and each bag or table is `(id, size)`.
        let state = (
            Address::new([0x30; 32]),
            (bag(0x41), bag(0x42)),
            (bag(0x43), bag(0x44), bag(0x45), bag(0x46)),
            ((RECORDS_BAG_ID, 3u64), bag(0x48)),
            bag(0x49),
        );
        let field_id = bitcoin_state_field_id(HASHI_OBJECT_ID, PACKAGE_ID);
        let mut object = Object::default();
        object.object_id = Some(field_id.to_string());
        object.contents = Some(Bcs::serialize(&(field_id, false, state)).unwrap());
        object
    }

    /// A fullnode serving the `BitcoinState` field and its `utxo_records`
    /// bag, `page_size` records a page. Each listing first fails with the
    /// next of `failures`, if any.
    #[derive(Clone)]
    struct PoolLedger {
        records: Vec<Bcs>,
        page_size: usize,
        failures: Arc<Mutex<VecDeque<tonic::Code>>>,
        listings: Arc<Mutex<u32>>,
    }

    impl PoolLedger {
        fn new(records: Vec<Bcs>, page_size: usize) -> Self {
            Self {
                records,
                page_size,
                failures: Arc::default(),
                listings: Arc::default(),
            }
        }

        fn failing_first_with(self, failures: impl IntoIterator<Item = tonic::Code>) -> Self {
            *self.failures.lock().unwrap() = failures.into_iter().collect();
            self
        }
    }

    #[tonic::async_trait]
    impl LedgerService for PoolLedger {
        async fn get_object(
            &self,
            request: tonic::Request<GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            let state = bitcoin_state_object();
            if request.into_inner().object_id != state.object_id {
                return Err(tonic::Status::not_found("no such object"));
            }
            Ok(tonic::Response::new(GetObjectResponse::new(state)))
        }
    }

    #[tonic::async_trait]
    impl StateService for PoolLedger {
        async fn list_dynamic_fields(
            &self,
            request: tonic::Request<ListDynamicFieldsRequest>,
        ) -> Result<tonic::Response<ListDynamicFieldsResponse>, tonic::Status> {
            *self.listings.lock().unwrap() += 1;
            if let Some(code) = self.failures.lock().unwrap().pop_front() {
                return Err(tonic::Status::new(code, "injected failure"));
            }
            let request = request.into_inner();
            if request.parent() != RECORDS_BAG_ID.to_string() {
                return Err(tonic::Status::not_found("no such parent"));
            }
            let start = request
                .page_token_opt()
                .map(|token| usize::from_le_bytes(token.try_into().unwrap()))
                .unwrap_or(0);
            let end = (start + self.page_size).min(self.records.len());
            let mut response = ListDynamicFieldsResponse::default();
            for (index, value) in self.records[start..end].iter().enumerate() {
                let mut field = DynamicField::default();
                field.field_id = Some(Address::new([(start + index) as u8; 32]).to_string());
                field.name = Some(Bcs::serialize(&(start + index)).unwrap());
                field.value = Some(value.clone());
                response.dynamic_fields.push(field);
            }
            if end < self.records.len() {
                response.next_page_token = Some(end.to_le_bytes().to_vec().into());
            }
            Ok(tonic::Response::new(response))
        }
    }

    async fn poller_over(ledger: PoolLedger) -> SuiEventsPoller {
        poller_for_router(
            tonic::transport::Server::builder()
                .add_service(LedgerServiceServer::new(ledger.clone()))
                .add_service(StateServiceServer::new(ledger)),
        )
        .await
    }

    #[tokio::test]
    async fn records_are_read_across_pages() {
        let ledger = PoolLedger::new(vec![record_bcs(1), record_bcs(2), record_bcs(3)], 2);
        let mut poller = poller_over(ledger.clone()).await;

        let records = poller.read_utxo_records().await.unwrap();

        let vouts: Vec<u32> = records.iter().map(|record| record.utxo.id.vout).collect();
        assert_eq!(vouts, vec![1, 2, 3]);
        assert_eq!(records[2].utxo.amount, 3_000);
        assert!(records.iter().all(|record| record.spent_epoch.is_none()));
        assert_eq!(*ledger.listings.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_field_listed_without_its_object_fails_the_read() {
        let ledger = PoolLedger::new(vec![record_bcs(1), Bcs::from(Vec::new())], 10);
        let mut poller = poller_over(ledger).await;

        let error = poller.read_utxo_records().await.unwrap_err();

        assert!(error.to_string().contains("deleted mid-read"), "{error:#}");
    }

    #[tokio::test]
    async fn a_transient_listing_failure_is_retried() {
        let ledger =
            PoolLedger::new(vec![record_bcs(1)], 10).failing_first_with([tonic::Code::Unavailable]);
        let mut poller = poller_over(ledger.clone()).await;

        let records = poller.read_utxo_records().await.unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(*ledger.listings.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn a_missing_bitcoin_state_fails_the_read() {
        let ledger = PoolLedger::new(vec![], 10);
        let mut poller = poller_over(ledger).await;
        // Point the poller at a field the ledger does not hold.
        poller.bitcoin_state_id = bitcoin_state_field_id(Address::new([0x99; 32]), PACKAGE_ID);

        let error = poller.read_utxo_records().await.unwrap_err();

        assert!(error.to_string().contains("BitcoinState"), "{error:#}");
    }
}
