// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Live membership lookups against the on-chain `spent_utxos` bag.
//!
//! The bag holds one `UtxoId -> spent_epoch` tombstone per UTXO the
//! bridge has ever spent, kept permanently as replay protection. It
//! only grows, and on a busy network it runs to millions of entries,
//! so the object mirror deliberately does not track it (see
//! `route::Slot::SpentUtxos`). The two replay checks that need
//! membership — approving a deposit and confirming an approved one —
//! ask the fullnode for the single entry instead.

use anyhow::Result;
use sui_rpc::Client;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::ToBcs;

use super::types::UtxoId;

/// Whether the `spent_utxos` bag holds an entry for `utxo_id`.
///
/// A bag entry is a dynamic field whose object id derives from the bag
/// id and the BCS-encoded key, so one `GetObject` decides membership:
/// an object means spent, `NotFound` means not spent, and any other
/// status is an error for the caller to retry. A wrong "not spent"
/// costs one rejected transaction, never a double-spend — every entry
/// function that inserts a UTXO re-checks the bag itself.
pub(super) async fn lookup_spent_utxo(
    mut client: Client,
    spent_utxos_id: Address,
    package_id: Address,
    utxo_id: &UtxoId,
) -> Result<bool> {
    let field_id = spent_utxo_field_id(spent_utxos_id, package_id, utxo_id);
    let response = client
        .ledger_client()
        .get_object(
            GetObjectRequest::new(&field_id)
                .with_read_mask(FieldMask::from_paths([Object::path_builder().object_id()])),
        )
        .await;
    match response {
        Ok(_) => Ok(true),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(false),
        Err(status) => Err(anyhow::Error::new(status).context(format!(
            "failed to look up the spent_utxos entry for {utxo_id:?}"
        ))),
    }
}

/// The derived object id of the `spent_utxos` bag entry keyed by
/// `utxo_id`. The key type is `utxo::UtxoId` from the original package:
/// a struct keeps its defining package's address through upgrades.
fn spent_utxo_field_id(spent_utxos_id: Address, package_id: Address, utxo_id: &UtxoId) -> Address {
    let key_type = TypeTag::Struct(Box::new(StructTag::new(
        package_id,
        Identifier::from_static("utxo"),
        Identifier::from_static("UtxoId"),
        vec![],
    )));
    spent_utxos_id.derive_dynamic_child_id(
        &key_type,
        &utxo_id
            .to_bcs()
            .expect("UtxoId BCS serialization cannot fail"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::Mutex;

    use hashi_types::bitcoin_txid::BitcoinTxid;
    use sui_rpc::proto::sui::rpc::v2::GetObjectResponse;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerService;
    use sui_rpc::proto::sui::rpc::v2::ledger_service_server::LedgerServiceServer;

    fn addr(byte: u8) -> Address {
        Address::from_bytes([byte; 32]).unwrap()
    }

    fn utxo_id(byte: u8, vout: u32) -> UtxoId {
        UtxoId {
            txid: BitcoinTxid::from(addr(byte)),
            vout,
        }
    }

    /// A ledger that knows one object id and answers everything else
    /// with the configured status, recording what it was asked for.
    #[derive(Clone)]
    struct OneObjectLedger {
        known: Address,
        miss: tonic::Code,
        asked: Arc<Mutex<Vec<String>>>,
    }

    #[tonic::async_trait]
    impl LedgerService for OneObjectLedger {
        async fn get_object(
            &self,
            request: tonic::Request<GetObjectRequest>,
        ) -> Result<tonic::Response<GetObjectResponse>, tonic::Status> {
            let object_id = request.into_inner().object_id.unwrap_or_default();
            self.asked.lock().unwrap().push(object_id.clone());
            if object_id != self.known.to_string() {
                return Err(tonic::Status::new(self.miss, "no such object"));
            }
            let mut object = Object::default();
            object.object_id = Some(object_id);
            Ok(tonic::Response::new(GetObjectResponse::new(object)))
        }
    }

    async fn spawn_ledger(ledger: OneObjectLedger) -> Client {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = futures::stream::unfold(listener, |listener| async move {
            let result = listener.accept().await.map(|(stream, _)| stream);
            Some((result, listener))
        });
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(LedgerServiceServer::new(ledger))
                .serve_with_incoming(incoming),
        );
        Client::new(format!("http://{addr}").as_str()).unwrap()
    }

    #[test]
    fn field_id_depends_on_bag_key_and_package() {
        let base = spent_utxo_field_id(addr(0x10), addr(0xAA), &utxo_id(0x77, 0));
        assert_ne!(
            base,
            spent_utxo_field_id(addr(0x11), addr(0xAA), &utxo_id(0x77, 0))
        );
        assert_ne!(
            base,
            spent_utxo_field_id(addr(0x10), addr(0xAB), &utxo_id(0x77, 0))
        );
        assert_ne!(
            base,
            spent_utxo_field_id(addr(0x10), addr(0xAA), &utxo_id(0x77, 1))
        );
        assert_eq!(
            base,
            spent_utxo_field_id(addr(0x10), addr(0xAA), &utxo_id(0x77, 0))
        );
    }

    #[tokio::test]
    async fn present_entry_is_spent_and_missing_entry_is_not() {
        let spent_utxos_id = addr(0x10);
        let package_id = addr(0xAA);
        let spent = utxo_id(0x77, 0);
        let unspent = utxo_id(0x77, 1);
        let ledger = OneObjectLedger {
            known: spent_utxo_field_id(spent_utxos_id, package_id, &spent),
            miss: tonic::Code::NotFound,
            asked: Arc::default(),
        };
        let client = spawn_ledger(ledger.clone()).await;

        assert!(
            lookup_spent_utxo(client.clone(), spent_utxos_id, package_id, &spent)
                .await
                .unwrap()
        );
        assert!(
            !lookup_spent_utxo(client, spent_utxos_id, package_id, &unspent)
                .await
                .unwrap()
        );

        // Each answer came from exactly the derived entry id, not from
        // a listing or a guess.
        let asked = ledger.asked.lock().unwrap();
        assert_eq!(
            *asked,
            vec![
                spent_utxo_field_id(spent_utxos_id, package_id, &spent).to_string(),
                spent_utxo_field_id(spent_utxos_id, package_id, &unspent).to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn any_status_but_not_found_is_an_error() {
        let spent_utxos_id = addr(0x10);
        let package_id = addr(0xAA);
        let ledger = OneObjectLedger {
            known: addr(0xFF),
            miss: tonic::Code::Unavailable,
            asked: Arc::default(),
        };
        let client = spawn_ledger(ledger).await;

        let err = lookup_spent_utxo(client, spent_utxos_id, package_id, &utxo_id(0x77, 0))
            .await
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<tonic::Status>().map(|s| s.code()),
            Some(tonic::Code::Unavailable),
            "{err:#}"
        );
    }
}
