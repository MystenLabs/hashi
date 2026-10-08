// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Parsing of the Hashi approvals that the monitor reads from Sui.
//!
//! Why it exists: what the monitor accepts as a Hashi approval is security
//! sensitive, so it lives apart from the checkpoint scanning and RPC
//! transport in `mod.rs`.
//!
//! How it works:
//! - `parse_event` turns a scanned Sui event into a monitor event.
//! - `parse_withdrawal_object` turns a fetched `WithdrawalTransaction` object
//!   into the Hashi approval it records.
//!
//! Assumptions:
//! - An approval comes from a `WithdrawalPickedForProcessing` event or from the
//!   `WithdrawalTransaction` object created with it. Both carry the same txid
//!   and timestamp.

use anyhow::Context;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::MoveType;
use hashi_types::move_types::PackageVersions;
use hashi_types::move_types::WithdrawalTransaction;
use sui_rpc::proto::sui::rpc::v2::Event;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::StructTag;

use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;

/// The Hashi approval recorded by the object at `wid`, or `None` if that object
/// is not a Hashi `WithdrawalTransaction`.
pub fn parse_withdrawal_object(
    package_versions: &PackageVersions,
    wid: WithdrawalID,
    object: &Object,
) -> anyhow::Result<Option<MonitorWithdrawalEvent>> {
    let is_withdrawal_transaction = object
        .object_type_opt()
        .context("Sui object is missing its type")?
        .parse::<StructTag>()
        .is_ok_and(|tag| WithdrawalTransaction::matches(package_versions, &tag));
    if !is_withdrawal_transaction {
        return Ok(None);
    }
    let txn: WithdrawalTransaction = object
        .contents()
        .deserialize()
        .with_context(|| format!("failed to decode withdrawal transaction {wid}"))?;
    anyhow::ensure!(
        txn.id == wid,
        "Sui returned withdrawal transaction {} for {wid}",
        txn.id
    );
    Ok(Some(MonitorWithdrawalEvent {
        event_type: WithdrawalEventType::E1HashiApproved,
        wid,
        timestamp_secs: unix_millis_to_seconds(txn.created_timestamp_ms),
        btc_txid: txn.txid.into(),
    }))
}

/// The monitored event a Sui event carries, if any.
pub fn parse_event(
    package_versions: &PackageVersions,
    event: Event,
    transaction_timestamp_secs: UnixSeconds,
) -> anyhow::Result<Option<MonitorEvent>> {
    let contents = event
        .contents
        .context("Sui event is missing BCS contents")?;
    let event = HashiEvent::try_parse(package_versions, &contents)
        .context("failed to parse Hashi Sui event")?;

    Ok(match event {
        Some(HashiEvent::WithdrawalPickedForProcessing(event)) => {
            Some(MonitorEvent::Withdrawal(MonitorWithdrawalEvent {
                event_type: WithdrawalEventType::E1HashiApproved,
                wid: event.withdrawal_txn_id,
                timestamp_secs: unix_millis_to_seconds(event.timestamp_ms),
                btc_txid: event.txid.into(),
            }))
        }
        Some(HashiEvent::DepositConfirmed(event)) => {
            Some(MonitorEvent::Deposit(MonitorDepositEvent {
                event_type: DepositEventType::E2HashiDeposited,
                // DepositConfirmed has no timestamp in its Move payload.
                // ListTransactions supplies the containing checkpoint's
                // timestamp alongside the nested events.
                timestamp_secs: transaction_timestamp_secs,
                deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
            }))
        }
        Some(_) | None => None,
    })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::SigningBatch;
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_sdk_types::Address;

    pub const PACKAGE_ID: Address = Address::new([0x11; 32]);
    pub const WID: Address = Address::new([0x3d; 32]);

    pub fn package_versions() -> PackageVersions {
        PackageVersions::new(BTreeMap::from([(1, PACKAGE_ID)]))
    }

    pub fn withdrawal_transaction(id: Address) -> WithdrawalTransaction {
        WithdrawalTransaction {
            id,
            txid: BitcoinTxid::from(Address::new([0x47; 32])),
            request_ids: vec![],
            inputs: vec![],
            withdrawal_outputs: vec![],
            change_outputs: vec![],
            created_timestamp_ms: 1_789_805_327_448,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: SigningBatch {
                signatures: vec![],
                epoch: 0,
            },
            guardian_signatures: None,
        }
    }

    /// The `WithdrawalTransaction` object of `txn`, served at `WID`.
    pub fn object_at_wid(package_id: Address, txn: &WithdrawalTransaction) -> Object {
        let mut object = Object::default();
        object.object_id = Some(WID.to_string());
        object.object_type = Some(format!(
            "{package_id}::withdrawal_queue::WithdrawalTransaction"
        ));
        object.contents = Some(Bcs::serialize(txn).unwrap());
        object
    }

    /// The `WithdrawalPickedForProcessing` event emitted alongside `txn`.
    pub fn picked_for_processing_event(txn: &WithdrawalTransaction) -> Event {
        // `WithdrawalPickedForProcessing` fields, in declaration order.
        let mut contents = Bcs::serialize(&(
            txn.id,
            txn.txid,
            txn.request_ids.clone(),
            txn.inputs.clone(),
            txn.withdrawal_outputs.clone(),
            txn.change_outputs.clone(),
            txn.created_timestamp_ms,
            txn.randomness.clone(),
        ))
        .unwrap();
        contents.name = Some(format!(
            "{PACKAGE_ID}::withdrawal_queue::WithdrawalPickedForProcessing"
        ));
        let mut event = Event::default();
        event.contents = Some(contents);
        event
    }

    #[test]
    fn a_foreign_object_is_no_approval() {
        let txn = withdrawal_transaction(WID);
        let foreign_type = object_at_wid(Address::new([0x22; 32]), &txn);
        let mut package = object_at_wid(PACKAGE_ID, &txn);
        package.object_type = Some("package".to_string());

        for object in [foreign_type, package] {
            let approval = parse_withdrawal_object(&package_versions(), WID, &object);
            assert_eq!(approval.unwrap(), None);
        }
    }

    #[test]
    fn unreadable_or_mismatched_contents_are_an_error() {
        let another_withdrawal = object_at_wid(
            PACKAGE_ID,
            &withdrawal_transaction(Address::new([0x3e; 32])),
        );
        let mut undecodable = object_at_wid(PACKAGE_ID, &withdrawal_transaction(WID));
        undecodable.contents = Some(Bcs::from(vec![1, 2, 3]));

        for object in [another_withdrawal, undecodable] {
            let approval = parse_withdrawal_object(&package_versions(), WID, &object);
            assert!(approval.is_err());
        }
    }

    #[test]
    fn lookup_and_event_scan_build_the_same_approval() {
        let txn = withdrawal_transaction(WID);

        let looked_up =
            parse_withdrawal_object(&package_versions(), WID, &object_at_wid(PACKAGE_ID, &txn))
                .unwrap();
        assert_eq!(
            parse_event(&package_versions(), picked_for_processing_event(&txn), 0).unwrap(),
            looked_up.map(MonitorEvent::Withdrawal)
        );
    }
}
