// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Checks on the Hashi approvals that the monitor reads from Sui.
//!
//! Why it exists: Move validates a withdrawal's user outputs against the user
//! requests, but not its txid or its change outputs. A compromised committee
//! controls both, so the monitor checks them here before an approval enters
//! the state machine.
//!
//! Goals of the approval checks, together with Move and the state machine:
//! 1. The transaction the guardian signs is the one posted on Sui: the same
//!    input UTXOs, the same external outputs and the same internal outputs.
//! 2. Every output pays either a user-requested address with the requested
//!    amount less the fee share, or a change address owned by Hashi.
//!
//! Chain of trust, from the user's request to the guardian's signature:
//! 1. Move builds the `WithdrawalTransaction` object in `new_withdrawal_txn`
//!    (`withdrawal_queue.move`). It asserts that each user output pays the
//!    request's address and the request's amount less the per-user miner fee,
//!    and it caps that fee. The inputs are copied from the UTXO pool by id in
//!    `commit_withdrawal_tx` (`withdraw.move`). Change outputs are not checked.
//! 2. `commit_withdrawal_tx` then calls `emit_withdrawal_picked_for_processing`,
//!    which emits `WithdrawalPickedForProcessing` from that object's own
//!    fields. So the event and the object carry the same txid, inputs and
//!    outputs, and both reach this file.
//! 3. This file rebuilds the transaction from those inputs and outputs and
//!    rejects the approval if the claimed txid differs.
//! 4. The guardian computes its own txid from the outputs it signs, and the
//!    state machine requires the guardian's txid to equal the approval's.
//!    Together: the guardian signed exactly the outputs that Move validated.
//! 5. A txid does not commit to Sui's change label, so this file also rejects
//!    a change output that does not pay the bridge change address. With step
//!    4, every signed output is a user output or change to the bridge, which
//!    completes both goals.
//!
//! Assumptions:
//! - The two keys every bridge address derives from never change. The caller
//!   reads them once.
//! - An approval comes from a `WithdrawalPickedForProcessing` event or from the
//!   `WithdrawalTransaction` object created with it. Both carry the same txid,
//!   inputs, outputs and timestamp.

use anyhow::Context;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use hashi_types::bitcoin::script_pubkey_from_witness_program;
use hashi_types::bitcoin::unsigned_withdrawal_tx;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::MoveType;
use hashi_types::move_types::OutputUtxo;
use hashi_types::move_types::PackageVersions;
use hashi_types::move_types::Utxo;
use hashi_types::move_types::WithdrawalTransaction;
use sui_rpc::proto::sui::rpc::v2::Event;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::StructTag;

use crate::domain::DepositEventType;
use crate::domain::DepositId;
use crate::domain::HashiBTCKeys;
use crate::domain::MonitorDepositEvent;
use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::WithdrawalEventType;
use crate::findings::MonitorFinding;

/// A Hashi approval read from Sui.
#[derive(Debug, PartialEq, Eq)]
pub enum HashiApproval {
    /// The approval passed every check.
    Valid(MonitorWithdrawalEvent),
    /// The approval failed a check. It is reported and not ingested.
    Rejected(Vec<MonitorFinding>),
}

/// Check what Move does not on the Hashi approval of `wid`: the claimed
/// txid must be the txid of the transaction its inputs and outputs build, and
/// every change output must pay `change_script`. Otherwise a committee can
/// commit a user's outputs under the txid of a transaction that pays itself,
/// or label a payout to itself as change.
fn validate_withdrawal(
    wid: WithdrawalID,
    claimed_txid: Txid,
    inputs: &[Utxo],
    withdrawal_outputs: &[OutputUtxo],
    change_outputs: &[OutputUtxo],
    change_script: &ScriptBuf,
    timestamp_secs: UnixSeconds,
) -> HashiApproval {
    let mut findings = Vec::new();
    for (index, output) in change_outputs.iter().enumerate() {
        let script = script_pubkey_from_witness_program(&output.bitcoin_address).ok();
        if script.as_ref() != Some(change_script) {
            findings.push(MonitorFinding::ChangeOutputNotToBridge {
                wid,
                vout: (withdrawal_outputs.len() + index) as u32,
                bitcoin_address: output.bitcoin_address.clone(),
            });
        }
    }

    let outputs = [withdrawal_outputs, change_outputs].concat();
    match unsigned_withdrawal_tx(inputs, &outputs) {
        Ok(tx) if tx.compute_txid() == claimed_txid => {}
        Ok(tx) => findings.push(MonitorFinding::WithdrawalTxidMismatch {
            wid,
            claimed: claimed_txid,
            computed: tx.compute_txid(),
        }),
        Err(error) => findings.push(MonitorFinding::WithdrawalTxUnbuildable {
            wid,
            claimed: claimed_txid,
            reason: format!("{error:#}"),
        }),
    }

    if findings.is_empty() {
        HashiApproval::Valid(MonitorWithdrawalEvent {
            event_type: WithdrawalEventType::E1HashiApproved,
            wid,
            timestamp_secs,
            btc_txid: claimed_txid,
        })
    } else {
        HashiApproval::Rejected(findings)
    }
}

/// The Hashi approval recorded by the object at `wid`, or `None` if that object
/// is not a Hashi `WithdrawalTransaction`.
pub fn parse_withdrawal_object(
    package_versions: &PackageVersions,
    hashi_btc_keys: &HashiBTCKeys,
    wid: WithdrawalID,
    object: &Object,
) -> anyhow::Result<Option<HashiApproval>> {
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
    Ok(Some(validate_withdrawal(
        wid,
        txn.txid.into(),
        &txn.inputs,
        &txn.withdrawal_outputs,
        &txn.change_outputs,
        &hashi_btc_keys.script_pubkey(None),
        unix_millis_to_seconds(txn.created_timestamp_ms),
    )))
}

/// Parse the monitored event a Sui event carries into `events`, or its
/// findings into `findings` if it fails a check.
pub fn parse_event(
    package_versions: &PackageVersions,
    hashi_btc_keys: &HashiBTCKeys,
    event: Event,
    transaction_timestamp_secs: UnixSeconds,
    events: &mut Vec<MonitorEvent>,
    findings: &mut Vec<MonitorFinding>,
) -> anyhow::Result<()> {
    let contents = event
        .contents
        .context("Sui event is missing BCS contents")?;
    let event = HashiEvent::try_parse(package_versions, &contents)
        .context("failed to parse Hashi Sui event")?;

    match event {
        Some(HashiEvent::WithdrawalPickedForProcessing(event)) => {
            let approval = validate_withdrawal(
                event.withdrawal_txn_id,
                event.txid.into(),
                &event.inputs,
                &event.withdrawal_outputs,
                &event.change_outputs,
                &hashi_btc_keys.script_pubkey(None),
                unix_millis_to_seconds(event.timestamp_ms),
            );
            match approval {
                HashiApproval::Valid(event) => events.push(MonitorEvent::Withdrawal(event)),
                HashiApproval::Rejected(rejection) => findings.extend(rejection),
            }
        }
        Some(HashiEvent::DepositConfirmed(event)) => {
            events.push(MonitorEvent::Deposit(MonitorDepositEvent {
                event_type: DepositEventType::E2HashiDeposited,
                // DepositConfirmed has no timestamp in its Move payload.
                // ListTransactions supplies the containing checkpoint's
                // timestamp alongside the nested events.
                timestamp_secs: transaction_timestamp_secs,
                deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
                amount: event.utxo.amount,
                // The state machine compares the claim with the paid output.
                script_pubkey: hashi_btc_keys.script_pubkey(event.utxo.derivation_path.as_ref()),
            }));
        }
        Some(_) | None => {}
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::collections::BTreeMap;

    use crate::domain::HashiBTCKeys;
    use crate::findings::FindingCategory;
    use hashi_types::bitcoin::BTC_LIB;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::bitcoin::BitcoinKeypair;
    use hashi_types::bitcoin::HashiMasterG;
    use hashi_types::bitcoin::witness_program_from_address;
    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::SigningBatch;
    use hashi_types::move_types::UtxoId;
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_sdk_types::Address;

    pub const PACKAGE_ID: Address = Address::new([0x11; 32]);
    pub const WID: Address = Address::new([0x3d; 32]);

    pub fn package_versions() -> PackageVersions {
        PackageVersions::new(BTreeMap::from([(1, PACKAGE_ID)]))
    }

    /// Bridge keys from fixed test guardian and MPC keys, on Signet.
    pub fn test_hashi_btc_keys() -> HashiBTCKeys {
        let guardian = BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[6u8; 32])
            .unwrap()
            .x_only_public_key()
            .0;
        let mpc = HashiMasterG::with_even_y_from_x_be_bytes(
            &BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[7u8; 32])
                .unwrap()
                .x_only_public_key()
                .0
                .serialize(),
        )
        .unwrap();
        HashiBTCKeys::new(guardian, mpc, bitcoin::Network::Signet)
    }

    /// The bridge change address of `test_hashi_btc_keys`.
    pub fn test_change_address() -> BitcoinAddress {
        BitcoinAddress::from_script(
            &test_hashi_btc_keys().script_pubkey(None),
            bitcoin::Network::Signet,
        )
        .unwrap()
    }

    /// `txn` with the txid that its inputs and outputs build.
    pub fn with_rebuilt_txid(mut txn: WithdrawalTransaction) -> WithdrawalTransaction {
        let txid = unsigned_withdrawal_tx(&txn.inputs, &txn.all_outputs())
            .unwrap()
            .compute_txid();
        txn.txid = txid.into();
        txn
    }

    /// A withdrawal of one input into one user output and one change output to
    /// the bridge, whose txid is the one its inputs and outputs build.
    pub fn withdrawal_transaction(id: Address) -> WithdrawalTransaction {
        let inputs = vec![Utxo {
            id: UtxoId {
                txid: BitcoinTxid::from(Address::new([0x51; 32])),
                vout: 1,
            },
            amount: 120_000,
            derivation_path: Some(Address::new([0x52; 32])),
        }];
        let withdrawal_outputs = vec![OutputUtxo {
            amount: 100_000,
            bitcoin_address: vec![0x53; 20],
        }];
        let change_outputs = vec![OutputUtxo {
            amount: 19_000,
            bitcoin_address: witness_program_from_address(&test_change_address()).unwrap(),
        }];
        let txn = WithdrawalTransaction {
            id,
            txid: BitcoinTxid::ZERO,
            request_ids: vec![Address::new([0x55; 32])],
            inputs,
            withdrawal_outputs,
            change_outputs,
            created_timestamp_ms: 1_789_805_327_448,
            signed_timestamp_ms: None,
            confirmed_timestamp_ms: None,
            randomness: vec![],
            signing: SigningBatch {
                signatures: vec![],
                epoch: 0,
            },
            guardian_signatures: None,
        };
        with_rebuilt_txid(txn)
    }

    /// `txn` with a txid that its inputs and outputs do not build.
    pub fn with_wrong_txid(mut txn: WithdrawalTransaction) -> WithdrawalTransaction {
        txn.txid = BitcoinTxid::from(Address::new([0x47; 32]));
        txn
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

    /// The approval of `txn`'s object at `WID`.
    fn approval(txn: &WithdrawalTransaction) -> HashiApproval {
        parse_withdrawal_object(
            &package_versions(),
            &test_hashi_btc_keys(),
            WID,
            &object_at_wid(PACKAGE_ID, txn),
        )
        .unwrap()
        .unwrap()
    }

    /// The findings of a rejected approval.
    fn rejection(approval: HashiApproval) -> Vec<MonitorFinding> {
        match approval {
            HashiApproval::Rejected(findings) => findings,
            HashiApproval::Valid(event) => panic!("approval was not rejected: {event:?}"),
        }
    }

    #[test]
    fn a_valid_approval_is_its_hashi_event() {
        let txn = withdrawal_transaction(WID);

        assert_eq!(
            approval(&txn),
            HashiApproval::Valid(MonitorWithdrawalEvent {
                event_type: WithdrawalEventType::E1HashiApproved,
                wid: WID,
                timestamp_secs: 1_789_805_327,
                btc_txid: txn.txid.into(),
            })
        );
    }

    #[test]
    fn a_wrong_txid_rejects_the_approval() {
        let txn = withdrawal_transaction(WID);
        let computed: Txid = txn.txid.into();
        let txn = with_wrong_txid(txn);
        let claimed: Txid = txn.txid.into();

        let findings = rejection(approval(&txn));

        assert_eq!(
            findings,
            vec![MonitorFinding::WithdrawalTxidMismatch {
                wid: WID,
                claimed,
                computed,
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_change_output_to_another_address_rejects_the_approval() {
        let mut txn = withdrawal_transaction(WID);
        txn.change_outputs[0].bitcoin_address = vec![0x54; 32];
        // An honest txid, as a committee paying itself as change would commit.
        let txn = with_rebuilt_txid(txn);

        let findings = rejection(approval(&txn));

        assert_eq!(
            findings,
            vec![MonitorFinding::ChangeOutputNotToBridge {
                wid: WID,
                vout: 1,
                bitcoin_address: vec![0x54; 32],
            }]
        );
        assert_eq!(findings[0].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_tampered_change_output_rejects_the_approval() {
        let mut txn = withdrawal_transaction(WID);
        txn.change_outputs[0].amount += 1;

        let findings = rejection(approval(&txn));

        assert!(matches!(
            findings[..],
            [MonitorFinding::WithdrawalTxidMismatch { wid: WID, .. }]
        ));
    }

    #[test]
    fn an_unbuildable_output_rejects_the_approval() {
        let mut txn = withdrawal_transaction(WID);
        txn.change_outputs[0].bitcoin_address = vec![0x54; 5];
        let claimed: Txid = txn.txid.into();

        let findings = rejection(approval(&txn));

        // The bad address is not the bridge's either.
        assert!(
            matches!(
                findings[..],
                [
                    MonitorFinding::ChangeOutputNotToBridge { wid: WID, vout: 1, .. },
                    MonitorFinding::WithdrawalTxUnbuildable { wid: WID, claimed: c, .. },
                ] if c == claimed
            ),
            "{findings:?}"
        );
        assert_eq!(findings[1].category(), FindingCategory::Safety);
    }

    #[test]
    fn a_foreign_object_is_no_approval() {
        let txn = withdrawal_transaction(WID);
        let foreign_type = object_at_wid(Address::new([0x22; 32]), &txn);
        let mut package = object_at_wid(PACKAGE_ID, &txn);
        package.object_type = Some("package".to_string());

        for object in [foreign_type, package] {
            let approval =
                parse_withdrawal_object(&package_versions(), &test_hashi_btc_keys(), WID, &object);
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
            let approval =
                parse_withdrawal_object(&package_versions(), &test_hashi_btc_keys(), WID, &object);
            assert!(approval.is_err());
        }
    }

    #[test]
    fn lookup_and_event_scan_build_the_same_approval() {
        let hashi_btc_keys = test_hashi_btc_keys();
        for txn in [
            withdrawal_transaction(WID),
            with_wrong_txid(withdrawal_transaction(WID)),
        ] {
            let looked_up = parse_withdrawal_object(
                &package_versions(),
                &hashi_btc_keys,
                WID,
                &object_at_wid(PACKAGE_ID, &txn),
            )
            .unwrap()
            .unwrap();
            let expected = match looked_up {
                HashiApproval::Valid(event) => (vec![MonitorEvent::Withdrawal(event)], vec![]),
                HashiApproval::Rejected(findings) => (vec![], findings),
            };

            let (mut events, mut findings) = (Vec::new(), Vec::new());
            parse_event(
                &package_versions(),
                &hashi_btc_keys,
                picked_for_processing_event(&txn),
                0,
                &mut events,
                &mut findings,
            )
            .unwrap();
            assert_eq!((events, findings), expected);
        }
    }
}
