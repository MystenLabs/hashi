// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdrawal-side checks on the Hashi approvals that the monitor reads from Sui.
//!
//! Why it exists: Move validates a withdrawal's user outputs against the user
//! requests, but not its txid or its change outputs. A compromised committee
//! controls both, so the monitor checks them here before an approval enters
//! the state machine.
//!
//! Goals of the approval checks, together with Move and the state machine:
//! 1. The transaction the guardian signs is the one posted on Sui: the same
//!    input UTXOs and the same output UTXOs.
//! 2. Every output is either a user-requested payout, with the requested
//!    amount less the fee share, or change to a Hashi address.
//!
//! Chain of trust, from the user's request to the guardian's signature:
//! 1. Move builds the `WithdrawalTransaction` object in `new_withdrawal_txn`
//!    (`withdrawal_queue.move`). It asserts that each user output pays the
//!    request's address and the request's amount less the per-user miner fee,
//!    and it caps that fee. The inputs are copied from the UTXO pool by id in
//!    `commit_withdrawal_tx` (`withdraw.move`). Change outputs are not checked.
//! 2. `commit_withdrawal_tx` then calls `emit_withdrawal_picked_for_processing`,
//!    which emits `WithdrawalPickedForProcessing` from that object's own
//!    fields. So the event carries the object's txid, inputs and outputs to
//!    this file.
//! 3. This file rebuilds the transaction from those inputs and outputs and
//!    rejects the approval if the claimed txid differs.
//! 4. The guardian computes its own txid from the outputs it signs, and the
//!    state machine requires the guardian's txid to equal the approval's.
//!    Together: the guardian signed exactly the outputs that Move validated.
//! 5. A txid does not commit to which outputs Sui calls change, so the event
//!    carries the inputs and outputs in Move's shape, and the state machine
//!    requires the guardian's log, converted into that shape, to be equal.
//!    The guardian derives every change address from a path it logs, so
//!    equality means each change output pays the bridge, which completes
//!    both goals.
//!
//! Assumptions:
//! - The two keys every bridge address derives from never change. The caller
//!   reads them once.
//! - An approval comes from a `WithdrawalPickedForProcessing` event.

use anyhow::Context;
use hashi_types::move_types::HashiEvent;
use hashi_types::move_types::PackageVersions;
use sui_rpc::proto::sui::rpc::v2::Event;

use crate::domain::MonitorEvent;
use crate::domain::MonitorWithdrawalEvent;
use crate::domain::SuiDepositApprovedEvent;
use crate::domain::SuiDepositRequestedEvent;
use crate::findings::MonitorFinding;
use crate::keys::HashiBTCKeys;

/// Parse the monitored event a Sui event carries into `events`, or its
/// findings into `findings` if it fails a check.
pub fn parse_event(
    package_versions: &PackageVersions,
    hashi_btc_keys: &HashiBTCKeys,
    event: Event,
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
            match MonitorWithdrawalEvent::from_sui_event(event) {
                Ok(event) => events.push(MonitorEvent::Withdrawal(event)),
                Err(rejection) => findings.extend(rejection),
            }
        }
        Some(HashiEvent::DepositApproved(event)) => {
            events.push(MonitorEvent::DepositApproved(SuiDepositApprovedEvent::new(
                event,
                hashi_btc_keys,
            )));
        }
        Some(HashiEvent::DepositRequested(event)) => {
            events.push(MonitorEvent::DepositRequested(
                SuiDepositRequestedEvent::new(event, hashi_btc_keys),
            ));
        }
        Some(_) | None => {}
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use bitcoin::Txid;

    use super::*;
    use crate::domain::DepositId;
    use crate::domain::WithdrawalEventType;
    use crate::domain::WithdrawalTx;
    use hashi_types::move_types::WithdrawalTransaction;

    use std::collections::BTreeMap;

    use crate::test_utils::test_hashi_btc_keys;
    use crate::test_utils::withdrawal_tx;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::witness_program_from_address;
    use hashi_types::bitcoin_txid::BitcoinTxid;
    use hashi_types::move_types::SigningBatch;
    use sui_rpc::proto::sui::rpc::v2::Bcs;
    use sui_sdk_types::Address;

    pub const PACKAGE_ID: Address = Address::new([0x11; 32]);
    pub const WID: Address = Address::new([0x3d; 32]);

    pub fn package_versions() -> PackageVersions {
        PackageVersions::new(BTreeMap::from([(1, PACKAGE_ID)]))
    }

    /// The bridge change address of `test_hashi_btc_keys`.
    fn test_change_address() -> BitcoinAddress {
        BitcoinAddress::from_script(
            &test_hashi_btc_keys().script_pubkey(None),
            bitcoin::Network::Signet,
        )
        .unwrap()
    }

    /// The inputs and outputs of `txn` as its Hashi approval carries them.
    pub fn approval_tx(txn: &WithdrawalTransaction) -> WithdrawalTx {
        WithdrawalTx::new(
            txn.inputs.clone(),
            txn.withdrawal_outputs.clone(),
            txn.change_outputs.clone(),
        )
    }

    /// `txn` with the txid that its inputs and outputs build.
    pub fn with_rebuilt_txid(mut txn: WithdrawalTransaction) -> WithdrawalTransaction {
        let txid = approval_tx(&txn).unsigned_tx().unwrap().compute_txid();
        txn.txid = txid.into();
        txn
    }

    /// The `withdrawal_tx` of one input into one user output and one change
    /// output to the bridge, as a `WithdrawalTransaction` object whose txid is
    /// the one its inputs and outputs build.
    /// A `DepositRequested` event for `txn`'s first input, claimed at `timestamp_ms`.
    pub fn deposit_requested_event(txn: &WithdrawalTransaction, timestamp_ms: u64) -> Event {
        let input = &txn.inputs[0];
        // `DepositRequested` fields, in declaration order.
        let mut contents = Bcs::serialize(&(
            Address::new([0x61; 32]),
            input.id,
            input.amount,
            input.derivation_path,
            timestamp_ms,
            Address::new([0x62; 32]),
            sui_sdk_types::Digest::new([0x63; 32]),
        ))
        .unwrap();
        contents.name = Some(format!("{PACKAGE_ID}::deposit::DepositRequested"));
        let mut event = Event::default();
        event.contents = Some(contents);
        event
    }

    /// A `DepositApproved` event for `txn`'s first input, approved at `timestamp_ms`.
    pub fn deposit_approved_event(txn: &WithdrawalTransaction, timestamp_ms: u64) -> Event {
        let input = &txn.inputs[0];
        // `DepositApproved` fields, in declaration order: the request, the
        // UTXO, the committee certificate and the approval time.
        let mut contents = Bcs::serialize(&(
            Address::new([0x61; 32]),
            (input.id, input.amount, input.derivation_path),
            (7_u64, vec![0x64_u8; 48], vec![0xff_u8]),
            timestamp_ms,
        ))
        .unwrap();
        contents.name = Some(format!("{PACKAGE_ID}::deposit::DepositApproved"));
        let mut event = Event::default();
        event.contents = Some(contents);
        event
    }

    pub fn withdrawal_transaction(id: Address) -> WithdrawalTransaction {
        let tx = withdrawal_tx(witness_program_from_address(&test_change_address()).unwrap());
        let txn = WithdrawalTransaction {
            id,
            txid: BitcoinTxid::ZERO,
            request_ids: vec![Address::new([0x55; 32])],
            inputs: tx.inputs,
            withdrawal_outputs: tx.withdrawal_outputs,
            change_outputs: tx.change_outputs,
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

    /// The approval that the `WithdrawalPickedForProcessing` event of `txn`
    /// carries, or the findings that reject it.
    fn approval(
        txn: &WithdrawalTransaction,
    ) -> Result<MonitorWithdrawalEvent, Vec<MonitorFinding>> {
        let (mut events, mut findings) = (Vec::new(), Vec::new());
        parse_event(
            &package_versions(),
            &test_hashi_btc_keys(),
            picked_for_processing_event(txn),
            &mut events,
            &mut findings,
        )
        .unwrap();
        match &events[..] {
            [] => Err(findings),
            [MonitorEvent::Withdrawal(event)] if findings.is_empty() => Ok(event.clone()),
            _ => panic!("unexpected parse: {events:?}, {findings:?}"),
        }
    }

    /// The findings of a rejected approval.
    fn rejection(
        approval: Result<MonitorWithdrawalEvent, Vec<MonitorFinding>>,
    ) -> Vec<MonitorFinding> {
        approval.expect_err("approval was not rejected")
    }

    #[test]
    fn a_valid_approval_is_its_hashi_event() {
        let txn = withdrawal_transaction(WID);

        assert_eq!(
            approval(&txn),
            Ok(MonitorWithdrawalEvent {
                event_type: WithdrawalEventType::E1HashiApproved,
                wid: WID,
                timestamp_secs: 1_789_805_327,
                btc_txid: txn.txid.into(),
                tx: approval_tx(&txn),
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
    }

    #[test]
    fn a_change_output_to_another_address_is_carried_for_the_guardian_check() {
        let mut txn = withdrawal_transaction(WID);
        txn.change_outputs[0].bitcoin_address = vec![0x54; 32];
        // An honest txid, as a committee paying itself as change would commit.
        let txn = with_rebuilt_txid(txn);

        // The address is not checked here: the state machine compares Sui's
        // transaction with the guardian's once E2 arrives.
        let event = approval(&txn).expect("the approval was rejected");
        assert_eq!(event.tx.change_outputs[0].bitcoin_address, vec![0x54; 32]);
    }

    #[test]
    fn an_unset_input_path_is_carried_as_the_zero_path() {
        let mut txn = withdrawal_transaction(WID);
        txn.inputs[0].derivation_path = None;
        let txn = with_rebuilt_txid(txn);

        let event = approval(&txn).expect("the approval was rejected");
        assert_eq!(
            event.tx.inputs[0].derivation_path,
            Some(DerivationPath::ZERO)
        );
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

        assert!(
            matches!(
                findings[..],
                [MonitorFinding::WithdrawalTxUnbuildable { wid: WID, claimed: c, .. }] if c == claimed
            ),
            "{findings:?}"
        );
    }

    #[test]
    fn a_deposit_request_carries_the_claimed_script_and_its_own_time() {
        let txn = withdrawal_transaction(WID);
        let input = &txn.inputs[0];
        let (mut events, mut findings) = (Vec::new(), Vec::new());

        parse_event(
            &package_versions(),
            &test_hashi_btc_keys(),
            deposit_requested_event(&txn, 1_700_000_000_500),
            &mut events,
            &mut findings,
        )
        .unwrap();

        assert_eq!(
            events,
            vec![MonitorEvent::DepositRequested(SuiDepositRequestedEvent {
                request_id: Address::new([0x61; 32]),
                timestamp_secs: 1_700_000_000,
                deposit_id: DepositId::new(input.id.txid.into(), input.id.vout),
                amount: input.amount,
                script_pubkey: test_hashi_btc_keys().script_pubkey(input.derivation_path.as_ref()),
            })]
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn a_deposit_approval_carries_the_claimed_script_and_its_own_time() {
        let txn = withdrawal_transaction(WID);
        let input = &txn.inputs[0];
        let (mut events, mut findings) = (Vec::new(), Vec::new());

        parse_event(
            &package_versions(),
            &test_hashi_btc_keys(),
            deposit_approved_event(&txn, 1_700_000_600_900),
            &mut events,
            &mut findings,
        )
        .unwrap();

        assert_eq!(
            events,
            vec![MonitorEvent::DepositApproved(SuiDepositApprovedEvent {
                timestamp_secs: 1_700_000_600,
                request_id: Address::new([0x61; 32]),
                deposit_id: DepositId::new(input.id.txid.into(), input.id.vout),
                amount: input.amount,
                script_pubkey: test_hashi_btc_keys().script_pubkey(input.derivation_path.as_ref()),
            })]
        );
        assert!(findings.is_empty());
    }
}
