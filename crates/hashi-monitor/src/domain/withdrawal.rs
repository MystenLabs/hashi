// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The withdrawal flow's events and the transaction they state.

use crate::domain::BtcConfirmation;
use std::fmt;

use anyhow::Context as _;
use bitcoin::Transaction;
use bitcoin::Txid;
use hashi_types::bitcoin::DerivationPath;
use hashi_types::bitcoin::OutputUTXOWire;
use hashi_types::bitcoin::TxUTXOsWire;
use hashi_types::bitcoin::unsigned_withdrawal_tx;
use hashi_types::bitcoin::witness_program_from_address;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::OutputUtxo;
use hashi_types::move_types::Utxo;
use hashi_types::move_types::UtxoId;
use hashi_types::move_types::WithdrawalPickedForProcessing;
use hashi_types::move_types::WithdrawalTransaction;

use crate::findings::MonitorFinding;
use crate::keys::HashiBTCKeys;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorWithdrawalEvent {
    /// The source that produced the event.
    pub event_type: WithdrawalEventType,

    /// Stable withdrawal identifier.
    pub wid: WithdrawalID,

    /// Unix timestamp embedded in the Sui event / S3 log / BTC block.
    pub timestamp_secs: UnixSeconds,

    /// The txid of `tx`. It is derivable, and carried so that the Bitcoin
    /// lookup and the join of the three events need not rebuild the
    /// transaction. E1 carries Sui's claim, checked against `tx` on ingest.
    /// E2 carries the txid the guardian signed.
    pub btc_txid: Txid,

    /// The withdrawal's inputs and outputs as the source of this event states
    /// them. E3 repeats what the state machine already holds.
    pub tx: WithdrawalTx,
}

impl MonitorWithdrawalEvent {
    /// E1 from the `WithdrawalTransaction` object at `wid`.
    pub fn from_sui_object(
        wid: WithdrawalID,
        txn: WithdrawalTransaction,
    ) -> Result<Self, Vec<MonitorFinding>> {
        Self::checked(
            WithdrawalEventType::E1HashiApproved,
            wid,
            txn.txid.into(),
            WithdrawalTx::new(txn.inputs, txn.withdrawal_outputs, txn.change_outputs),
            unix_millis_to_seconds(txn.created_timestamp_ms),
        )
    }

    /// E1 from the `WithdrawalPickedForProcessing` event.
    pub fn from_sui_event(
        event: WithdrawalPickedForProcessing,
    ) -> Result<Self, Vec<MonitorFinding>> {
        Self::checked(
            WithdrawalEventType::E1HashiApproved,
            event.withdrawal_txn_id,
            event.txid.into(),
            WithdrawalTx::new(event.inputs, event.withdrawal_outputs, event.change_outputs),
            unix_millis_to_seconds(event.timestamp_ms),
        )
    }

    /// Check what Move does not on an approval of `wid`: the claimed txid
    /// must be the txid of the transaction `tx` builds. Otherwise a committee
    /// can commit a user's outputs under the txid of a transaction that pays
    /// itself, and a guardian's log could label outputs the txid does not
    /// have. A failed check is returned as findings, and the event is not
    /// ingested. The event carries `tx` for the state machine to compare the
    /// two approvals.
    fn checked(
        event_type: WithdrawalEventType,
        wid: WithdrawalID,
        claimed_txid: Txid,
        tx: WithdrawalTx,
        timestamp_secs: UnixSeconds,
    ) -> Result<Self, Vec<MonitorFinding>> {
        match tx.unsigned_tx() {
            Ok(built) if built.compute_txid() == claimed_txid => {}
            Ok(built) => {
                return Err(vec![MonitorFinding::WithdrawalTxidMismatch {
                    wid,
                    claimed: claimed_txid,
                    computed: built.compute_txid(),
                }]);
            }
            Err(error) => {
                return Err(vec![MonitorFinding::WithdrawalTxUnbuildable {
                    wid,
                    claimed: claimed_txid,
                    reason: format!("{error:#}"),
                }]);
            }
        }
        Ok(Self {
            event_type,
            wid,
            timestamp_secs,
            btc_txid: claimed_txid,
            tx,
        })
    }

    /// E2 from the guardian's withdrawal log message, logged at
    /// `timestamp_ms`. The log labels every output it signed; `keys` turn its
    /// change paths into addresses. A layout the keys cannot build, or one
    /// that does not hash to the txid the log states, is returned as findings.
    pub fn from_guardian(
        withdrawal: &WithdrawalLogMessage,
        timestamp_ms: u64,
        keys: &HashiBTCKeys,
    ) -> Result<Self, Vec<MonitorFinding>> {
        let wid = withdrawal.request_data.wid;
        let tx =
            WithdrawalTx::from_guardian(keys, &withdrawal.request_data.utxos).map_err(|error| {
                vec![MonitorFinding::WithdrawalTxUnbuildable {
                    wid,
                    claimed: withdrawal.txid,
                    reason: format!("{error:#}"),
                }]
            })?;
        Self::checked(
            WithdrawalEventType::E2GuardianApproved,
            wid,
            withdrawal.txid,
            tx,
            unix_millis_to_seconds(timestamp_ms),
        )
    }

    /// E3 from Bitcoin's confirmation of the withdrawal `wid` and `btc_txid`.
    /// It repeats `tx`, which the state machine already holds.
    pub fn from_btc(
        confirmation: &BtcConfirmation,
        wid: WithdrawalID,
        btc_txid: Txid,
        tx: WithdrawalTx,
    ) -> Self {
        Self {
            event_type: WithdrawalEventType::E3BtcConfirmed,
            wid,
            btc_txid,
            timestamp_secs: confirmation.confirmed_time,
            tx,
        }
    }
}

/// A withdrawal Bitcoin confirmed, with the guardian's word on which of its
/// outputs are change. The UTXO pool applies it.
#[derive(Clone, Debug)]
pub struct ConfirmedWithdrawal {
    pub txid: Txid,
    pub confirmation: BtcConfirmation,
    /// The vout of the first change output. The change outputs trail the
    /// user payouts, so every output from here on is change.
    pub first_change_vout: usize,
}

impl ConfirmedWithdrawal {
    /// The withdrawal the guardian approved in `e2`, as Bitcoin confirmed
    /// it. Only the change layout is E2's: Bitcoin cannot say which outputs
    /// are change, and the guardian labels them from paths it derives. The
    /// outputs themselves agree by construction: E2's layout was checked to
    /// hash to the txid at ingest, and so was the confirmation at lookup.
    pub fn from_confirmation(e2: &MonitorWithdrawalEvent, confirmation: BtcConfirmation) -> Self {
        Self {
            txid: e2.btc_txid,
            confirmation,
            first_change_vout: e2.tx.withdrawal_outputs.len(),
        }
    }
}

/// A withdrawal transaction in Move's shape: the inputs, the user payouts, then
/// the change back to the bridge. Sui records it so, and the guardian's log is
/// converted into it, so the two can be compared as a whole.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WithdrawalTx {
    pub inputs: Vec<Utxo>,
    pub withdrawal_outputs: Vec<OutputUtxo>,
    pub change_outputs: Vec<OutputUtxo>,
}

impl WithdrawalTx {
    /// Move leaves an input's derivation path unset for change UTXOs. The
    /// guardian and the transaction builder read that as the zero path, so it
    /// is made explicit here and the two sources compare equal.
    pub fn new(
        inputs: Vec<Utxo>,
        withdrawal_outputs: Vec<OutputUtxo>,
        change_outputs: Vec<OutputUtxo>,
    ) -> Self {
        let inputs = inputs
            .into_iter()
            .map(|input| Utxo {
                derivation_path: Some(input.derivation_path.unwrap_or(DerivationPath::ZERO)),
                ..input
            })
            .collect();
        Self {
            inputs,
            withdrawal_outputs,
            change_outputs,
        }
    }

    /// The UTXOs the guardian signed, in Move's shape. The guardian labels
    /// each output external, to a user address, or internal, to the bridge
    /// address of a derivation path. The external outputs are Move's user
    /// payouts and the internal ones its change, each with the address as a
    /// witness program.
    pub fn from_guardian(keys: &HashiBTCKeys, utxos: &TxUTXOsWire) -> anyhow::Result<Self> {
        let inputs = utxos
            .inputs
            .iter()
            .map(|input| Utxo {
                id: UtxoId {
                    txid: input.outpoint.txid.into(),
                    vout: input.outpoint.vout,
                },
                amount: input.amount.to_sat(),
                derivation_path: Some(input.derivation_path),
            })
            .collect();
        let mut withdrawal_outputs = Vec::new();
        let mut change_outputs = Vec::new();
        for output in &utxos.outputs {
            match output {
                OutputUTXOWire::External(external) => {
                    let address = external
                        .address
                        .clone()
                        .require_network(keys.network())
                        .context("guardian external output address is for another network")?;
                    withdrawal_outputs.push(OutputUtxo {
                        amount: external.amount.to_sat(),
                        bitcoin_address: witness_program_from_address(&address)?,
                    });
                }
                OutputUTXOWire::Internal(internal) => change_outputs.push(OutputUtxo {
                    amount: internal.amount.to_sat(),
                    bitcoin_address: witness_program_from_address(
                        &keys.address(Some(&internal.derivation_path)),
                    )?,
                }),
            }
        }
        Ok(Self::new(inputs, withdrawal_outputs, change_outputs))
    }

    /// The unsigned Bitcoin transaction these inputs and outputs build.
    pub fn unsigned_tx(&self) -> anyhow::Result<Transaction> {
        let outputs = [&self.withdrawal_outputs[..], &self.change_outputs[..]].concat();
        unsigned_withdrawal_tx(&self.inputs, &outputs)
    }
}

impl fmt::Display for WithdrawalTx {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn outputs(outputs: &[OutputUtxo]) -> String {
            outputs
                .iter()
                .map(|output| format!("{}:{}", hex::encode(&output.bitcoin_address), output.amount))
                .collect::<Vec<_>>()
                .join(",")
        }
        let inputs = self
            .inputs
            .iter()
            .map(|input| {
                format!(
                    "{}:{}:{}:{}",
                    bitcoin::Txid::from(input.id.txid),
                    input.id.vout,
                    input.amount,
                    input.derivation_path.unwrap_or(DerivationPath::ZERO),
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        write!(
            formatter,
            "inputs=[{inputs}], payouts=[{}], change=[{}]",
            outputs(&self.withdrawal_outputs),
            outputs(&self.change_outputs),
        )
    }
}

/// Event source or type.
/// Note: Make sure WithdrawalEventType::NON_TERMINAL_EVENTS and TERMINAL_EVENT are up-to-date.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum WithdrawalEventType {
    /// E_hashi (WithdrawalPickedForProcessing on sui)
    E1HashiApproved,
    /// E_guardian (NormalWithdrawalSuccess on s3)
    E2GuardianApproved,
    /// E_btc
    E3BtcConfirmed,
}

impl WithdrawalEventType {
    pub const NON_TERMINAL_EVENTS: [WithdrawalEventType; 2] =
        [Self::E1HashiApproved, Self::E2GuardianApproved];
    pub const TERMINAL_EVENT: Self = Self::E3BtcConfirmed;

    pub fn successor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => Some(WithdrawalEventType::E2GuardianApproved),
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E3BtcConfirmed),
            WithdrawalEventType::E3BtcConfirmed => None,
        }
    }

    pub fn predecessor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => None,
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E1HashiApproved),
            WithdrawalEventType::E3BtcConfirmed => Some(WithdrawalEventType::E2GuardianApproved),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::p2wpkh;
    use crate::test_utils::test_hashi_btc_keys;
    use crate::test_utils::txid;
    use crate::test_utils::withdrawal_tx;
    use bitcoin::Amount;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::InputUTXO;
    use hashi_types::bitcoin::OutputUTXOWire;
    use hashi_types::bitcoin::TxUTXOsWire;
    use hashi_types::bitcoin::witness_program_from_address;

    #[test]
    fn the_guardians_utxos_convert_to_moves_shape() {
        let keys = test_hashi_btc_keys();
        let input_path = DerivationPath::new([0x52; 32]);
        let change_path = DerivationPath::new([0x42; 32]);
        let outpoint = OutPoint {
            txid: txid(0x51),
            vout: 1,
        };
        let user_address = BitcoinAddress::from_script(&p2wpkh(0x53), keys.network()).unwrap();
        let utxos = TxUTXOsWire {
            inputs: vec![InputUTXO::new(
                outpoint,
                Amount::from_sat(120_000),
                input_path,
            )],
            outputs: vec![
                OutputUTXOWire::external(user_address.into_unchecked(), Amount::from_sat(100_000)),
                OutputUTXOWire::internal(change_path, Amount::from_sat(19_000)),
            ],
        };

        assert_eq!(
            WithdrawalTx::from_guardian(&keys, &utxos).unwrap(),
            withdrawal_tx(witness_program_from_address(&keys.address(Some(&change_path))).unwrap())
        );
    }

    #[test]
    fn an_e2_whose_layout_does_not_hash_to_its_txid_is_a_finding() {
        let wid = sui_sdk_types::Address::new([0x3d; 32]);
        let tx = withdrawal_tx(vec![0x54; 20]);
        let computed = tx.unsigned_tx().unwrap().compute_txid();
        let claimed = txid(0x99);

        let findings = MonitorWithdrawalEvent::checked(
            WithdrawalEventType::E2GuardianApproved,
            wid,
            claimed,
            tx.clone(),
            100,
        )
        .unwrap_err();

        assert_eq!(
            findings,
            vec![MonitorFinding::WithdrawalTxidMismatch {
                wid,
                claimed,
                computed,
            }]
        );
        let event = MonitorWithdrawalEvent::checked(
            WithdrawalEventType::E2GuardianApproved,
            wid,
            computed,
            tx,
            100,
        )
        .unwrap();
        assert_eq!(event.event_type, WithdrawalEventType::E2GuardianApproved);
    }

    #[test]
    fn an_external_address_for_another_network_is_an_error() {
        let keys = test_hashi_btc_keys();
        let mainnet = BitcoinAddress::from_script(&p2wpkh(0x53), Network::Bitcoin).unwrap();
        let utxos = TxUTXOsWire {
            inputs: vec![InputUTXO::new(
                OutPoint::null(),
                Amount::from_sat(1),
                DerivationPath::ZERO,
            )],
            outputs: vec![OutputUTXOWire::external(
                mainnet.into_unchecked(),
                Amount::from_sat(1),
            )],
        };

        assert!(WithdrawalTx::from_guardian(&keys, &utxos).is_err());
    }
}
