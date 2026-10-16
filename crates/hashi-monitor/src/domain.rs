// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Domain model for the monitor.
//!
//! We model the cross-system withdrawal flow as a sequence of events:
//! - E1 or E_hashi: Hashi approval event on sui (corresponds to WithdrawalPickedForProcessing)
//! - E2 or E_guardian: Guardian approval event on S3 (corresponds to NormalWithdrawalSuccess)
//! - E3 or E_btc: BTC transaction confirmed
//!
//! Predecessor checks: every E_{i+1} has a corresponding E_i, and E_i does not
//! occur more than its configured clock skew after E_{i+1}.
//! Successor checks: for every E_i, there exists a corresponding E_{i+1} within time `t`.
//!
//! Note: IOP-203 matches the withdrawal destination & amount that a user inputs with that in E_hashi.
//! The monitor is insecure without this check as a malicious hashi committee can include an arbitrary destination address.

use std::fmt;

use anyhow::Context as _;
use bitcoin::Network;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxOut;
use bitcoin::Txid;
use hashi_guardian::s3_reader::VerifiedLogEntry;
use hashi_types::bitcoin::BitcoinAddress;
use hashi_types::bitcoin::BitcoinPubkey;
use hashi_types::bitcoin::DerivationPath;
use hashi_types::bitcoin::HashiMasterG;
use hashi_types::bitcoin::OutputUTXOWire;
use hashi_types::bitcoin::TxUTXOsWire;
use hashi_types::bitcoin::taproot_address;
use hashi_types::bitcoin::unsigned_withdrawal_tx;
use hashi_types::bitcoin::witness_program_from_address;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::time::UnixSeconds;
use hashi_types::guardian::unix_millis_to_seconds;
use hashi_types::move_types::DepositConfirmed;
use hashi_types::move_types::OutputUtxo;
use hashi_types::move_types::Utxo;
use hashi_types::move_types::UtxoId;
use hashi_types::move_types::WithdrawalPickedForProcessing;
use hashi_types::move_types::WithdrawalTransaction;
use serde::Deserialize;

use crate::findings::MonitorFinding;

/// Unix seconds rendered in the monitor's canonical UTC timestamp format.
pub struct UtcTimestamp(UnixSeconds);

pub fn utc_timestamp(timestamp: UnixSeconds) -> UtcTimestamp {
    UtcTimestamp(timestamp)
}

impl fmt::Display for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(timestamp) = i64::try_from(self.0)
            && let Ok(datetime) = time::OffsetDateTime::from_unix_timestamp(timestamp)
        {
            return write!(
                formatter,
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                datetime.year(),
                u8::from(datetime.month()),
                datetime.day(),
                datetime.hour(),
                datetime.minute(),
                datetime.second(),
            );
        }

        formatter.write_str("<invalid UTC timestamp>")
    }
}

/// Seconds rendered as a compact human-readable duration.
pub struct HumanDuration(UnixSeconds);

pub fn human_duration(seconds: UnixSeconds) -> HumanDuration {
    HumanDuration(seconds)
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hours = self.0 / 3_600;
        let minutes = (self.0 % 3_600) / 60;
        let seconds = self.0 % 60;

        if hours > 0 {
            write!(formatter, "{hours}h")?;
        }
        if minutes > 0 || hours > 0 {
            write!(formatter, "{minutes}m")?;
        }
        write!(formatter, "{seconds}s")
    }
}

/// Signed difference between two Unix timestamps, rendered compactly.
pub struct HumanTimestampDelta(i128);

pub fn human_timestamp_delta(later: UnixSeconds, earlier: UnixSeconds) -> HumanTimestampDelta {
    HumanTimestampDelta(i128::from(later) - i128::from(earlier))
}

impl fmt::Display for HumanTimestampDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 < 0 {
            formatter.write_str("-")?;
        }

        let total_seconds = self.0.unsigned_abs();
        let hours = total_seconds / 3_600;
        let minutes = (total_seconds % 3_600) / 60;
        let seconds = total_seconds % 60;

        if hours > 0 {
            write!(formatter, "{hours}h")?;
        }
        if minutes > 0 || hours > 0 {
            write!(formatter, "{minutes}m")?;
        }
        write!(formatter, "{seconds}s")
    }
}

/// Parse the monitor's sole public timestamp format: whole-second UTC RFC 3339.
pub fn parse_utc_timestamp(value: &str) -> Result<UnixSeconds, String> {
    if !value.ends_with('Z') {
        return Err(
            "timestamp must be UTC and end in `Z` (for example, 2026-08-04T19:00:00Z)".to_string(),
        );
    }

    let datetime =
        time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .map_err(|error| format!("invalid UTC timestamp `{value}`: {error}"))?;
    let timestamp = UnixSeconds::try_from(datetime.unix_timestamp())
        .map_err(|_| "timestamp must not precede 1970-01-01T00:00:00Z".to_string())?;
    if utc_timestamp(timestamp).to_string() != value {
        return Err(
            "timestamp must use exactly `YYYY-MM-DDTHH:MM:SSZ` with no fractional seconds"
                .to_string(),
        );
    }

    Ok(timestamp)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MonitorEvent {
    Withdrawal(MonitorWithdrawalEvent),
    Deposit(MonitorDepositEvent),
}

impl fmt::Display for MonitorEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Withdrawal(event) => write!(
                formatter,
                "Withdrawal(type={:?}, wid={}, timestamp={}, btc_txid={})",
                event.event_type,
                event.wid,
                utc_timestamp(event.timestamp_secs),
                event.btc_txid,
            ),
            Self::Deposit(event) => write!(
                formatter,
                "Deposit(type={:?}, deposit_id={}, timestamp={}, amount={}, script_pubkey={:x})",
                event.event_type,
                event.deposit_id,
                utc_timestamp(event.timestamp_secs),
                event.amount,
                event.script_pubkey,
            ),
        }
    }
}

/// Stable identifier for a monitored deposit: its Bitcoin outpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DepositId(OutPoint);

impl DepositId {
    pub fn new(txid: Txid, vout: u32) -> Self {
        Self(OutPoint { txid, vout })
    }

    pub fn txid(self) -> Txid {
        self.0.txid
    }

    pub fn vout(self) -> u32 {
        self.0.vout
    }
}

impl fmt::Display for DepositId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Correlation identifier for an event in the monitor's withdrawal or deposit model.
/// This is not a chain-native event ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorEventId {
    Withdrawal(WithdrawalID),
    Deposit(DepositId),
}

impl fmt::Display for MonitorEventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Withdrawal(wid) => write!(formatter, "wid={wid}"),
            Self::Deposit(deposit_id) => write!(formatter, "deposit_id={deposit_id}"),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum MonitorEventType {
    Withdrawal(WithdrawalEventType),
    Deposit(DepositEventType),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorWithdrawalEvent {
    /// Who produced the event?
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
        Self::checked_approval(
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
        Self::checked_approval(
            event.withdrawal_txn_id,
            event.txid.into(),
            WithdrawalTx::new(event.inputs, event.withdrawal_outputs, event.change_outputs),
            unix_millis_to_seconds(event.timestamp_ms),
        )
    }

    /// Check what Move does not on the Hashi approval of `wid`: the claimed
    /// txid must be the txid of the transaction `tx` builds. Otherwise a
    /// committee can commit a user's outputs under the txid of a transaction
    /// that pays itself. A failed check is returned as findings, and the
    /// approval is not ingested. The event carries `tx` for the state
    /// machine to compare with the guardian's once E2 arrives.
    fn checked_approval(
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
            event_type: WithdrawalEventType::E1HashiApproved,
            wid,
            timestamp_secs,
            btc_txid: claimed_txid,
            tx,
        })
    }

    /// E2 from a verified guardian withdrawal log. The log labels every
    /// output it signed; `keys` turn its change paths into addresses.
    pub fn from_guardian(log: VerifiedLogEntry, keys: &HashiBTCKeys) -> anyhow::Result<Self> {
        let entry = log.into_entry();
        let timestamp_ms = entry.timestamp_ms();
        let withdrawal = entry
            .into_message()
            .into_withdrawal()
            .ok_or_else(|| anyhow::anyhow!("non-withdrawal logs found"))?;
        Ok(Self {
            event_type: WithdrawalEventType::E2GuardianApproved,
            wid: withdrawal.request_data.wid,
            timestamp_secs: unix_millis_to_seconds(timestamp_ms),
            btc_txid: withdrawal.txid,
            tx: WithdrawalTx::from_guardian(keys, &withdrawal.request_data.utxos)?,
        })
    }

    /// E3 from Bitcoin's confirmation of the withdrawal `wid` and `btc_txid`.
    /// It repeats `tx`, which the state machine already holds.
    pub fn from_btc(
        confirmation: &TxConfirmation,
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
    /// Move leaves an input's derivation path unset for change coins. The
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
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Deserialize)]
pub enum WithdrawalEventType {
    /// E_hashi (WithdrawalPickedForProcessing on sui)
    E1HashiApproved,
    /// E_guardian (NormalWithdrawalSuccess on s3)
    E2GuardianApproved,
    /// E_btc
    E3BtcConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitorDepositEvent {
    pub event_type: DepositEventType,
    pub timestamp_secs: UnixSeconds,
    pub deposit_id: DepositId,
    /// Satoshis in the deposit output. Sui gives the claimed amount, Bitcoin
    /// the paid amount.
    pub amount: u64,
    /// Script the deposit output pays. Sui gives the bridge address of the
    /// claimed derivation path, Bitcoin the paid script.
    pub script_pubkey: ScriptBuf,
}

impl MonitorDepositEvent {
    /// E2 from Hashi's `DepositConfirmed`. Its Move payload has no
    /// timestamp, so the containing checkpoint's time is used. The claim's
    /// derivation path becomes the bridge script the state machine compares
    /// with the paid output.
    pub fn from_sui(
        event: DepositConfirmed,
        checkpoint_timestamp_secs: UnixSeconds,
        keys: &HashiBTCKeys,
    ) -> Self {
        Self {
            event_type: DepositEventType::E2HashiDeposited,
            timestamp_secs: checkpoint_timestamp_secs,
            deposit_id: DepositId::new(event.utxo.id.txid.into(), event.utxo.id.vout),
            amount: event.utxo.amount,
            script_pubkey: keys.script_pubkey(event.utxo.derivation_path.as_ref()),
        }
    }

    /// E1 from Bitcoin's confirmation: the output at `deposit_id`'s vout, or
    /// `None` if the transaction has no output there.
    pub fn from_btc(confirmation: &TxConfirmation, deposit_id: DepositId) -> Option<Self> {
        let output = confirmation.outputs.get(deposit_id.vout() as usize)?;
        Some(Self {
            event_type: DepositEventType::E1BtcConfirmed,
            timestamp_secs: confirmation.confirmed_time,
            deposit_id,
            amount: output.value.to_sat(),
            script_pubkey: output.script_pubkey.clone(),
        })
    }
}

/// A transaction mined at least `MIN_CONFIRMATIONS` blocks deep.
#[derive(Clone, Debug)]
pub struct TxConfirmation {
    /// The time of the block that holds the transaction. The recovery leaf's
    /// clock starts at this block, so a coin's age counts from here.
    pub block_time: UnixSeconds,
    /// The time of the block that gave the transaction `MIN_CONFIRMATIONS`.
    /// The bridge acts on that block, so the Bitcoin events carry this time.
    pub confirmed_time: UnixSeconds,
    /// The transaction's outputs, in order.
    pub outputs: Vec<TxOut>,
}

/// The two fixed keys that every bridge address derives from.
#[derive(Clone)]
pub struct HashiBTCKeys {
    guardian_btc_pubkey: BitcoinPubkey,
    mpc_master_g: HashiMasterG,
    network: Network,
}

impl HashiBTCKeys {
    pub fn new(
        guardian_btc_pubkey: BitcoinPubkey,
        mpc_master_g: HashiMasterG,
        network: Network,
    ) -> Self {
        Self {
            guardian_btc_pubkey,
            mpc_master_g,
            network,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The bridge address for `derivation_path`. A missing path is the zero
    /// path, as in Move.
    pub fn address(&self, derivation_path: Option<&DerivationPath>) -> BitcoinAddress {
        taproot_address(
            &self.guardian_btc_pubkey,
            &self.mpc_master_g,
            derivation_path.unwrap_or(&DerivationPath::ZERO),
            self.network,
        )
    }

    /// The script of the bridge address for `derivation_path`.
    pub fn script_pubkey(&self, derivation_path: Option<&DerivationPath>) -> ScriptBuf {
        self.address(derivation_path).script_pubkey()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum DepositEventType {
    /// deposit confirmed event on btc
    E1BtcConfirmed,
    /// `DepositConfirmed` on Sui. Its timestamp is the containing checkpoint's
    /// timestamp, supplied with the transaction by Sui gRPC.
    E2HashiDeposited,
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

    pub fn has_successor(&self) -> bool {
        self.successor().is_some()
    }

    pub fn predecessor(&self) -> Option<Self> {
        match self {
            WithdrawalEventType::E1HashiApproved => None,
            WithdrawalEventType::E2GuardianApproved => Some(WithdrawalEventType::E1HashiApproved),
            WithdrawalEventType::E3BtcConfirmed => Some(WithdrawalEventType::E2GuardianApproved),
        }
    }
}

/// Per-source cursors tracking how far we've read from each data source.
#[derive(Clone, Copy, Debug)]
pub struct Cursors {
    pub sui: UnixSeconds,
    pub guardian: UnixSeconds,
}

impl Cursors {
    pub fn for_event_type(&self, et: WithdrawalEventType) -> UnixSeconds {
        match et {
            WithdrawalEventType::E1HashiApproved => self.sui,
            WithdrawalEventType::E2GuardianApproved => self.guardian,
            WithdrawalEventType::E3BtcConfirmed => {
                unreachable!("E3 cursor is tracked per-withdrawal via btc_checked_at")
            }
        }
    }

    pub fn min(&self) -> UnixSeconds {
        self.sui.min(self.guardian)
    }
}

/// Outcome of a Guardian or Sui poll
pub enum PollOutcome {
    /// The events of the newly scanned range, and the findings of events that failed a check.
    CursorAdvanced {
        events: Vec<MonitorEvent>,
        findings: Vec<MonitorFinding>,
    },
    CursorUnmoved,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::sui::approval::tests::test_hashi_btc_keys;
    use bitcoin::Amount;
    use bitcoin::Network;
    use bitcoin::OutPoint;
    use bitcoin::ScriptBuf;
    use bitcoin::WPubkeyHash;
    use bitcoin::hashes::Hash as _;
    use hashi_types::bitcoin::BitcoinAddress;
    use hashi_types::bitcoin::DerivationPath;
    use hashi_types::bitcoin::InputUTXO;
    use hashi_types::bitcoin::OutputUTXOWire;
    use hashi_types::bitcoin::TxUTXOsWire;
    use hashi_types::bitcoin::witness_program_from_address;
    use hashi_types::move_types::UtxoId;

    #[test]
    fn the_guardians_utxos_convert_to_moves_shape() {
        let keys = test_hashi_btc_keys();
        let input_path = DerivationPath::new([0x52; 32]);
        let change_path = DerivationPath::new([0x42; 32]);
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_slice(&[0x51; 32]).unwrap(),
            vout: 1,
        };
        let user_script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x53; 20]));
        let user_address = BitcoinAddress::from_script(&user_script, keys.network()).unwrap();
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
            WithdrawalTx {
                inputs: vec![Utxo {
                    id: UtxoId {
                        txid: outpoint.txid.into(),
                        vout: 1,
                    },
                    amount: 120_000,
                    derivation_path: Some(input_path),
                }],
                withdrawal_outputs: vec![OutputUtxo {
                    amount: 100_000,
                    bitcoin_address: vec![0x53; 20],
                }],
                change_outputs: vec![OutputUtxo {
                    amount: 19_000,
                    bitcoin_address: witness_program_from_address(
                        &keys.address(Some(&change_path))
                    )
                    .unwrap(),
                }],
            }
        );
    }

    #[test]
    fn an_external_address_for_another_network_is_an_error() {
        let keys = test_hashi_btc_keys();
        let mainnet = BitcoinAddress::from_script(
            &ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x53; 20])),
            Network::Bitcoin,
        )
        .unwrap();
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

    #[test]
    fn utc_timestamp_round_trip() {
        let input = "2026-08-04T19:45:38Z";
        let timestamp = parse_utc_timestamp(input).unwrap();
        assert_eq!(utc_timestamp(timestamp).to_string(), input);
    }

    #[test]
    fn timestamp_parser_requires_canonical_utc_format() {
        assert!(parse_utc_timestamp("1785872738").is_err());
        assert!(parse_utc_timestamp("2026-08-04T19:45:38+00:00").is_err());
        assert!(parse_utc_timestamp("2026-08-04T19:45:38.000Z").is_err());
    }

    #[test]
    fn duration_uses_compact_human_readable_format() {
        assert_eq!(human_duration(0).to_string(), "0s");
        assert_eq!(human_duration(191).to_string(), "3m11s");
        assert_eq!(human_duration(4_028).to_string(), "1h7m8s");
        assert_eq!(human_timestamp_delta(100, 120).to_string(), "-20s");
    }
}
