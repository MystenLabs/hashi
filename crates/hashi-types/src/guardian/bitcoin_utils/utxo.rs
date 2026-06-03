// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! UTXO and transaction types for guardian withdrawals.
//!
//! Two classes of types exist here:
//! - Types with checked addresses that implement Serialize but not Deserialize
//! - Wire types with unchecked addresses that implement both Serialize and Deserialize
//!
//! Internal-output addresses are derived via `super::taproot`.

use super::BTC_LIB;
use super::DerivationPath;
use super::taproot::compute_taproot_artifacts;
use crate::guardian::BitcoinAddress;
use crate::guardian::BitcoinKeypair;
use crate::guardian::BitcoinPubkey;
use crate::guardian::BitcoinSignature;
use crate::guardian::GuardianError::InvalidInputs;
use crate::guardian::GuardianResult;
use crate::guardian::HashiMasterG;
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkChecked;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::*;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashSet;

// ---------------------------------
//    Core Data Structures
// ---------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InputUTXO {
    outpoint: OutPoint,
    amount: Amount,
    derivation_path: DerivationPath,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ExternalOutputUTXO {
    /// Bitcoin address to withdraw to
    address: BitcoinAddress<NetworkChecked>,
    /// Amount in satoshis
    amount: Amount,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InternalOutputUTXO {
    /// The derivation path
    derivation_path: DerivationPath,
    /// Amount in satoshis
    amount: Amount,
}

/// Withdrawal destination and amount.
/// External amounts count towards rate limits whereas internal amounts don't.
/// Internal address is derived inside the enclave to ensure that it is actually internal.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub enum OutputUTXO {
    External(ExternalOutputUTXO),
    Internal(InternalOutputUTXO),
}

/// All the UTXOs associated with a withdrawal transaction
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct TxUTXOs {
    /// Inputs: internal
    inputs: Vec<InputUTXO>,
    /// Outputs: either external or internal
    outputs: Vec<OutputUTXO>,
}

// ---------------------------------
//    Implementations
// ---------------------------------

/// Validates that an unchecked address is valid for `network` and returns a checked address.
fn validate_address_for_network(
    address: &BitcoinAddress<NetworkUnchecked>,
    network: Network,
) -> GuardianResult<BitcoinAddress<NetworkChecked>> {
    // Prefer the library's checked conversion to avoid accidentally assuming correctness.
    address.clone().require_network(network).map_err(|_| {
        InvalidInputs(format!(
            "invalid address {:?} for network {}",
            address, network
        ))
    })
}

/// Represents an input to be spent.
///
/// All inputs are expected to be P2TR (Pay-to-Taproot) since spending is done via taproot script path.
impl InputUTXO {
    pub fn new(
        outpoint: OutPoint,
        amount: Amount,
        derivation_path: DerivationPath,
    ) -> GuardianResult<Self> {
        if amount == Amount::ZERO {
            return Err(InvalidInputs("input amount must be > 0".into()));
        }
        Ok(Self {
            outpoint,
            amount,
            derivation_path,
        })
    }

    pub fn from_wire(input: InputUTXOWire) -> GuardianResult<Self> {
        Self::new(input.outpoint, input.amount, input.derivation_path)
    }

    /// Returns a `TxIn` for this UTXO with placeholder witness data.
    ///
    /// The witness will be populated later after signing.
    pub fn txin(&self) -> TxIn {
        TxIn {
            previous_output: self.outpoint,
            // No script sig needed for taproot
            script_sig: ScriptBuf::default(),
            // Enables RBF, disables relative lock time, allows absolute lock time
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            // Witness will be set later
            witness: Witness::default(),
        }
    }

    /// Prevout `TxOut` and tap leaf hash for sighash, derived from the path.
    fn prevout_and_leaf_hash(
        &self,
        enclave_pubkey: &BitcoinPubkey,
        hashi_master_g: &HashiMasterG,
    ) -> (TxOut, TapLeafHash) {
        let (script_pubkey, leaf_hash) =
            compute_taproot_artifacts(enclave_pubkey, hashi_master_g, &self.derivation_path);
        (
            TxOut {
                value: self.amount,
                script_pubkey,
            },
            leaf_hash,
        )
    }
}

impl InternalOutputUTXO {
    pub fn new(derivation_path: DerivationPath, amount: Amount) -> Self {
        Self {
            derivation_path,
            amount,
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        self.derivation_path
    }
    pub fn amount(&self) -> Amount {
        self.amount
    }
}

impl ExternalOutputUTXO {
    /// Constructs a new `ExternalOutputUTXO` and validates the address for the network.
    pub fn new(
        address: BitcoinAddress<NetworkUnchecked>,
        amount: Amount,
        network: Network,
    ) -> GuardianResult<Self> {
        if amount == Amount::ZERO {
            return Err(InvalidInputs("output amount must be > 0".into()));
        }
        let address = validate_address_for_network(&address, network)?;
        Ok(Self { address, amount })
    }

    pub fn from_wire(input: ExternalOutputUTXOWire, network: Network) -> GuardianResult<Self> {
        Self::new(input.address, input.amount, network)
    }
}
/// Represents an output destination for a withdrawal.
///
/// Outputs can be **external** (to a user-provided address) or **internal** (change, derived inside enclave).
impl OutputUTXO {
    /// Constructs a new `OutputUTXO::External` variant.
    pub fn new_external(
        address: BitcoinAddress<NetworkUnchecked>,
        amount: Amount,
        network: Network,
    ) -> GuardianResult<Self> {
        Ok(OutputUTXO::External(ExternalOutputUTXO::new(
            address, amount, network,
        )?))
    }

    /// Constructs a new `OutputUTXO::Internal` variant.
    pub fn new_internal(derivation_path: DerivationPath, amount: Amount) -> Self {
        OutputUTXO::Internal(InternalOutputUTXO {
            derivation_path,
            amount,
        })
    }

    pub fn from_wire(output: OutputUTXOWire, network: Network) -> GuardianResult<Self> {
        Ok(match output {
            OutputUTXOWire::External(external) => {
                OutputUTXO::External(ExternalOutputUTXO::from_wire(external, network)?)
            }
            OutputUTXOWire::Internal(internal) => OutputUTXO::Internal(internal),
        })
    }

    /// Returns the output amount in satoshis.
    pub fn amount(&self) -> Amount {
        match self {
            OutputUTXO::External(ExternalOutputUTXO { amount, .. }) => *amount,
            OutputUTXO::Internal(InternalOutputUTXO { amount, .. }) => *amount,
        }
    }

    /// Constructs a `TxOut` for this output.
    ///
    /// `hashi_master_g` is the raw MPC verifying key (with y-parity preserved).
    /// Internal outputs derive their child key from this raw G — using only
    /// the x-only/even-y projection would silently produce a different child
    /// key for half of all MPC vks, breaking the 2-of-2 leaf script.
    pub fn to_txout(&self, enclave_pubkey: &BitcoinPubkey, hashi_master_g: &HashiMasterG) -> TxOut {
        match self {
            OutputUTXO::External(ExternalOutputUTXO { address, amount }) => TxOut {
                value: *amount,
                script_pubkey: address.script_pubkey(),
            },
            OutputUTXO::Internal(InternalOutputUTXO {
                derivation_path,
                amount,
            }) => {
                let scripts =
                    compute_taproot_artifacts(enclave_pubkey, hashi_master_g, derivation_path);
                TxOut {
                    value: *amount,
                    script_pubkey: scripts.0,
                }
            }
        }
    }
}

impl TxUTXOs {
    /// Constructs a new `TxUTXOs` and validates all invariants.
    pub fn new(inputs: Vec<InputUTXO>, outputs: Vec<OutputUTXO>) -> GuardianResult<Self> {
        if inputs.is_empty() {
            return Err(InvalidInputs("input utxos must not be empty".into()));
        }
        if outputs.is_empty() {
            return Err(InvalidInputs("output utxos must not be empty".into()));
        }

        // Disallow duplicate inputs (same txid,vout), which would result in an invalid transaction.
        let mut seen_inputs: HashSet<OutPoint> = HashSet::with_capacity(inputs.len());
        for utxo in &inputs {
            if !seen_inputs.insert(utxo.outpoint) {
                return Err(InvalidInputs(format!(
                    "duplicate input outpoint: {}",
                    utxo.outpoint
                )));
            }
        }

        let tx_info = Self { inputs, outputs };

        // Enforce the intended invariant: fees > 0.
        tx_info.assert_positive_fees()?;

        Ok(tx_info)
    }

    /// Returns a reference to the inputs.
    pub fn get_inputs(&self) -> &[InputUTXO] {
        &self.inputs
    }

    /// Returns a reference to the outputs.
    pub fn get_outputs(&self) -> &[OutputUTXO] {
        &self.outputs
    }

    /// Constructs all outputs (both external and internal).
    ///
    /// For `External` outputs, uses the user-provided address. For `Internal` outputs,
    /// derives a taproot address using the enclave and hashi keys.
    pub fn compute_all_outputs(
        &self,
        enclave_pubkey: &BitcoinPubkey,
        hashi_master_g: &HashiMasterG,
    ) -> Vec<TxOut> {
        self.outputs
            .iter()
            .map(|utxo| utxo.to_txout(enclave_pubkey, hashi_master_g))
            .collect()
    }

    pub fn external_outs(&self) -> Vec<&ExternalOutputUTXO> {
        self.outputs
            .iter()
            .filter_map(|utxo| match utxo {
                OutputUTXO::External(x) => Some(x),
                OutputUTXO::Internal(_) => None,
            })
            .collect::<Vec<_>>()
    }

    pub fn external_out_amount(&self) -> Amount {
        self.outputs
            .iter()
            .filter_map(|utxo| match utxo {
                OutputUTXO::External(x) => Some(x.amount),
                OutputUTXO::Internal(_) => None,
            })
            .sum()
    }

    /// BTC that leaves the pool when this txn broadcasts: `inputs - change`,
    /// equivalent to `external_out_amount + miner_fee`. The amount that
    /// consumes the rate-limiter (miner fee leaves the pool too; change
    /// flows back).
    pub fn gross_outflow_amount(&self) -> Amount {
        let inputs: Amount = self.inputs.iter().map(|i| i.amount).sum();
        let internal: Amount = self
            .outputs
            .iter()
            .filter_map(|utxo| match utxo {
                OutputUTXO::Internal(x) => Some(x.amount),
                OutputUTXO::External(_) => None,
            })
            .sum();
        inputs - internal
    }

    /// Constructs an unsigned Bitcoin transaction for these UTXOs.
    fn unsigned_tx(
        &self,
        enclave_pubkey: &BitcoinPubkey,
        hashi_master_g: &HashiMasterG,
    ) -> Transaction {
        let all_outputs = self.compute_all_outputs(enclave_pubkey, hashi_master_g);
        construct_tx(
            self.inputs.iter().map(|input| input.txin()).collect(),
            all_outputs,
        )
    }

    /// Constructs sighash messages for each input, ready for signing.
    ///
    /// Uses `taproot_script_spend_signature_hash` for script-path spending.
    pub fn signing_messages_and_txid(
        &self,
        enclave_pubkey: &BitcoinPubkey,
        hashi_master_g: &HashiMasterG,
    ) -> (Vec<Message>, Txid) {
        let tx = self.unsigned_tx(enclave_pubkey, hashi_master_g);
        // Derive each input's prevout + tap leaf hash from its path.
        let artifacts: Vec<(TxOut, TapLeafHash)> = self
            .inputs
            .iter()
            .map(|input| input.prevout_and_leaf_hash(enclave_pubkey, hashi_master_g))
            .collect();
        let prevouts: Vec<TxOut> = artifacts
            .iter()
            .map(|(prevout, _)| prevout.clone())
            .collect();

        let messages = artifacts
            .iter()
            .enumerate()
            .map(|(index, (_, leaf_hash))| {
                let mut sighasher = SighashCache::new(tx.clone());
                let sighash = sighasher
                    .taproot_script_spend_signature_hash(
                        index,
                        &Prevouts::All(&prevouts),
                        *leaf_hash,
                        TapSighashType::Default,
                    )
                    .expect("sighash failed unexpectedly");
                Message::from_digest(*sighash.as_byte_array())
            })
            .collect::<Vec<Message>>();
        (messages, tx.compute_txid())
    }

    fn assert_positive_fees(&self) -> GuardianResult<()> {
        let input_sum = self.inputs.iter().map(|utxo| utxo.amount).sum::<Amount>();
        let output_sum = self.outputs.iter().map(|utxo| utxo.amount()).sum();
        if input_sum <= output_sum {
            return Err(InvalidInputs(format!(
                "fees must be positive: input_sum={} output_sum={}",
                input_sum, output_sum
            )));
        }
        Ok(())
    }
}

// -------------------------------------------------
//      Transaction Construction & Signing
// -------------------------------------------------

/// Signs messages using Schnorr signatures (suitable for taproot script-spend).
///
/// Each message is signed and wrapped in a `Signature` with `TapSighashType::Default`.
pub fn sign_btc_tx(messages: &[Message], kp: &BitcoinKeypair) -> Vec<BitcoinSignature> {
    messages
        .iter()
        // Not using aux randomness which only provides side-channel protection
        .map(|m| BTC_LIB.sign_schnorr_no_aux_rand(m, kp))
        .map(|s| Signature {
            signature: s,
            sighash_type: TapSighashType::Default,
        })
        .collect()
}

/// Constructs a Bitcoin transaction with the given inputs and outputs.
///
/// Uses BTC tx version 2 and disables lock time.
pub fn construct_tx(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        // The latest BTC tx version
        version: Version::TWO,
        // Disable absolute lock time (i.e., can be mined immediately)
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

// ---------------------------------
//    Serialize / Deserialize
// ---------------------------------

/// Copy of bitcoin_utils::InputUTXO. Kept distinct from the domain type so
/// `TxUTXOsWire` stays a uniform wire shape alongside the output wire types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputUTXOWire {
    pub outpoint: OutPoint,
    pub amount: Amount,
    pub derivation_path: DerivationPath,
}

impl From<InputUTXO> for InputUTXOWire {
    fn from(input: InputUTXO) -> Self {
        Self {
            outpoint: input.outpoint,
            amount: input.amount,
            derivation_path: input.derivation_path,
        }
    }
}

/// Copy of bitcoin_utils::ExternalOutputUTXO with unchecked address
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Ord, PartialOrd)]
pub struct ExternalOutputUTXOWire {
    /// Bitcoin address to withdraw to
    pub address: BitcoinAddress<NetworkUnchecked>,
    /// Amount in satoshis
    pub amount: Amount,
}

impl From<ExternalOutputUTXO> for ExternalOutputUTXOWire {
    fn from(o: ExternalOutputUTXO) -> Self {
        Self {
            address: o.address.into_unchecked(),
            amount: o.amount,
        }
    }
}

/// Copy of bitcoin_utils::OutputUTXO with unchecked address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputUTXOWire {
    External(ExternalOutputUTXOWire),
    Internal(InternalOutputUTXO),
}

impl From<OutputUTXO> for OutputUTXOWire {
    fn from(o: OutputUTXO) -> Self {
        match o {
            OutputUTXO::External(o) => OutputUTXOWire::External(o.into()),
            OutputUTXO::Internal(o) => OutputUTXOWire::Internal(o),
        }
    }
}

/// Copy of bitcoin_utils::TxUTXOs with unchecked address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxUTXOsWire {
    /// Inputs: internal
    pub inputs: Vec<InputUTXOWire>,
    /// Outputs: either external or internal
    pub outputs: Vec<OutputUTXOWire>,
}

impl From<TxUTXOs> for TxUTXOsWire {
    fn from(utxos: TxUTXOs) -> Self {
        Self {
            inputs: utxos.inputs.into_iter().map(Into::into).collect(),
            outputs: utxos.outputs.into_iter().map(Into::into).collect(),
        }
    }
}
