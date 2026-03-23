// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! UTXO pool management and coin selection for Bitcoin withdrawal transactions.
//!
//! This module provides a coin selection algorithm that simultaneously:
//! - Selects UTXOs to fund one or more withdrawal requests in a single transaction.
//! - Amortises UTXO pool maintenance by aggressively consolidating inputs back
//!   into a small target number of UTXOs via a change output.
//!
//! The miner fee is split equally among the selected withdrawal requests and
//! deducted from each request's output amount. The fee must not exceed a
//! configurable per-request cap (`CoinSelectionParams::max_fee_per_request`),
//! and is sourced entirely from the request amounts. When spending
//! unconfirmed change (CPFP), the per-request deduction also includes any
//! deficit needed to bring the ancestor package fee rate up to the target.
//! The fund balance decreases by `sum(request.amounts)` for confirmed inputs
//! and by `sum(request.amounts) + cpfp_deficit` when ancestor boosting is
//! needed.

use bitcoin::Address as BitcoinAddress;
use bitcoin::FeeRate;
use bitcoin::Weight;
use sui_sdk_types::Address;
use thiserror::Error;

use crate::onchain::types::UtxoId;

#[cfg(test)]
mod tests;

// ── Constants ────────────────────────────────────────────────────────────────

/// Base weight of a segwit transaction input (non-witness portion).
///
/// nSequence(4) + prevout_txid(32) + prevout_vout(4) + script_sig_len(1)
///   = 41 bytes × 4 = 164 WU
const TXIN_BASE_WEIGHT: Weight = Weight::from_wu(164);

/// Base weight of a transaction output (amount + script-length varint).
///
/// amount(8) + script_len_varint(1) = 9 bytes × 4 = 36 WU.
/// The scriptPubKey weight is added separately.
const TXOUT_BASE_WEIGHT: Weight = Weight::from_wu(36);

/// Minimum value (sat) for a P2PKH or P2SH output to be above the dust
/// relay threshold at Bitcoin's default dust relay fee of 3 sat/vByte.
/// This is the legacy dust limit and the highest of the three thresholds.
#[allow(dead_code)]
const DUST_RELAY_MIN_VALUE: u64 = 546;

/// Minimum value (sat) for a P2TR (or P2WSH) output to be above the dust
/// relay threshold at Bitcoin's default dust relay fee of 3 sat/vByte.
/// Outputs below this value will not be relayed by default Bitcoin nodes.
const TR_DUST_RELAY_MIN_VALUE: u64 = 330;

/// Minimum value (sat) for a P2WPKH output to be above the dust relay
/// threshold at Bitcoin's default dust relay fee of 3 sat/vByte.
const WPKH_DUST_RELAY_MIN_VALUE: u64 = 294;

// ── Spend Path ───────────────────────────────────────────────────────────────

/// Describes the spend path for a UTXO, used to calculate the witness
/// satisfaction weight and thus the full input weight contribution to a
/// transaction.
#[derive(Clone, Debug)]
pub enum SpendPath {
    /// Taproot script-path 2-of-2 multisig spend.
    ///
    /// Witness items:
    ///   items_count(1) + sig1_len(1) + sig1(64) + sig2_len(1) + sig2(64)
    ///     + script_len(1) + script(68) + control_block_len(1) + control_block(33)
    ///   = 234 WU
    TaprootScriptPath2of2,

    /// Taproot key-path spend (single x-only Schnorr signature).
    ///
    /// Witness items:
    ///   items_count(1) + sig_len(1) + sig(64) = 66 WU
    TaprootKeyPath,

    /// Custom witness satisfaction weight, for non-standard spend paths.
    Custom(Weight),
}

impl SpendPath {
    /// Returns the witness-only satisfaction weight.
    pub fn satisfaction_weight(&self) -> Weight {
        match self {
            SpendPath::TaprootScriptPath2of2 => Weight::from_wu(234),
            SpendPath::TaprootKeyPath => Weight::from_wu(66),
            SpendPath::Custom(w) => *w,
        }
    }

    /// Returns the total input weight: `TXIN_BASE_WEIGHT` (164 WU) + satisfaction weight.
    pub fn input_weight(&self) -> Weight {
        TXIN_BASE_WEIGHT
            .checked_add(self.satisfaction_weight())
            .expect("input weight overflow")
    }
}

// ── UTXO Status ──────────────────────────────────────────────────────────────

/// An ancestor transaction in an unconfirmed UTXO's chain.
///
/// Each entry represents a transaction that must confirm before the
/// UTXO is fully settled. The chain is ordered from the UTXO's
/// creating transaction (index 0) back to the oldest unconfirmed
/// ancestor.
#[derive(Clone, Debug)]
pub struct AncestorTx {
    /// Number of confirmations. `0` means the transaction is in the
    /// mempool only (not yet included in a block). Values `1..N`
    /// mean it has been included but has not yet reached the
    /// finality threshold.
    pub confirmations: u32,
    /// The total weight of this transaction.
    pub tx_weight: Weight,
    /// The total fee paid by this transaction in satoshis.
    pub tx_fee: u64,
}

/// The confirmation status of a UTXO.
#[derive(Clone, Debug)]
pub enum UtxoStatus {
    /// The UTXO and all of its ancestors have reached the finality
    /// threshold (e.g., 6 confirmations). Safe to spend without any
    /// concern for reorgs or rebroadcasting.
    Confirmed,

    /// The UTXO has an unconfirmed or insufficiently confirmed
    /// ancestor chain.
    ///
    /// `chain[0]` is the transaction that created this UTXO.
    /// `chain[1]` is its parent (if unconfirmed), and so on back to
    /// the oldest unconfirmed ancestor. The chain is empty only for
    /// `Confirmed` UTXOs (which use the `Confirmed` variant instead).
    ///
    /// This information is used to:
    /// - Compute the **package fee rate** for CPFP: the effective
    ///   rate of a new transaction spending this UTXO is
    ///   `(sum(chain.tx_fee) + new_fee) / (sum(chain.tx_weight) + new_weight)`.
    /// - Enforce a **maximum chain depth** policy (e.g., never chain
    ///   deeper than 3 unconfirmed transactions).
    /// - Determine how much extra fee a child transaction must pay
    ///   to boost underpaying ancestors.
    Pending {
        /// The ancestor chain, from this UTXO's creating transaction
        /// back to the oldest unconfirmed ancestor.
        chain: Vec<AncestorTx>,
    },
}

impl UtxoStatus {
    /// Returns the full depth of the ancestor chain (both mempool and
    /// insufficiently confirmed). `0` for confirmed UTXOs,
    /// `chain.len()` for pending ones.
    pub fn chain_depth(&self) -> usize {
        match self {
            UtxoStatus::Confirmed => 0,
            UtxoStatus::Pending { chain } => chain.len(),
        }
    }

    /// Returns the number of ancestors still in the mempool (0
    /// confirmations). This is the depth that matters for Bitcoin
    /// relay policy limits. Ancestors with 1+ confirmations are
    /// already in blocks and don't count toward the mempool chain
    /// limit.
    pub fn mempool_chain_depth(&self) -> usize {
        match self {
            UtxoStatus::Confirmed => 0,
            UtxoStatus::Pending { chain } => chain.iter().filter(|a| a.confirmations == 0).count(),
        }
    }

    /// Returns the total weight of all unconfirmed ancestors
    /// (transactions with 0 confirmations).
    pub fn unconfirmed_ancestor_weight(&self) -> Weight {
        match self {
            UtxoStatus::Confirmed => Weight::ZERO,
            UtxoStatus::Pending { chain } => chain
                .iter()
                .filter(|a| a.confirmations == 0)
                .map(|a| a.tx_weight)
                .sum(),
        }
    }

    /// Returns the total fee paid by all unconfirmed ancestors
    /// (transactions with 0 confirmations).
    pub fn unconfirmed_ancestor_fee(&self) -> u64 {
        match self {
            UtxoStatus::Confirmed => 0,
            UtxoStatus::Pending { chain } => chain
                .iter()
                .filter(|a| a.confirmations == 0)
                .map(|a| a.tx_fee)
                .sum(),
        }
    }
}

// ── UTXO Candidate ───────────────────────────────────────────────────────────

/// A UTXO available for selection as a transaction input.
#[derive(Clone, Debug)]
pub struct UtxoCandidate {
    /// The on-chain identifier for this UTXO (txid + vout).
    pub id: UtxoId,
    /// The value of this UTXO in satoshis.
    pub amount: u64,
    /// The spend path for this UTXO, used to compute the weight contribution
    /// of this input to the transaction.
    pub spend_path: SpendPath,
    /// Whether this UTXO is confirmed on-chain or still pending/unconfirmed.
    pub status: UtxoStatus,
}

// ── Withdrawal Request ───────────────────────────────────────────────────────

/// A withdrawal request candidate for inclusion in a Bitcoin transaction.
///
/// This is the coin-selection view of a withdrawal; it contains only the
/// fields needed by the algorithm. Callers should construct this from the
/// on-chain [`crate::onchain::types::WithdrawalRequest`].
#[derive(Clone, Debug)]
pub struct WithdrawalRequest {
    /// Unique identifier for this withdrawal (Sui object ID / request ID).
    pub id: Address,
    /// Raw witness-program bytes of the recipient Bitcoin address.
    ///
    /// Used to build the output scriptPubKey and to compute the output weight
    /// contribution to the transaction.
    pub recipient: Vec<u8>,
    /// Withdrawal amount in satoshis. This is the exact amount the fund
    /// releases; the miner fee is deducted from it before the remainder is
    /// sent to `recipient`.  The fund balance decreases by exactly this value
    /// regardless of the fee rate.
    pub amount: u64,
    /// Unix timestamp in milliseconds when the withdrawal was submitted.
    /// Used to prioritise older requests over newer ones.
    pub timestamp_ms: u64,
}

// ── Algorithm Parameters ─────────────────────────────────────────────────────

/// Tuning parameters for the coin selection algorithm.
#[derive(Clone, Debug)]
pub struct CoinSelectionParams {
    /// Upper bound on transaction weight. The algorithm will not propose a
    /// transaction that exceeds this limit.
    pub max_tx_weight: Weight,

    /// Hard cap on the total number of transaction inputs, covering both the
    /// primary inputs selected in Step 2 and any consolidation inputs added in
    /// Step 3.
    pub max_inputs: usize,

    /// Maximum number of withdrawal requests that may be batched into a single
    /// transaction.
    pub max_withdrawal_requests: usize,

    /// Maximum miner fee in satoshis that may be deducted from any single
    /// request's amount. The batch is rejected if `total_fee / N` would exceed
    /// this value for the selected set of N requests. Sourced from
    /// [`crate::onchain::types::Config::worst_case_network_fee`], which is
    /// derived from `high_fee_rate_threshold` and the worst-case transaction
    /// shape.
    pub max_fee_per_request: u64,

    /// Absolute minimum fee rate (floor). The actual fee rate passed to
    /// [`select_coins`] should be clamped to at least this value before the
    /// call; it is also used as the lower bound when computing the available
    /// consolidation budget.
    pub min_fee_rate: FeeRate,

    /// Expected long-term average fee rate (e.g., 10 sat/vB, matching
    /// Bitcoin Core's `-consolidatefeerate` default). Divides the fee
    /// environment into two regimes:
    ///
    /// - **Below this rate:** consolidation is cheap. The algorithm
    ///   aggressively pulls in extra inputs (up to `max_inputs`) to
    ///   reduce the UTXO set while fees are favourable.
    /// - **At or above this rate:** input selection is aggressively
    ///   minimized. Consolidation is capped at `input_budget` extra
    ///   inputs per request, and no pool consolidation is performed
    ///   beyond what is strictly required to fund the withdrawals.
    pub long_term_fee_rate: FeeRate,

    /// The fee rate threshold at which the algorithm aggressively
    /// minimizes inputs and performs no pool consolidation.
    /// `max_fee_per_request` is derived from this rate applied to the
    /// worst-case transaction shape. Also used as the reference point
    /// for scaling the consolidation budget: `max_fee_per_request` is
    /// proportionally scaled from this rate to `long_term_fee_rate`
    /// when computing the low-fee consolidation budget.
    pub high_fee_rate_threshold: FeeRate,

    /// Maximum number of extra consolidation inputs per request when the
    /// fee rate is at or above `long_term_fee_rate`. At high fee rates,
    /// consolidation is capped at `input_budget × N` extra inputs; below
    /// the long-term rate the cap is lifted (bounded only by `max_inputs`).
    /// Matches the on-chain `input_budget` config parameter.
    pub input_budget: usize,

    /// Maximum number of mempool-only (0-confirmation) ancestors a
    /// UTXO may have and still be eligible as an input. This
    /// constrains how deep the chain of unconfirmed transactions can
    /// grow, staying within Bitcoin's relay policy limits.
    ///
    /// Only ancestors with 0 confirmations count toward this limit.
    /// Ancestors already included in a block (1+ confirmations, even
    /// if below the 6-confirmation finality threshold) do not count
    /// — they are settled from a mempool policy perspective.
    ///
    /// A value of 0 means only confirmed UTXOs (or those whose
    /// entire ancestor chain has at least 1 confirmation) are
    /// eligible. A value of 3 allows spending UTXOs with up to 3
    /// mempool-only ancestors.
    pub max_mempool_chain_depth: usize,

    /// Bitcoin address to receive the consolidation/change output.
    pub change_address: BitcoinAddress,
}

impl CoinSelectionParams {
    /// Default maximum transaction weight (400 kWU). This matches
    /// Bitcoin Core's `MAX_STANDARD_TX_WEIGHT` policy limit — the
    /// maximum weight a transaction can have and still be relayed by
    /// default nodes. It is 10% of the 4 MWU block weight consensus
    /// limit. Transactions exceeding this are valid per consensus but
    /// will not propagate through the standard P2P network.
    pub const DEFAULT_MAX_TX_WEIGHT: Weight = Weight::from_wu(400_000);

    /// Default maximum consolidation inputs beyond the minimum
    /// required to fund withdrawals.
    pub const DEFAULT_MAX_INPUTS: usize = 500;

    /// Default maximum number of withdrawal requests per batch. A
    /// batch of 50 P2TR outputs is ~9.2 kWU (~2.3% of the 400 kWU
    /// policy limit), so the weight limit is never the binding
    /// constraint. Larger batches amortize the fixed transaction
    /// overhead across more requests, reducing per-request fees.
    pub const DEFAULT_MAX_WITHDRAWAL_REQUESTS: usize = 50;

    /// Default minimum fee rate floor (1 sat/vB), matching Bitcoin
    /// Core's minimum relay fee.
    pub const DEFAULT_MIN_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

    /// Default long-term average fee rate (10 sat/vB), matching
    /// Bitcoin Core's `-consolidatefeerate` default. Below this rate,
    /// the algorithm aggressively consolidates; at or above, it
    /// minimizes inputs.
    pub const DEFAULT_LONG_TERM_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(10);

    /// Default high fee rate threshold (30 sat/vB). Matches Bitcoin
    /// Core's CoinGrinder activation threshold (3× the long-term
    /// consolidation fee rate). At or above this rate, the algorithm
    /// aggressively minimizes inputs and performs no pool
    /// consolidation.
    pub const DEFAULT_HIGH_FEE_RATE_THRESHOLD: FeeRate = FeeRate::from_sat_per_vb_unchecked(30);

    /// Default input budget per request at or above the long-term fee
    /// rate (10 extra inputs per request). Matches the on-chain
    /// `input_budget` config parameter.
    pub const DEFAULT_INPUT_BUDGET: usize = 10;

    /// Default maximum mempool chain depth (5). Allows spending
    /// change from up to 5 levels of mempool-only ancestors. At
    /// 5-minute batching intervals this covers ~25 minutes of
    /// batches before a confirmation is needed, well within
    /// Bitcoin's cluster mempool limit of 64 and the pre-cluster
    /// limit of 25.
    pub const DEFAULT_MAX_MEMPOOL_CHAIN_DEPTH: usize = 5;

    /// Creates a new `CoinSelectionParams` with sensible defaults.
    ///
    /// The `change_address` must be provided; all other parameters
    /// use their `DEFAULT_*` values and can be overridden via struct
    /// update syntax:
    ///
    /// ```ignore
    /// let params = CoinSelectionParams {
    ///     max_withdrawal_requests: 20,
    ///     ..CoinSelectionParams::new(change_addr)
    /// };
    /// ```
    ///
    /// `max_fee_per_request` is derived from
    /// `DEFAULT_HIGH_FEE_RATE_THRESHOLD` and a worst-case transaction
    /// shape of `DEFAULT_INPUT_BUDGET` inputs, mirroring the on-chain
    /// `worst_case_network_fee` formula.
    pub fn new(change_address: BitcoinAddress) -> Self {
        // Mirror the on-chain worst_case_network_fee formula:
        //   tx_vbytes = TX_FIXED_VB + (input_budget * INPUT_VB) + (OUTPUT_BUDGET * OUTPUT_VB)
        //   max_fee_per_request = high_fee_rate_threshold * tx_vbytes
        //
        // Using the on-chain constants: TX_FIXED_VB=11, INPUT_VB=100,
        // OUTPUT_BUDGET=2, OUTPUT_VB=43.
        const TX_FIXED_VB: u64 = 11;
        const INPUT_VB: u64 = 100;
        const OUTPUT_BUDGET: u64 = 2;
        const OUTPUT_VB: u64 = 43;

        let tx_vbytes = TX_FIXED_VB
            + (Self::DEFAULT_INPUT_BUDGET as u64 * INPUT_VB)
            + (OUTPUT_BUDGET * OUTPUT_VB);
        let max_fee_per_request =
            Self::DEFAULT_HIGH_FEE_RATE_THRESHOLD.to_sat_per_vb_floor() * tx_vbytes;

        Self {
            max_tx_weight: Self::DEFAULT_MAX_TX_WEIGHT,
            max_inputs: Self::DEFAULT_MAX_INPUTS,
            max_withdrawal_requests: Self::DEFAULT_MAX_WITHDRAWAL_REQUESTS,
            max_fee_per_request,
            min_fee_rate: Self::DEFAULT_MIN_FEE_RATE,
            long_term_fee_rate: Self::DEFAULT_LONG_TERM_FEE_RATE,
            high_fee_rate_threshold: Self::DEFAULT_HIGH_FEE_RATE_THRESHOLD,
            input_budget: Self::DEFAULT_INPUT_BUDGET,
            max_mempool_chain_depth: Self::DEFAULT_MAX_MEMPOOL_CHAIN_DEPTH,
            change_address,
        }
    }
}

// ── Output Types ─────────────────────────────────────────────────────────────

/// A single withdrawal output in the proposed transaction.
#[derive(Clone, Debug)]
pub struct WithdrawalOutput {
    /// The ID of the withdrawal request this output satisfies.
    pub request_id: Address,
    /// Raw witness-program bytes of the recipient Bitcoin address.
    pub recipient: Vec<u8>,
    /// Net amount in satoshis delivered to `recipient`: the request amount
    /// minus this request's equal share of the total miner fee.
    pub amount: u64,
}

/// The result produced by a successful call to [`select_coins`].
#[derive(Debug)]
pub struct CoinSelectionResult {
    /// UTXOs selected as transaction inputs.
    ///
    /// Includes both the minimum inputs required to fund the selected
    /// withdrawal requests and any additional consolidation inputs pulled in
    /// for pool maintenance.
    pub inputs: Vec<UtxoCandidate>,

    /// Withdrawal outputs, one per selected request, in the same order as
    /// `selected_requests`.
    pub withdrawal_outputs: Vec<WithdrawalOutput>,

    /// Change output amount in satoshis, or `None` if the residual value
    /// after outputs and fees falls below the dust threshold. When `Some`,
    /// the change is sent to the `change_address` passed to [`select_coins`].
    pub change: Option<u64>,

    /// Total miner fee in satoshis:
    /// `sum(inputs.amount) − sum(withdrawal_outputs.amount) − change.unwrap_or(0)`.
    ///
    /// Computed as `floor(total_weight_fee / N) × N`, where `total_weight_fee`
    /// is the fee at `fee_rate` for the final transaction weight and N is the
    /// number of selected requests. The `total_weight_fee % N` remainder is
    /// implicitly donated to the miner and is included here (it is captured in
    /// the conservation identity but not charged to any individual request).
    pub fee: u64,

    /// The withdrawal requests included in this transaction, in the same
    /// order as `withdrawal_outputs`.
    pub selected_requests: Vec<WithdrawalRequest>,
}

// ── Error Types ──────────────────────────────────────────────────────────────

/// Errors that can be returned by [`select_coins`].
#[derive(Debug, Error)]
pub enum CoinSelectionError {
    /// The UTXO pool is empty; there are no inputs available to fund any
    /// transaction.
    #[error("UTXO pool is empty")]
    EmptyPool,

    /// No withdrawal requests were provided to the algorithm.
    #[error("no withdrawal requests provided")]
    NoRequests,

    /// The final per-request fee share exceeds `params.max_fee_per_request`.
    ///
    /// This is a safety check performed after all inputs and outputs are
    /// finalised (step 5). It should not occur when parameters are
    /// well-formed (i.e. `fee_rate` has been clamped to `params.high_fee_rate_threshold`
    /// before calling [`select_coins`] and `params.max_fee_per_request` was
    /// derived from `params.high_fee_rate_threshold`).
    #[error(
        "per-request deduction {fee_per_request} sat exceeds the configured cap \
         {max_fee_per_request} sat (total deduction {total_deduction} sat across \
         {n_requests} requests)"
    )]
    FeeExceedsCap {
        /// `floor(total_deduction / N)` — the equal share charged to each
        /// request.
        fee_per_request: u64,
        /// The configured per-request fee cap (`params.max_fee_per_request`).
        max_fee_per_request: u64,
        /// Total deduction in satoshis (miner fee + CPFP deficit + dust
        /// padding).
        total_deduction: u64,
        /// Number of selected requests (N).
        n_requests: usize,
    },

    /// The total confirmed UTXO value is insufficient to cover the total
    /// requested withdrawal amounts. All fees come from request amounts, so
    /// inputs only need to cover `sum(request.amount)`; no extra for fees.
    #[error(
        "insufficient funds: {available} sat available across confirmed UTXOs, \
         {required} sat required to cover selected withdrawal amounts"
    )]
    InsufficientFunds {
        /// Total satoshis available across confirmed UTXOs only.
        available: u64,
        /// Sum of the selected withdrawal request amounts.
        required: u64,
    },

    /// Even a single-request transaction with the minimum required inputs
    /// exceeds `params.max_tx_weight`. This is the gating check for request
    /// selection (step 1): requests are dropped newest-first until the batch
    /// fits; this error fires only when a one-request batch still exceeds the
    /// limit.
    #[error(
        "single-request transaction weight {weight:#} exceeds the configured \
         maximum {max_weight:#}"
    )]
    ExceedsMaxWeight {
        /// Estimated weight of a single-request transaction.
        weight: Weight,
        /// Configured maximum (`params.max_tx_weight`).
        max_weight: Weight,
    },

    /// A selected request's amount is smaller than the per-request fee share,
    /// which would produce a zero-value or negative output.
    ///
    /// This can occur when a request amount is less than
    /// `floor(total_fee / N)`. Callers should ensure request amounts exceed
    /// `params.max_fee_per_request` before submitting them.
    #[error(
        "withdrawal request {request_id} amount {amount} sat is less than the \
         per-request fee share {fee_per_request} sat"
    )]
    RequestAmountTooSmall {
        /// ID of the offending withdrawal request.
        request_id: Address,
        /// The request's withdrawal amount.
        amount: u64,
        /// The fee share that would be deducted.
        fee_per_request: u64,
    },
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Output weight for a withdrawal request's recipient.
///
/// Assumes recipient addresses have been validated upstream. Uses the
/// cheaper P2WPKH weight for 20-byte witness programs and the P2TR
/// weight for 32-byte programs. Any other length conservatively uses
/// the P2TR weight (the more expensive of the two).
fn output_weight_for_recipient(request: &WithdrawalRequest) -> Weight {
    match request.recipient.len() {
        // P2WPKH: OP_0 OP_PUSHBYTES_20 <20 bytes> → 22-byte scriptPubKey → 124 WU
        20 => TXOUT_BASE_WEIGHT + Weight::from_wu(22 * 4),
        // P2TR (or unknown): OP_1 OP_PUSHBYTES_32 <32 bytes> → 34-byte scriptPubKey → 172 WU
        _ => TXOUT_BASE_WEIGHT + Weight::from_wu(34 * 4),
    }
}

/// Output weight for an arbitrary scriptPubKey.
///
/// Assumes the script-length varint fits in one byte, which holds for all
/// standard scripts (length < 252).
fn output_weight_for_script(script: &bitcoin::Script) -> Weight {
    Weight::from_wu((8u64 + 1 + script.len() as u64) * 4)
}

/// Minimum change output value (sat) above Bitcoin's dust relay threshold for
/// the given change scriptPubKey.
///
/// Uses the standard script lengths to identify the output type:
/// - 22 bytes → P2WPKH (294 sat at 3 sat/vByte min relay fee)
/// - 34 bytes → P2TR / P2WSH (330 sat)
/// - anything else → conservative P2TR value (330 sat)
fn dust_threshold_for_change(script: &bitcoin::Script) -> u64 {
    match script.len() {
        22 => WPKH_DUST_RELAY_MIN_VALUE,
        _ => TR_DUST_RELAY_MIN_VALUE,
    }
}

/// Fee in satoshis for a given weight at the given fee rate.
///
/// Uses `FeeRate::fee_wu` which rounds up to the next whole satoshi to
/// avoid underpaying relay fees.
fn fee_for_weight(fee_rate: FeeRate, weight: Weight) -> u64 {
    fee_rate
        .fee_wu(weight)
        .map(|a| a.to_sat())
        .expect("fee computation overflow: fee rate or weight is unreasonably large")
}


/// Select UTXOs and plan a batched withdrawal transaction.
///
/// Uses a `TransactionBuilder` to construct the transaction
/// incrementally, with CPFP-aware fee management for spending
/// unconfirmed change outputs.
///
/// # Algorithm
///
/// 1. **Request selection** — up to `max_withdrawal_requests` requests
///    are taken oldest-first by timestamp.
///
/// 2. **Input selection** — UTXOs are sorted largest-first and selected
///    greedily until `input_total >= total_requested`. Both confirmed
///    and pending UTXOs are eligible, subject to the
///    `max_mempool_chain_depth` filter.
///
/// 3. **Consolidation** — if there is change (excess input value) and
///    the fee rate is favourable, extra *confirmed* UTXOs are pulled in
///    smallest-first to reduce the UTXO set. Aggressiveness depends on
///    the fee environment:
///    - Below `long_term_fee_rate`: up to `input_budget × N` extras.
///    - Between long-term and `high_fee_rate_threshold`: up to
///      `input_budget × N / 2` extras.
///    - At or above high threshold: no consolidation.
///
/// 4. **Fee allocation** — `finalize_fees` computes the total deduction
///    (own fee + CPFP deficit + dust padding), checks it against the
///    per-request cap, verifies each output stays above dust, assigns
///    net amounts, and derives the actual miner fee from conservation.
///
/// # Preconditions
///
/// The caller must provide a **consistent, non-overlapping UTXO set**.
/// See the module-level documentation for details.
pub fn select_coins(
    utxos: &[UtxoCandidate],
    requests: &[WithdrawalRequest],
    params: &CoinSelectionParams,
    fee_rate: FeeRate,
) -> Result<CoinSelectionResult, CoinSelectionError> {
    // ── Early validation ────────────────────────────────────────────────────
    if utxos.is_empty() {
        return Err(CoinSelectionError::EmptyPool);
    }
    if requests.is_empty() {
        return Err(CoinSelectionError::NoRequests);
    }
    if params.max_withdrawal_requests == 0 {
        return Err(CoinSelectionError::NoRequests);
    }

    // clamp fee rate floor
    let fee_rate = fee_rate.max(params.min_fee_rate);

    let mut builder = TransactionBuilder {
        fee_rate,
        params,
        inputs: Vec::new(),
        outputs: Vec::new(),
        raw_change: None,
        final_change: None,
    };

    // ── Step 1: Request selection ───────────────────────────────────────────
    // Take up to max_withdrawal_requests oldest requests.

    let mut requests: Vec<&WithdrawalRequest> = requests.iter().collect();
    requests.sort_by_key(|r| r.timestamp_ms);

    for r in requests.iter().take(params.max_withdrawal_requests) {
        builder.outputs.push(WithdrawalOutput2 {
            request: r,
            net_amount: 0,
        });
    }

    // ── Step 2: Input selection (largest-first) ────────────────────────────
    //
    // Sort all UTXOs by descending value, then by id for determinism.
    // Both confirmed and pending UTXOs are eligible — pending ones may
    // require CPFP fee boosting, accounted for in Step 4. UTXOs with
    // too many mempool-only (0-confirmation) ancestors are excluded to
    // stay within Bitcoin's relay policy limits.
    let mut pool: Vec<&UtxoCandidate> = utxos
        .iter()
        .filter(|u| u.status.mempool_chain_depth() <= params.max_mempool_chain_depth)
        .collect();
    pool.sort_by(|a, b| b.amount.cmp(&a.amount).then_with(|| a.id.cmp(&b.id)));

    let total_requested = builder.total_requested();
    let mut input_total = 0u64;

    for utxo in &pool {
        if builder.inputs.len() >= params.max_inputs {
            break;
        }
        if input_total >= total_requested {
            break;
        }

        builder.inputs.push(utxo);
        input_total += utxo.amount;
    }

    if input_total < total_requested {
        return Err(CoinSelectionError::InsufficientFunds {
            available: pool.iter().map(|u| u.amount).sum(),
            required: total_requested,
        });
    }

    let raw_change = builder.compute_raw_change();

    // Verify the base transaction (before consolidation) is within fee
    // and weight limits. Bail out early if even the minimum inputs
    // exceed limits.
    builder.check_fees()?;
    builder.check_weight()?;

    // ── Step 3: Consolidation ──────────────────────────────────────────
    //
    // Pull in extra *confirmed* inputs (smallest-first) to reduce the
    // UTXO set toward a single output. Only confirmed UTXOs are
    // eligible — pending UTXOs would add unaccounted ancestors to the
    // CPFP calculation. Consolidation only runs when there is already
    // a change output (raw_change > 0).
    //
    // The aggressiveness depends on the fee environment:
    // - Below long-term rate: up to `input_budget × N` extras.
    // - Between long-term and high threshold: up to
    //   `input_budget × N / 2` extras.
    // - At or above high threshold: no consolidation.
    let max_consolidation = if fee_rate < params.long_term_fee_rate {
        (params.max_inputs.saturating_sub(builder.inputs.len()))
            .min(builder.outputs.len() * params.input_budget)
    } else if fee_rate < params.high_fee_rate_threshold {
        (params.max_inputs.saturating_sub(builder.inputs.len()))
            .min(builder.outputs.len() * params.input_budget / 2)
    } else {
        0
    };

    if max_consolidation > 0 && raw_change > 0 {
        let mut remaining: Vec<&UtxoCandidate> = pool
            .iter()
            .filter(|u| {
                matches!(u.status, UtxoStatus::Confirmed)
                    && !builder.inputs.iter().any(|s| s.id == u.id)
            })
            .copied()
            .collect();
        remaining.sort_by_key(|u| u.amount);

        for utxo in remaining.into_iter().take(max_consolidation) {
            if builder.inputs.len() >= params.max_inputs {
                break;
            }
            builder.inputs.push(utxo);
            builder.compute_raw_change();

            // If adding this input pushed fees or weight over the
            // limit, undo it and stop consolidating. This is a
            // greedy heuristic: inputs are sorted smallest-first so
            // weight increases monotonically, but a larger input
            // could theoretically eliminate dust padding and lower
            // total_deduction enough to pass. We accept this
            // approximation for simplicity.
            if builder.check_fees().is_err() || builder.exceeds_max_weight() {
                builder.inputs.pop();
                builder.compute_raw_change();
                break;
            }
        }
    }

    // ── Step 4: Fee allocation ──────────────────────────────────────────
    //
    // Recompute raw_change (consolidation may have added inputs),
    // then finalize: check fee caps, assign net output amounts,
    // compute final change (with dust padding), and derive the
    // actual miner fee from conservation.
    builder.compute_raw_change();
    let miner_fee = builder.finalize_fees()?;

    Ok(CoinSelectionResult {
        inputs: builder.inputs.iter().map(|u| (*u).clone()).collect(),
        withdrawal_outputs: builder
            .outputs
            .iter()
            .map(|o| WithdrawalOutput {
                request_id: o.request.id,
                recipient: o.request.recipient.clone(),
                amount: o.net_amount,
            })
            .collect(),
        change: builder.final_change,
        fee: miner_fee,
        selected_requests: builder
            .outputs
            .iter()
            .map(|o| o.request.clone())
            .collect(),
    })
}

struct TransactionBuilder<'a> {
    // Fixed from the Params
    fee_rate: FeeRate,
    params: &'a CoinSelectionParams,

    // Values that are built up
    inputs: Vec<&'a UtxoCandidate>,
    outputs: Vec<WithdrawalOutput2<'a>>,
    /// The raw excess of input value over requested value, before any
    /// dust padding. `None` means not yet computed; `Some(0)` means
    /// exact match (no change output); `Some(n)` means `n` sats of
    /// change.
    raw_change: Option<u64>,
    final_change: Option<u64>,
}

struct WithdrawalOutput2<'a> {
    request: &'a WithdrawalRequest,
    net_amount: u64,
}

impl<'a> WithdrawalOutput2<'a> {
    /// The dust relay threshold for this output's recipient address type.
    fn dust_threshold(&self) -> u64 {
        match self.request.recipient.len() {
            20 => WPKH_DUST_RELAY_MIN_VALUE,
            _ => TR_DUST_RELAY_MIN_VALUE,
        }
    }
}

impl<'a> TransactionBuilder<'a> {
    /// Compute the total transaction weight based on the current inputs,
    /// outputs, and change state.
    ///
    /// When `raw_change` is `None` (not yet computed), the change output is
    /// conservatively assumed to be present. This overestimates weight
    /// slightly, which is the safe direction: a weight check that passes
    /// with a change output included will still pass if no change output
    /// ends up being emitted.
    fn weight(&self) -> Weight {
        let input_count = self.inputs.len();
        let has_change = self.raw_change.is_none_or(|v| v > 0);
        let output_count = self.outputs.len() + if has_change { 1 } else { 0 };

        // Non-witness fixed fields (scaled ×4):
        //   nVersion(4) + nLockTime(4) = 8 bytes × 4 = 32 WU
        //   vin_count varint + vout_count varint (scaled ×4)
        //
        // Witness fixed fields (scaled ×1):
        //   segwit_marker(1) + segwit_flag(1) = 2 WU
        let fixed = Weight::from_wu(32 + 2)
            + varint_weight(input_count as u64)
            + varint_weight(output_count as u64);

        // Sum of all input weights (base + witness satisfaction).
        let inputs: Weight = self
            .inputs
            .iter()
            .map(|u| u.spend_path.input_weight())
            .sum();

        // Sum of all withdrawal output weights.
        let outputs: Weight = self
            .outputs
            .iter()
            .map(|o| output_weight_for_recipient(o.request))
            .sum();

        // Change output weight (if present).
        let change = if has_change {
            output_weight_for_script(&self.change_script())
        } else {
            Weight::ZERO
        };

        fixed + inputs + outputs + change
    }

    /// The total value of all selected inputs.
    fn input_total(&self) -> u64 {
        self.inputs.iter().map(|u| u.amount).sum()
    }

    /// Compute and set the raw change amount based on the current
    /// inputs and requested outputs. Raw change is the excess of input
    /// value over the total requested amount, before any dust padding.
    ///
    /// - `Some(0)` means exact match (no change output).
    /// - `Some(n)` where `n > 0` means `n` sats of raw change.
    ///
    /// Panics if `input_total < total_requested` — the caller must
    /// ensure sufficient inputs have been selected before calling.
    fn compute_raw_change(&mut self) -> u64 {
        let input_total = self.input_total();
        let total_requested = self.total_requested();
        assert!(
            input_total >= total_requested,
            "input_total ({input_total}) < total_requested ({total_requested})"
        );
        let raw_change = input_total - total_requested;
        self.raw_change = Some(raw_change);
        raw_change
    }

    /// Whether the transaction weight exceeds the configured maximum.
    fn exceeds_max_weight(&self) -> bool {
        self.weight() > self.params.max_tx_weight
    }

    /// Check that the transaction weight is within the configured
    /// maximum. Returns an error if exceeded.
    fn check_weight(&self) -> Result<(), CoinSelectionError> {
        if self.exceeds_max_weight() {
            Err(CoinSelectionError::ExceedsMaxWeight {
                weight: self.weight(),
                max_weight: self.params.max_tx_weight,
            })
        } else {
            Ok(())
        }
    }

    /// The total amount deducted from requests: the transaction's own
    /// fee, any CPFP deficit for underpaying ancestors, and any dust
    /// padding needed to bring a sub-dust change output up to the
    /// relay threshold.
    fn total_deduction(&self) -> u64 {
        self.required_fee() + self.dust_padding()
    }

    /// The amount of dust padding needed for the change output. If
    /// the raw change is positive but below the dust threshold, it
    /// must be padded up — and that padding cost comes from the
    /// requests. Returns 0 if there is no change or the change is
    /// already above dust.
    fn dust_padding(&self) -> u64 {
        match self.raw_change {
            Some(v) if v > 0 && v < self.change_dust_threshold() => {
                self.change_dust_threshold() - v
            }
            _ => 0,
        }
    }

    /// Compute the CPFP deficit: the extra fee this transaction must
    /// pay to ensure that the unconfirmed ancestor transactions
    /// effectively pay the target `fee_rate`.
    ///
    /// ```text
    /// needed_ancestor_fee = fee_rate × ancestor_weight
    /// deficit = needed_ancestor_fee - ancestor_fee
    /// ```
    ///
    /// This transaction's own fee (for its own weight) is handled
    /// separately by the normal fee calculation. The deficit is purely
    /// the shortfall in what the ancestors should have paid.
    ///
    /// Only mempool-only ancestors (0 confirmations) are included —
    /// ancestors already in a block don't need boosting.
    ///
    /// Returns 0 if the ancestors already pay enough.
    fn cpfp_deficit(&self) -> u64 {
        let ancestor_weight: Weight = self
            .inputs
            .iter()
            .map(|u| u.status.unconfirmed_ancestor_weight())
            .sum();
        let ancestor_fee: u64 = self
            .inputs
            .iter()
            .map(|u| u.status.unconfirmed_ancestor_fee())
            .sum();

        let needed_ancestor_fee = fee_for_weight(self.fee_rate, ancestor_weight);
        needed_ancestor_fee.saturating_sub(ancestor_fee)
    }

    /// The total fee this transaction must pay: its own weight-based
    /// fee plus any CPFP deficit to boost underpaying ancestors.
    fn required_fee(&self) -> u64 {
        let own_fee = fee_for_weight(self.fee_rate, self.weight());
        own_fee + self.cpfp_deficit()
    }

    /// The sum of all withdrawal request amounts.
    fn total_requested(&self) -> u64 {
        self.outputs.iter().map(|o| o.request.amount).sum()
    }

    /// The change script for the pool's change address.
    fn change_script(&self) -> bitcoin::ScriptBuf {
        self.params.change_address.script_pubkey()
    }

    /// The dust threshold for change outputs based on the change
    /// address script type.
    fn change_dust_threshold(&self) -> u64 {
        dust_threshold_for_change(&self.change_script())
    }

    /// Check that the current fee deductions are within bounds:
    /// the per-request cap isn't exceeded, and every request can
    /// absorb its share and still produce a non-dust output.
    ///
    /// This is a read-only check — it does not mutate the builder.
    /// Call it early to bail out before consolidation if the base
    /// transaction already exceeds limits, and again during
    /// consolidation to detect when adding inputs pushes fees over.
    fn check_fees(&self) -> Result<(), CoinSelectionError> {
        let n = self.outputs.len() as u64;
        if n == 0 {
            return Ok(());
        }

        let total_deduction = self.total_deduction();
        let deduction_per_request = total_deduction.div_ceil(n);

        if deduction_per_request > self.params.max_fee_per_request {
            return Err(CoinSelectionError::FeeExceedsCap {
                fee_per_request: deduction_per_request,
                max_fee_per_request: self.params.max_fee_per_request,
                total_deduction,
                n_requests: n as usize,
            });
        }

        for output in self.outputs.iter() {
            if output.request.amount < deduction_per_request + output.dust_threshold() {
                return Err(CoinSelectionError::RequestAmountTooSmall {
                    request_id: output.request.id,
                    amount: output.request.amount,
                    fee_per_request: deduction_per_request,
                });
            }
        }

        Ok(())
    }

    /// Perform final fee checks, assign net output amounts, compute
    /// final change (with dust padding), and return the actual miner
    /// fee.
    ///
    /// Requires `compute_raw_change` to have been called first.
    /// Returns the miner fee derived from the conservation identity:
    /// `input_total - sum(net_amounts) - final_change`.
    fn finalize_fees(&mut self) -> Result<u64, CoinSelectionError> {
        let raw_change = self
            .raw_change
            .expect("finalize_fees called before compute_raw_change");

        // Run the fee checks.
        self.check_fees()?;

        // Assign net amounts using ceiling division so the miner
        // always receives at least the required fee.
        let n = self.outputs.len() as u64;
        let deduction_per_request = self.total_deduction().div_ceil(n);
        for output in &mut self.outputs {
            output.net_amount = output.request.amount - deduction_per_request;
        }

        // Compute final change (padded to dust threshold if needed).
        self.final_change = if raw_change > 0 {
            Some(raw_change.max(self.change_dust_threshold()))
        } else {
            None
        };

        // Derive the actual miner fee from the conservation identity:
        //   input_total = sum(net_amounts) + final_change + miner_fee
        let output_total: u64 = self.outputs.iter().map(|o| o.net_amount).sum();
        let change = self.final_change.unwrap_or(0);
        let miner_fee = self.input_total() - output_total - change;

        // With ceiling division, the miner always gets at least the
        // required fee.
        assert!(
            miner_fee >= self.required_fee(),
            "miner_fee ({miner_fee}) < required_fee ({})",
            self.required_fee()
        );

        Ok(miner_fee)
    }
}

/// Weight of a Bitcoin varint encoding for `n`, counted as non-witness
/// data (scaled ×4).
///
/// Varint encoding sizes:
/// - 0–252: 1 byte
/// - 253–0xFFFF: 3 bytes
/// - 0x10000–0xFFFFFFFF: 5 bytes
/// - 0x100000000–: 9 bytes
fn varint_weight(n: u64) -> Weight {
    let bytes = match n {
        0..=252 => 1u64,
        253..=0xFFFF => 3,
        0x10000..=0xFFFFFFFF => 5,
        _ => 9,
    };
    Weight::from_wu(bytes * 4)
}
