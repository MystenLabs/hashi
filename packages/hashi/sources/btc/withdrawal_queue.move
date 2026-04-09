// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::withdrawal_queue;

use hashi::{btc::BTC, btc_config, config::Config, utxo::{Utxo, UtxoId}};
use sui::{balance::Balance, clock::Clock, object_bag::ObjectBag};

use fun btc_config::worst_case_network_fee as Config.worst_case_network_fee;

#[error]
const ERequestNotApproved: vector<u8> = b"Withdrawal request has not been approved";
#[error]
const EOutputBelowDust: vector<u8> =
    b"Withdrawal output would be below dust threshold after miner fee deduction";
#[error]
const EOutputAmountMismatch: vector<u8> = b"Withdrawal output amount does not match expected value";
#[error]
const EOutputAddressMismatch: vector<u8> = b"Withdrawal output address does not match request";
#[error]
const EMinerFeeExceedsMax: vector<u8> = b"Per-user miner fee exceeds worst-case network fee budget";
#[error]
const EInputsBelowOutputs: vector<u8> = b"Total input amount is less than total output amount";
#[error]
const EOutputCountMismatch: vector<u8> =
    b"Output count must equal request count or request count + 1 (change)";

// ======== Status Enum ========

public enum WithdrawalStatus has copy, drop, store {
    Requested,
    Approved,
    Processing,
    Signed,
    Confirmed,
}

// ======== Core Structs ========

/// Unified withdrawal request object. Tracks the full lifecycle of a withdrawal,
/// from initial request through to confirmation or cancellation.
///
/// Moves between bags on `WithdrawalRequestQueue`:
/// - `requests` bag: active requests (Requested, Approved)
/// - `processed` bag: completed requests (Processing, Signed, Confirmed)
///
/// The BTC balance starts full and is drained to zero at commit (burned) or cancel (returned).
public struct WithdrawalRequest has key, store {
    id: UID,
    sender: address,
    btc_amount: u64,
    bitcoin_address: vector<u8>,
    timestamp_ms: u64,
    status: WithdrawalStatus,
    withdrawal_txn_id: Option<address>,
    sui_tx_digest: vector<u8>,
    btc: Balance<BTC>,
}

public struct WithdrawalRequestQueue has store {
    /// Active requests awaiting action (Requested, Approved).
    /// ObjectBag so WithdrawalRequest UIDs are directly accessible via getObject.
    requests: ObjectBag,
    /// Processed requests — BTC consumed, lifecycle continuing or complete
    /// (Processing, Signed, Confirmed).
    processed: ObjectBag,
    /// In-flight withdrawal transactions (unsigned, signed but unconfirmed).
    /// ObjectBag so WithdrawalTransaction UIDs are directly accessible via getObject.
    withdrawal_txns: ObjectBag,
    /// Confirmed withdrawal transactions (historical record).
    confirmed_txns: ObjectBag,
}

/// A Bitcoin transaction constructed for one or more withdrawal requests.
/// Tracks the full lifecycle from construction through signing to confirmation.
///
/// Lives in `withdrawal_txns` while in-flight, moves to `confirmed_txns`
/// after the Bitcoin transaction is confirmed on-chain.
public struct WithdrawalTransaction has key, store {
    id: UID,
    txid: address,
    request_ids: vector<address>,
    /// UTXOs consumed by this withdrawal. The UTXOs remain locked in the pool
    /// until `confirm_withdrawal()` moves them to spent; these copies are kept
    /// for event emission and fee accounting.
    inputs: vector<Utxo>,
    withdrawal_outputs: vector<OutputUtxo>,
    change_output: Option<OutputUtxo>,
    timestamp_ms: u64,
    randomness: vector<u8>,
    signatures: Option<vector<vector<u8>>>,
    /// Global presignature start index assigned at construction time.
    /// Input `i` uses presig at index `presig_start_index + i`.
    presig_start_index: u64,
    epoch: u64,
}

public struct OutputUtxo has copy, drop, store {
    // In satoshis
    amount: u64,
    bitcoin_address: vector<u8>,
}

// ======== Constructors ========

public fun output_utxo(amount: u64, bitcoin_address: vector<u8>): OutputUtxo {
    OutputUtxo { amount, bitcoin_address }
}

public(package) fun create(ctx: &mut TxContext): WithdrawalRequestQueue {
    WithdrawalRequestQueue {
        requests: sui::object_bag::new(ctx),
        processed: sui::object_bag::new(ctx),
        withdrawal_txns: sui::object_bag::new(ctx),
        confirmed_txns: sui::object_bag::new(ctx),
    }
}

/// Create a withdrawal request with the given BTC balance.
public(package) fun create_withdrawal(
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): WithdrawalRequest {
    assert!(bitcoin_address.length() == 32 || bitcoin_address.length() == 20);

    let btc_amount = btc.value();

    WithdrawalRequest {
        id: object::new(ctx),
        sender: ctx.sender(),
        btc_amount,
        bitcoin_address,
        timestamp_ms: clock.timestamp_ms(),
        status: WithdrawalStatus::Requested,
        withdrawal_txn_id: option::none(),
        sui_tx_digest: *ctx.digest(),
        btc,
    }
}

// ======== Request Lifecycle Functions ========

/// Insert a new withdrawal request into the active requests bag and index by sender.
public(package) fun insert_withdrawal(
    self: &mut WithdrawalRequestQueue,
    request: WithdrawalRequest,
) {
    let request_id = request.id.to_address();
    self.requests.add(request_id, request);
}

/// Approve a withdrawal request. Updates status in the requests bag.
public(package) fun approve_withdrawal(self: &mut WithdrawalRequestQueue, request_id: address) {
    let request: &mut WithdrawalRequest = self.requests.borrow_mut(request_id);
    request.status = WithdrawalStatus::Approved;
}

/// Read-only extraction of request data for fee validation.
/// Called before the WithdrawalTransaction is created so its constructor
/// can validate outputs against the requested amounts.
public(package) fun extract_request_infos(
    self: &WithdrawalRequestQueue,
    request_ids: &vector<address>,
): vector<CommittedRequestInfo> {
    request_ids.map_ref!(|id| {
        let request: &WithdrawalRequest = self.requests.borrow(*id);
        CommittedRequestInfo {
            btc_amount: request.btc_amount,
            bitcoin_address: request.bitcoin_address,
        }
    })
}

/// Commit approved requests for a withdrawal transaction: drain BTC, update
/// status, move from requests to processed. Returns the merged BTC balance
/// for burning.
public(package) fun commit_requests(
    self: &mut WithdrawalRequestQueue,
    withdrawal_txn: &WithdrawalTransaction,
): Balance<BTC> {
    let withdrawal_txn_id = withdrawal_txn.id.to_address();
    let mut total_btc = sui::balance::zero<BTC>();

    withdrawal_txn.request_ids.do_ref!(|id| {
        let mut request: WithdrawalRequest = self.requests.remove(*id);
        assert!(request.status == WithdrawalStatus::Approved, ERequestNotApproved);

        // Drain the BTC balance and merge
        total_btc.join(request.btc.withdraw_all());

        // Update status and link to the withdrawal transaction
        request.status = WithdrawalStatus::Processing;
        request.withdrawal_txn_id = option::some(withdrawal_txn_id);
        self.processed.add(*id, request);
    });

    total_btc
}

/// Update request statuses to Signed after MPC signing completes.
public(package) fun update_requests_signed(
    self: &mut WithdrawalRequestQueue,
    request_ids: &vector<address>,
) {
    request_ids.do_ref!(|id| {
        let request: &mut WithdrawalRequest = self.processed.borrow_mut(*id);
        request.status = WithdrawalStatus::Signed;
    });
}

/// Update request statuses to Confirmed after withdrawal is finalized.
public(package) fun update_requests_confirmed(
    self: &mut WithdrawalRequestQueue,
    request_ids: &vector<address>,
) {
    request_ids.do_ref!(|id| {
        let request: &mut WithdrawalRequest = self.processed.borrow_mut(*id);
        request.status = WithdrawalStatus::Confirmed;
    });
}

/// Cancel a withdrawal: drain BTC, clean up user index, destroy the request.
/// Cancelled requests are not persisted — they have no useful terminal state.
/// Caller must verify sender and cooldown before calling.
public(package) fun cancel_withdrawal(
    self: &mut WithdrawalRequestQueue,
    request_id: address,
): Balance<BTC> {
    let request: WithdrawalRequest = self.requests.remove(request_id);

    let WithdrawalRequest {
        id,
        sender: _,
        btc_amount: _,
        bitcoin_address: _,
        timestamp_ms: _,
        status: _,
        withdrawal_txn_id: _,
        sui_tx_digest: _,
        btc,
    } = request;
    id.delete();
    btc
}

/// Borrow an active request from the requests bag (for sender/timestamp checks).
public(package) fun borrow_request(
    self: &WithdrawalRequestQueue,
    request_id: address,
): &WithdrawalRequest {
    self.requests.borrow(request_id)
}

/// Check if an active request is approved (for cancel guard).
public(package) fun is_request_approved(self: &WithdrawalRequestQueue, request_id: address): bool {
    let request: &WithdrawalRequest = self.requests.borrow(request_id);
    request.status == WithdrawalStatus::Approved
}

// ======== Committed Request Info ========

/// Lightweight info extracted from a request at commit time for validation.
public struct CommittedRequestInfo has copy, drop, store {
    btc_amount: u64,
    bitcoin_address: vector<u8>,
}

// ======== WithdrawalTransaction Functions ========

public(package) fun new_withdrawal_txn(
    ctx: &mut TxContext,
    request_ids: vector<address>,
    request_infos: &vector<CommittedRequestInfo>,
    inputs: vector<Utxo>,
    mut outputs: vector<OutputUtxo>,
    txid: address,
    presig_start_index: u64,
    epoch: u64,
    config: &Config,
    clock: &Clock,
    randomness: vector<u8>,
): WithdrawalTransaction {
    let max_network_fee = config.worst_case_network_fee();

    let mut input_amount = 0;
    inputs.do_ref!(|utxo| {
        input_amount = input_amount + utxo.amount();
    });

    let mut output_amount = 0;
    outputs.do_ref!(|utxo| {
        output_amount = output_amount + utxo.amount;
    });

    assert!(input_amount >= output_amount, EInputsBelowOutputs);
    let miner_fee = input_amount - output_amount;

    // Outputs must be either one-per-request, or one-per-request plus a single
    // trailing change output.
    let request_count = request_ids.length();
    let output_count = outputs.length();
    assert!(
        output_count == request_count || output_count == request_count + 1,
        EOutputCountMismatch,
    );

    // Miner fee is split evenly across all withdrawal requests. Any remainder
    // (at most request_count - 1 sats) is a rounding bonus to the miner.
    let per_user_miner_fee = miner_fee / request_count;
    assert!(per_user_miner_fee <= max_network_fee, EMinerFeeExceedsMax);

    // Each withdrawal output must match the expected amount after deducting
    // the per-user miner fee.
    request_count.do!(|i| {
        let info = request_infos.borrow(i);
        let output = outputs.borrow(i);
        let expected = info.btc_amount - per_user_miner_fee;
        assert!(expected >= hashi::btc_config::dust_relay_min_value(), EOutputBelowDust);
        assert!(output.amount == expected, EOutputAmountMismatch);
        assert!(output.bitcoin_address == info.bitcoin_address, EOutputAddressMismatch);
    });

    // TODO: ensure any change output goes to the correct destination address, once we start
    // storing the pubkey on chain.
    // https://linear.app/mysten-labs/issue/IOP-226/dkg-commit-mpc-public-key-onchain-and-read-from-there

    // Extract the trailing change output if present.
    let change_output = if (output_count == request_count + 1) {
        option::some(outputs.pop_back())
    } else {
        option::none()
    };

    WithdrawalTransaction {
        id: object::new(ctx),
        txid,
        request_ids,
        inputs,
        withdrawal_outputs: outputs,
        change_output,
        timestamp_ms: clock.timestamp_ms(),
        randomness,
        signatures: option::none(),
        presig_start_index,
        epoch,
    }
}

public(package) fun insert_withdrawal_txn(
    self: &mut WithdrawalRequestQueue,
    txn: WithdrawalTransaction,
) {
    self.withdrawal_txns.add(txn.id.to_address(), txn)
}

public(package) fun borrow_withdrawal_txn(
    self: &WithdrawalRequestQueue,
    withdrawal_id: address,
): &WithdrawalTransaction {
    self.withdrawal_txns.borrow(withdrawal_id)
}

public(package) fun remove_withdrawal_txn(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
): WithdrawalTransaction {
    self.withdrawal_txns.remove(withdrawal_id)
}

/// Insert a confirmed withdrawal transaction into the cold (historical) bag.
public(package) fun insert_confirmed_txn(
    self: &mut WithdrawalRequestQueue,
    txn: WithdrawalTransaction,
) {
    self.confirmed_txns.add(txn.id.to_address(), txn);
}

public(package) fun sign_withdrawal_txn(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
    signatures: vector<vector<u8>>,
) {
    let txn: &mut WithdrawalTransaction = self.withdrawal_txns.borrow_mut(withdrawal_id);
    txn.signatures = option::some(signatures);
    emit_withdrawal_signed(txn);
}

/// Reassign presig indices for a withdrawal transaction from a previous epoch.
public(package) fun reassign_presigs_for_withdrawal_txn(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
    presig_start_index: u64,
    current_epoch: u64,
) {
    let txn: &mut WithdrawalTransaction = self.withdrawal_txns.borrow_mut(withdrawal_id);
    assert!(txn.epoch != current_epoch);
    txn.presig_start_index = presig_start_index;
    txn.epoch = current_epoch;
}

public(package) fun withdrawal_txn_num_inputs(
    self: &WithdrawalRequestQueue,
    withdrawal_id: address,
): u64 {
    let txn: &WithdrawalTransaction = self.withdrawal_txns.borrow(withdrawal_id);
    txn.inputs.length()
}

/// Build the change UTXO from a withdrawal transaction's data.
///
/// Returns the Utxo that corresponds to the change output, or None if there
/// is no change output. Used by `commit_withdrawal_tx()` to insert the change
/// UTXO into the pool immediately after the withdrawal transaction is created.
public(package) fun build_change_utxo(self: &WithdrawalTransaction): Option<hashi::utxo::Utxo> {
    if (self.change_output.is_some()) {
        let change = self.change_output.borrow();
        // Change output is always the last output in the BTC transaction.
        let change_vout = (self.withdrawal_outputs.length() as u32);
        let change_utxo_id = hashi::utxo::utxo_id(self.txid, change_vout);
        option::some(hashi::utxo::utxo(change_utxo_id, change.amount, option::none()))
    } else {
        option::none()
    }
}

/// Compute the change UTXO ID for a withdrawal transaction, or None if there
/// is no change output.
public(package) fun change_utxo_id(self: &WithdrawalTransaction): Option<UtxoId> {
    if (self.change_output.is_some()) {
        // Change output is always the last output in the BTC transaction.
        let change_vout = (self.withdrawal_outputs.length() as u32);
        option::some(hashi::utxo::utxo_id(self.txid, change_vout))
    } else {
        option::none()
    }
}

// ======== Accessors ========

public(package) fun withdrawal_txn_id(self: &WithdrawalTransaction): address {
    self.id.to_address()
}

public(package) fun withdrawal_txn_request_ids(self: &WithdrawalTransaction): &vector<address> {
    &self.request_ids
}

public(package) fun txid(self: &WithdrawalTransaction): address {
    self.txid
}

public(package) fun withdrawal_txn_inputs(self: &WithdrawalTransaction): &vector<Utxo> {
    &self.inputs
}

public(package) fun request_id(self: &WithdrawalRequest): ID {
    self.id.to_inner()
}

public(package) fun request_sender(self: &WithdrawalRequest): address {
    self.sender
}

public(package) fun request_timestamp_ms(self: &WithdrawalRequest): u64 {
    self.timestamp_ms
}

public(package) fun request_btc_amount(self: &WithdrawalRequest): u64 {
    self.btc_amount
}

public(package) fun request_status(self: &WithdrawalRequest): &WithdrawalStatus {
    &self.status
}

public(package) fun request_bitcoin_address(self: &WithdrawalRequest): &vector<u8> {
    &self.bitcoin_address
}

public fun is_approved(self: &WithdrawalStatus): bool {
    match (self) {
        WithdrawalStatus::Approved => true,
        _ => false,
    }
}

// ======== Events ========

public(package) fun emit_withdrawal_requested(request: &WithdrawalRequest) {
    sui::event::emit(WithdrawalRequestedEvent {
        request_id: request.id.to_address(),
        btc_amount: request.btc_amount,
        bitcoin_address: request.bitcoin_address,
        timestamp_ms: request.timestamp_ms,
        requester_address: request.sender,
        sui_tx_digest: request.sui_tx_digest,
    });
}

public(package) fun emit_withdrawal_approved(request_id: address) {
    sui::event::emit(WithdrawalApprovedEvent { request_id });
}

public(package) fun emit_withdrawal_picked_for_processing(self: &WithdrawalTransaction) {
    sui::event::emit(WithdrawalPickedForProcessingEvent {
        withdrawal_txn_id: self.id.to_address(),
        txid: self.txid,
        request_ids: self.request_ids,
        inputs: self.inputs,
        withdrawal_outputs: self.withdrawal_outputs,
        change_output: self.change_output,
        timestamp_ms: self.timestamp_ms,
        randomness: self.randomness,
    });
}

public(package) fun emit_withdrawal_signed(self: &WithdrawalTransaction) {
    sui::event::emit(WithdrawalSignedEvent {
        withdrawal_txn_id: self.id.to_address(),
        request_ids: self.request_ids,
        signatures: *self.signatures.borrow(),
    });
}

public(package) fun emit_withdrawal_confirmed(self: &WithdrawalTransaction) {
    let (change_utxo_id, change_utxo_amount) = if (self.change_output.is_some()) {
        let change = self.change_output.borrow();
        let change_vout = (self.withdrawal_outputs.length() as u32);
        (option::some(hashi::utxo::utxo_id(self.txid, change_vout)), option::some(change.amount))
    } else {
        (option::none(), option::none())
    };

    sui::event::emit(WithdrawalConfirmedEvent {
        withdrawal_txn_id: self.id.to_address(),
        txid: self.txid,
        change_utxo_id,
        request_ids: self.request_ids,
        change_utxo_amount,
    });
}

public(package) fun emit_withdrawal_cancelled(request: &WithdrawalRequest) {
    sui::event::emit(WithdrawalCancelledEvent {
        request_id: request.id.to_address(),
        requester_address: request.sender,
        btc_amount: request.btc_amount,
    });
}

// ======== Event Structs ========

public struct WithdrawalRequestedEvent has copy, drop {
    request_id: address,
    btc_amount: u64,
    bitcoin_address: vector<u8>,
    timestamp_ms: u64,
    requester_address: address,
    sui_tx_digest: vector<u8>,
}

public struct WithdrawalApprovedEvent has copy, drop {
    request_id: address,
}

public struct WithdrawalPickedForProcessingEvent has copy, drop {
    withdrawal_txn_id: address,
    txid: address,
    request_ids: vector<address>,
    inputs: vector<Utxo>,
    withdrawal_outputs: vector<OutputUtxo>,
    change_output: Option<OutputUtxo>,
    timestamp_ms: u64,
    randomness: vector<u8>,
}

public struct WithdrawalSignedEvent has copy, drop {
    withdrawal_txn_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
}

public struct WithdrawalConfirmedEvent has copy, drop {
    withdrawal_txn_id: address,
    txid: address,
    change_utxo_id: Option<UtxoId>,
    request_ids: vector<address>,
    change_utxo_amount: Option<u64>,
}

public struct WithdrawalCancelledEvent has copy, drop {
    request_id: address,
    requester_address: address,
    btc_amount: u64,
}

// ======== Test Helpers ========

#[test_only]
public(package) fun new_withdrawal_txn_for_testing(
    request_ids: vector<address>,
    inputs: vector<Utxo>,
    withdrawal_outputs: vector<OutputUtxo>,
    change_output: Option<OutputUtxo>,
    txid: address,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
): WithdrawalTransaction {
    WithdrawalTransaction {
        id: object::new(ctx),
        txid,
        request_ids,
        inputs,
        withdrawal_outputs,
        change_output,
        timestamp_ms: clock.timestamp_ms(),
        randomness: vector[0, 0, 0, 0],
        signatures: option::none(),
        presig_start_index: 0,
        epoch: 0,
    }
}
