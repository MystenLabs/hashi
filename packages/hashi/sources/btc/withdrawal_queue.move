// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::withdrawal_queue;

use hashi::{btc::BTC, config::Config, utxo::{Utxo, UtxoId, UtxoInfo}};
use sui::{bag::Bag, balance::Balance, clock::Clock};

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
    Processing { pending_withdrawal_id: address },
    Signed { pending_withdrawal_id: address },
    Confirmed { txid: address },
    Cancelled,
}

// ======== Core Structs ========

/// Persistent status record for a withdrawal request.
/// Lives in the `requests` bag, keyed by request_id. Never deleted.
/// The frontend's single source of truth for withdrawal status.
public struct WithdrawalRequest has copy, drop, store {
    sender: address,
    btc_amount: u64,
    bitcoin_address: vector<u8>,
    timestamp_ms: u64,
    status: WithdrawalStatus,
    pending_withdrawal_id: Option<address>,
    sui_tx_digest: vector<u8>,
}

/// Operational BTC balance held during the withdrawal lifecycle.
/// Lives in the `balances` bag, keyed by request_id.
/// Deleted when the withdrawal is committed (BTC burned) or cancelled (BTC returned).
public struct WithdrawalBalance has store {
    id: address,
    btc: Balance<BTC>,
    approved: bool,
}

public struct WithdrawalRequestQueue has store {
    /// Persistent status records (WithdrawalRequest, never deleted)
    requests: Bag,
    /// Operational BTC balances (WithdrawalBalance, deleted at commit/cancel)
    balances: Bag,
    /// In-flight withdrawal transactions (PendingWithdrawal)
    pending_withdrawals: Bag,
}

public struct PendingWithdrawal has store {
    id: address,
    txid: address,
    request_ids: vector<address>,
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
        requests: sui::bag::new(ctx),
        balances: sui::bag::new(ctx),
        pending_withdrawals: sui::bag::new(ctx),
    }
}

/// Create the withdrawal request and balance.
/// Returns both plus the shared request_id.
public(package) fun create_withdrawal(
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): (WithdrawalBalance, WithdrawalRequest, address) {
    assert!(bitcoin_address.length() == 32 || bitcoin_address.length() == 20);

    let request_id = ctx.fresh_object_address();
    let btc_amount = btc.value();

    let balance = WithdrawalBalance {
        id: request_id,
        btc,
        approved: false,
    };

    let request = WithdrawalRequest {
        sender: ctx.sender(),
        btc_amount,
        bitcoin_address,
        timestamp_ms: clock.timestamp_ms(),
        status: WithdrawalStatus::Requested,
        pending_withdrawal_id: option::none(),
        sui_tx_digest: *ctx.digest(),
    };

    (balance, request, request_id)
}

// ======== Lifecycle Functions ========

/// Insert both the persistent request and operational balance.
public(package) fun insert_withdrawal(
    self: &mut WithdrawalRequestQueue,
    request_id: address,
    balance: WithdrawalBalance,
    request: WithdrawalRequest,
) {
    self.requests.add(request_id, request);
    self.balances.add(request_id, balance);
}

/// Approve a withdrawal: sets approved on the balance and updates request status.
public(package) fun approve_withdrawal(self: &mut WithdrawalRequestQueue, request_id: address) {
    let balance: &mut WithdrawalBalance = self.balances.borrow_mut(request_id);
    balance.approved = true;

    let request: &mut WithdrawalRequest = self.requests.borrow_mut(request_id);
    request.status = WithdrawalStatus::Approved;
}

/// Consume approved balances at commit time.
/// Removes each balance from the bag, updates request status to Processing.
/// Returns the copied request records (for validation) and the BTC balances (for burning).
public(package) fun consume_approved_balances(
    self: &mut WithdrawalRequestQueue,
    request_ids: &vector<address>,
    pending_withdrawal_id: address,
): (vector<WithdrawalRequest>, vector<Balance<BTC>>) {
    let mut infos = vector[];
    let mut btc_balances = vector[];

    request_ids.do_ref!(|id| {
        // Remove the operational balance
        let balance: WithdrawalBalance = self.balances.remove(*id);
        assert!(balance.approved, ERequestNotApproved);
        let WithdrawalBalance { id: _, btc, approved: _ } = balance;
        btc_balances.push_back(btc);

        // Copy the persistent request (has copy) and update its status
        let request: &mut WithdrawalRequest = self.requests.borrow_mut(*id);
        request.status = WithdrawalStatus::Processing { pending_withdrawal_id };
        request.pending_withdrawal_id = option::some(pending_withdrawal_id);
        infos.push_back(*request);
    });

    (infos, btc_balances)
}

/// Update request statuses to Signed after MPC signing completes.
public(package) fun update_requests_signed(
    self: &mut WithdrawalRequestQueue,
    request_ids: &vector<address>,
    pending_withdrawal_id: address,
) {
    request_ids.do_ref!(|id| {
        let request: &mut WithdrawalRequest = self.requests.borrow_mut(*id);
        request.status = WithdrawalStatus::Signed { pending_withdrawal_id };
    });
}

/// Update request statuses to Confirmed after withdrawal is finalized.
public(package) fun update_requests_confirmed(
    self: &mut WithdrawalRequestQueue,
    request_ids: &vector<address>,
    txid: address,
) {
    request_ids.do_ref!(|id| {
        let request: &mut WithdrawalRequest = self.requests.borrow_mut(*id);
        request.status = WithdrawalStatus::Confirmed { txid };
    });
}

/// Cancel a withdrawal: removes the balance, updates status, returns BTC.
/// Caller must verify sender and cooldown before calling.
public(package) fun cancel_withdrawal(
    self: &mut WithdrawalRequestQueue,
    request_id: address,
): Balance<BTC> {
    let balance: WithdrawalBalance = self.balances.remove(request_id);
    let WithdrawalBalance { id: _, btc, approved: _ } = balance;

    let request: &mut WithdrawalRequest = self.requests.borrow_mut(request_id);
    request.status = WithdrawalStatus::Cancelled;

    btc
}

/// Read a withdrawal request (for checks like sender, timestamp, status).
public(package) fun borrow_request(
    self: &WithdrawalRequestQueue,
    request_id: address,
): &WithdrawalRequest {
    self.requests.borrow(request_id)
}

/// Check if a balance exists and is not yet approved (for cancel guard).
public(package) fun is_balance_approved(self: &WithdrawalRequestQueue, request_id: address): bool {
    let balance: &WithdrawalBalance = self.balances.borrow(request_id);
    balance.approved
}

// ======== PendingWithdrawal Functions ========

public(package) fun new_pending_withdrawal(
    pending_id: address,
    request_ids: vector<address>,
    request_infos: &vector<WithdrawalRequest>,
    inputs: vector<Utxo>,
    mut outputs: vector<OutputUtxo>,
    txid: address,
    presig_start_index: u64,
    epoch: u64,
    config: &Config,
    clock: &Clock,
    randomness: vector<u8>,
): PendingWithdrawal {
    let max_network_fee = hashi::btc_config::worst_case_network_fee(config);

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

    let request_count = request_ids.length();
    let output_count = outputs.length();
    assert!(
        output_count == request_count || output_count == request_count + 1,
        EOutputCountMismatch,
    );

    let per_user_miner_fee = miner_fee / request_count;
    assert!(per_user_miner_fee <= max_network_fee, EMinerFeeExceedsMax);

    // Validate each output against the corresponding request info
    request_count.do!(|i| {
        let request = request_infos.borrow(i);
        let output = outputs.borrow(i);
        let expected = request.btc_amount - per_user_miner_fee;
        assert!(expected >= hashi::btc_config::dust_relay_min_value(), EOutputBelowDust);
        assert!(output.amount == expected, EOutputAmountMismatch);
        assert!(output.bitcoin_address == request.bitcoin_address, EOutputAddressMismatch);
    });

    let change_output = if (output_count == request_count + 1) {
        option::some(outputs.pop_back())
    } else {
        option::none()
    };

    PendingWithdrawal {
        id: pending_id,
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

public(package) fun insert_pending_withdrawal(
    self: &mut WithdrawalRequestQueue,
    pending: PendingWithdrawal,
) {
    self.pending_withdrawals.add(pending.id, pending)
}

public(package) fun remove_pending_withdrawal(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
): PendingWithdrawal {
    self.pending_withdrawals.remove(withdrawal_id)
}

public(package) fun sign_pending_withdrawal(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
    signatures: vector<vector<u8>>,
) {
    let pending: &mut PendingWithdrawal = self.pending_withdrawals.borrow_mut(withdrawal_id);
    pending.signatures = option::some(signatures);
    emit_withdrawal_signed(pending);
}

/// Reassign presig indices for a pending withdrawal from a previous epoch.
public(package) fun reassign_presigs_for_pending_withdrawal(
    self: &mut WithdrawalRequestQueue,
    withdrawal_id: address,
    presig_start_index: u64,
    current_epoch: u64,
) {
    let pending: &mut PendingWithdrawal = self.pending_withdrawals.borrow_mut(withdrawal_id);
    assert!(pending.epoch != current_epoch);
    pending.presig_start_index = presig_start_index;
    pending.epoch = current_epoch;
}

public(package) fun pending_withdrawal_num_inputs(
    self: &WithdrawalRequestQueue,
    withdrawal_id: address,
): u64 {
    let pending: &PendingWithdrawal = self.pending_withdrawals.borrow(withdrawal_id);
    pending.inputs.length()
}

/// Destroy a pending withdrawal, returning the request IDs, txid, and change UTXO if one exists.
public(package) fun destroy_pending_withdrawal(
    self: PendingWithdrawal,
): (vector<address>, address, Option<Utxo>) {
    let PendingWithdrawal {
        id: _,
        txid,
        request_ids,
        inputs,
        withdrawal_outputs,
        change_output,
        timestamp_ms: _,
        randomness: _,
        signatures: _,
        presig_start_index: _,
        epoch: _,
    } = self;

    inputs.destroy!(|utxo| {
        utxo.delete();
    });

    let change_utxo = if (change_output.is_some()) {
        let change = change_output.destroy_some();
        let change_vout = (withdrawal_outputs.length() as u32);
        let change_utxo_id = hashi::utxo::utxo_id(txid, change_vout);
        option::some(hashi::utxo::utxo(change_utxo_id, change.amount, option::none()))
    } else {
        change_output.destroy_none();
        option::none()
    };

    (request_ids, txid, change_utxo)
}

// ======== Accessors ========

public(package) fun pending_withdrawal_id(self: &PendingWithdrawal): address {
    self.id
}

public(package) fun pending_withdrawal_request_ids(self: &PendingWithdrawal): &vector<address> {
    &self.request_ids
}

public(package) fun txid(self: &PendingWithdrawal): address {
    self.txid
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

public fun is_approved(self: &WithdrawalStatus): bool {
    match (self) {
        WithdrawalStatus::Approved => true,
        _ => false,
    }
}

// ======== Events ========

public(package) fun emit_withdrawal_requested(request_id: address, request: &WithdrawalRequest) {
    sui::event::emit(WithdrawalRequestedEvent {
        request_id,
        btc_amount: request.btc_amount,
        bitcoin_address: request.bitcoin_address,
        timestamp_ms: request.timestamp_ms,
        requester_address: request.sender,
        sui_tx_digest: request.sui_tx_digest,
    });
}

public(package) fun emit_withdrawal_approved(request_id: address) {
    sui::event::emit(WithdrawalApprovedEvent {
        request_id,
    });
}

public(package) fun emit_withdrawal_picked_for_processing(self: &PendingWithdrawal) {
    sui::event::emit(WithdrawalPickedForProcessingEvent {
        pending_id: self.id,
        txid: self.txid,
        request_ids: self.request_ids,
        inputs: self.inputs.map_ref!(|u| u.to_info()),
        withdrawal_outputs: self.withdrawal_outputs,
        change_output: self.change_output,
        timestamp_ms: self.timestamp_ms,
        randomness: self.randomness,
    });
}

public(package) fun emit_withdrawal_signed(self: &PendingWithdrawal) {
    sui::event::emit(WithdrawalSignedEvent {
        withdrawal_id: self.id,
        request_ids: self.request_ids,
        signatures: *self.signatures.borrow(),
    });
}

public(package) fun emit_withdrawal_confirmed(self: &PendingWithdrawal) {
    let (change_utxo_id, change_utxo_amount) = if (self.change_output.is_some()) {
        let change = self.change_output.borrow();
        let change_vout = (self.withdrawal_outputs.length() as u32);
        (option::some(hashi::utxo::utxo_id(self.txid, change_vout)), option::some(change.amount))
    } else {
        (option::none(), option::none())
    };

    sui::event::emit(WithdrawalConfirmedEvent {
        pending_id: self.id,
        txid: self.txid,
        change_utxo_id,
        request_ids: self.request_ids,
        change_utxo_amount,
    });
}

public(package) fun emit_withdrawal_cancelled(request_id: address, request: &WithdrawalRequest) {
    sui::event::emit(WithdrawalCancelledEvent {
        request_id,
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
    pending_id: address,
    txid: address,
    request_ids: vector<address>,
    inputs: vector<UtxoInfo>,
    withdrawal_outputs: vector<OutputUtxo>,
    change_output: Option<OutputUtxo>,
    timestamp_ms: u64,
    randomness: vector<u8>,
}

public struct WithdrawalSignedEvent has copy, drop {
    withdrawal_id: address,
    request_ids: vector<address>,
    signatures: vector<vector<u8>>,
}

public struct WithdrawalConfirmedEvent has copy, drop {
    pending_id: address,
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
public(package) fun new_pending_withdrawal_for_testing(
    request_ids: vector<address>,
    inputs: vector<Utxo>,
    withdrawal_outputs: vector<OutputUtxo>,
    change_output: Option<OutputUtxo>,
    txid: address,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
): PendingWithdrawal {
    PendingWithdrawal {
        id: ctx.fresh_object_address(),
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
