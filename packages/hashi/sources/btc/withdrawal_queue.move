// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::withdrawal_queue;

use hashi::{btc::BTC, btc_config, config::Config, utxo::{Utxo, UtxoId}};
use sui::{bag::Bag, balance::Balance, clock::Clock};

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

public struct WithdrawalRequestQueue has store {
    requests: Bag,
    pending_withdrawals: Bag,
}

public struct WithdrawalRequest has store {
    info: WithdrawalRequestInfo,
    btc: Balance<BTC>,
    approved: bool,
}

public struct WithdrawalRequestInfo has copy, drop, store {
    id: address,
    btc_amount: u64,
    bitcoin_address: vector<u8>, // 32 or 20 bytes?
    timestamp_ms: u64,
    requester_address: address,
    sui_tx_digest: vector<u8>,
}

public struct PendingWithdrawal has store {
    id: address,
    txid: address,
    requests: vector<WithdrawalRequestInfo>,
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

public fun output_utxo(amount: u64, bitcoin_address: vector<u8>): OutputUtxo {
    OutputUtxo { amount, bitcoin_address }
}

public(package) fun withdrawal_request(
    btc: Balance<BTC>,
    bitcoin_address: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): WithdrawalRequest {
    //TODO improve destination address checking
    assert!(bitcoin_address.length() == 32 || bitcoin_address.length() == 20);

    WithdrawalRequest {
        info: WithdrawalRequestInfo {
            id: ctx.fresh_object_address(),
            btc_amount: btc.value(),
            bitcoin_address,
            timestamp_ms: clock.timestamp_ms(),
            requester_address: ctx.sender(),
            sui_tx_digest: *ctx.digest(),
        },
        btc,
        approved: false,
    }
}

public(package) fun new_pending_withdrawal(
    requests: vector<WithdrawalRequestInfo>,
    inputs: vector<Utxo>,
    mut outputs: vector<OutputUtxo>,
    txid: address,
    presig_start_index: u64,
    epoch: u64,
    config: &Config,
    clock: &Clock,
    randomness: vector<u8>,
    ctx: &mut TxContext,
): PendingWithdrawal {
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
    let request_count = requests.length();
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
    // the per-user miner fee. The protocol fee was already deducted at request
    // time, so request.btc_amount is net of the protocol fee.
    request_count.do!(|i| {
        let request = requests.borrow(i);
        let output = outputs.borrow(i);
        let expected = request.btc_amount - per_user_miner_fee;
        assert!(expected >= hashi::btc_config::dust_relay_min_value(), EOutputBelowDust);
        assert!(output.amount == expected, EOutputAmountMismatch);
        assert!(output.bitcoin_address == request.bitcoin_address, EOutputAddressMismatch);
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

    PendingWithdrawal {
        id: ctx.fresh_object_address(),
        txid,
        requests,
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

public(package) fun approve_request(self: &mut WithdrawalRequestQueue, request_id: address) {
    let request: &mut WithdrawalRequest = self.requests.borrow_mut(request_id);
    request.approved = true;
}

public(package) fun is_request_approved(self: &WithdrawalRequestQueue, request_id: address): bool {
    let request: &WithdrawalRequest = self.requests.borrow(request_id);
    request.approved
}

public(package) fun remove_request(
    self: &mut WithdrawalRequestQueue,
    id: address,
): WithdrawalRequest {
    self.requests.remove(id)
}

public(package) fun remove_approved_request(
    self: &mut WithdrawalRequestQueue,
    id: address,
): WithdrawalRequest {
    let request: WithdrawalRequest = self.requests.remove(id);
    assert!(request.approved, ERequestNotApproved);
    request
}

public(package) fun insert_request(self: &mut WithdrawalRequestQueue, request: WithdrawalRequest) {
    self.requests.add(request.info.id, request)
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

public(package) fun create(ctx: &mut TxContext): WithdrawalRequestQueue {
    WithdrawalRequestQueue {
        requests: sui::bag::new(ctx),
        pending_withdrawals: sui::bag::new(ctx),
    }
}

public(package) fun pending_withdrawal_num_inputs(
    self: &WithdrawalRequestQueue,
    withdrawal_id: address,
): u64 {
    let pending: &PendingWithdrawal = self.pending_withdrawals.borrow(withdrawal_id);
    pending.inputs.length()
}

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

public(package) fun request_into_parts(
    self: WithdrawalRequest,
): (WithdrawalRequestInfo, Balance<BTC>) {
    let WithdrawalRequest { info, btc, approved: _ } = self;
    (info, btc)
}

/// Build the change UTXO from a pending withdrawal's data.
///
/// Returns the Utxo that corresponds to the change output, or None if there
/// is no change output. Used by `commit_withdrawal_tx()` to insert the change
/// UTXO into the pool immediately after the pending withdrawal is created.
public(package) fun build_change_utxo(self: &PendingWithdrawal): Option<hashi::utxo::Utxo> {
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

/// Destroy a pending withdrawal, returning the input UTXOs and the change
/// UTXO ID (if any). The caller is responsible for calling `confirm_spent()`
/// on each input's ID and `confirm_pending()` on the change ID in the pool.
public(package) fun destroy_pending_withdrawal(
    self: PendingWithdrawal,
): (vector<Utxo>, Option<UtxoId>) {
    let PendingWithdrawal {
        id: _,
        txid,
        requests: _,
        inputs,
        withdrawal_outputs,
        change_output,
        timestamp_ms: _,
        randomness: _,
        signatures: _,
        presig_start_index: _,
        epoch: _,
    } = self;

    let change_id = if (change_output.is_some()) {
        let _change = change_output.destroy_some();
        // Change output is always the last output in the BTC transaction.
        let change_vout = (withdrawal_outputs.length() as u32);
        option::some(hashi::utxo::utxo_id(txid, change_vout))
    } else {
        change_output.destroy_none();
        option::none()
    };

    (inputs, change_id)
}

public(package) fun emit_withdrawal_requested(self: &WithdrawalRequest) {
    sui::event::emit(WithdrawalRequestedEvent {
        request_id: self.info.id,
        btc_amount: self.info.btc_amount,
        bitcoin_address: self.info.bitcoin_address,
        timestamp_ms: self.info.timestamp_ms,
        requester_address: self.info.requester_address,
        sui_tx_digest: self.info.sui_tx_digest,
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
        request_ids: self.requests.map_ref!(|info| info.id),
        inputs: self.inputs,
        withdrawal_outputs: self.withdrawal_outputs,
        change_output: self.change_output,
        timestamp_ms: self.timestamp_ms,
        randomness: self.randomness,
    });
}

public(package) fun emit_withdrawal_signed(self: &PendingWithdrawal) {
    sui::event::emit(WithdrawalSignedEvent {
        withdrawal_id: self.id,
        request_ids: self.requests.map_ref!(|info| info.id),
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
        request_ids: self.requests.map_ref!(|info| info.id),
        change_utxo_amount,
    });
}

public(package) fun emit_withdrawal_cancelled(self: &WithdrawalRequest) {
    sui::event::emit(WithdrawalCancelledEvent {
        request_id: self.info.id,
        requester_address: self.info.requester_address,
        btc_amount: self.info.btc_amount,
    });
}

#[test_only]
public(package) fun new_pending_withdrawal_for_testing(
    requests: vector<WithdrawalRequestInfo>,
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
        requests,
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

public(package) fun pending_withdrawal_id(self: &PendingWithdrawal): address {
    self.id
}

public(package) fun txid(self: &PendingWithdrawal): address {
    self.txid
}

public(package) fun requester_address(self: &WithdrawalRequest): address {
    self.info.requester_address
}

public(package) fun timestamp_ms(self: &WithdrawalRequest): u64 {
    self.info.timestamp_ms
}

public(package) fun request_id(self: &WithdrawalRequest): address {
    self.info.id
}

public(package) fun btc_amount(self: &WithdrawalRequest): u64 {
    self.info.btc_amount
}

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
    inputs: vector<Utxo>,
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
