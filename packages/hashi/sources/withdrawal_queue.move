module hashi::withdrawal_queue;

use hashi::{btc::BTC, utxo::{Utxo, UtxoInfo}};
use sui::{bag::Bag, balance::Balance, clock::Clock, random::Random};

const NUMBER_OF_RANDOM_BYTES: u16 = 32;

#[error]
const ERequestNotApproved: vector<u8> = b"Withdrawal request has not been approved";

public struct WithdrawalRequestQueue has store {
    requests: Bag,
    pending_withdrawals: Bag,
    /// Number of presignatures consumed in the current epoch.
    /// Used by recovering nodes to derive `(batch_index, index_in_batch)`.
    num_consumed_presigs: u64,
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
    inputs: vector<Utxo>,
    outputs: vector<OutputUtxo>,
    timestamp_ms: u64,
    randomness: vector<u8>,
    signatures: Option<vector<vector<u8>>>,
}

public struct OutputUtxo has copy, drop, store {
    // In satoshis
    amount: u64,
    bitcoin_address: vector<u8>,
}

public(package) fun output_utxo_from_bcs(raw: vector<u8>): OutputUtxo {
    let mut bcs = sui::bcs::new(raw);
    let amount = bcs.peel_u64();
    let bitcoin_address = bcs.peel_vec!(|bcs| bcs.peel_u8());
    bcs.into_remainder_bytes().destroy_empty();
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
    outputs: vector<OutputUtxo>,
    txid: address,
    clock: &Clock,
    r: &Random,
    ctx: &mut TxContext,
): PendingWithdrawal {
    let mut input_amount = 0;
    inputs.do_ref!(|utxo| {
        input_amount = input_amount + utxo.amount();
    });

    let mut output_amount = 0;
    outputs.do_ref!(|utxo| {
        output_amount = output_amount + utxo.amount;
    });

    assert!(input_amount >= output_amount);
    let _fee = input_amount - output_amount;

    // TODO Check that all requests have a corresponding output and that the amount is X - required BTC fee

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(NUMBER_OF_RANDOM_BYTES);

    PendingWithdrawal {
        id: ctx.fresh_object_address(),
        txid,
        requests,
        inputs,
        outputs,
        timestamp_ms: clock.timestamp_ms(),
        randomness,
        signatures: option::none(),
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
        num_consumed_presigs: 0,
    }
}

public(package) fun num_consumed_presigs(self: &WithdrawalRequestQueue): u64 {
    self.num_consumed_presigs
}

public(package) fun increment_num_consumed_presigs(self: &mut WithdrawalRequestQueue, count: u64) {
    self.num_consumed_presigs = self.num_consumed_presigs + count;
}

public(package) fun reset_num_consumed_presigs(self: &mut WithdrawalRequestQueue) {
    self.num_consumed_presigs = 0;
}

public(package) fun request_into_parts(
    self: WithdrawalRequest,
): (WithdrawalRequestInfo, Balance<BTC>) {
    let WithdrawalRequest { info, btc, approved: _ } = self;
    (info, btc)
}

// TODO return the change UTXO?
public(package) fun destroy_pending_withdrawal(self: PendingWithdrawal) {
    let PendingWithdrawal {
        id: _,
        txid: _,
        requests: _,
        inputs,
        outputs: _,
        timestamp_ms: _,
        randomness: _,
        signatures: _,
    } = self;

    inputs.destroy!(|utxo| {
        utxo.delete();
    });
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
        inputs: self.inputs.map_ref!(|u| u.to_info()),
        outputs: self.outputs,
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
    sui::event::emit(WithdrawalConfirmedEvent {
        pending_id: self.id,
        txid: self.txid,
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
    outputs: vector<OutputUtxo>,
    txid: address,
    clock: &sui::clock::Clock,
    ctx: &mut TxContext,
): PendingWithdrawal {
    PendingWithdrawal {
        id: ctx.fresh_object_address(),
        txid,
        requests,
        inputs,
        outputs,
        timestamp_ms: clock.timestamp_ms(),
        randomness: vector[0, 0, 0, 0],
        signatures: option::none(),
    }
}

public(package) fun pending_withdrawal_id(self: &PendingWithdrawal): address {
    self.id
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
    inputs: vector<UtxoInfo>,
    outputs: vector<OutputUtxo>,
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
}

public struct WithdrawalCancelledEvent has copy, drop {
    request_id: address,
    requester_address: address,
    btc_amount: u64,
}
