module hashi::withdrawal_queue;

use hashi::{btc::BTC, utxo::Utxo};
use sui::{bag::Bag, balance::Balance, clock::Clock, random::Random};

const NUMBER_OF_RANDOM_BYTES: u16 = 32;

public struct WithdrawalRequestQueue has store {
    // XXX bag or table?
    requests: Bag,
    // XXX do we need a separate bag or can we just use the same bag?
    pending_withdrawals: Bag, //vector<PendingWithdrawal>,
}

public struct WithdrawalRequest has store {
    info: WithdrawalRequestInfo,
    btc: Balance<BTC>,
}

public struct WithdrawalRequestInfo has drop, store {
    id: address,
    btc_amount: u64,
    bitcoin_address: vector<u8>, // 32 or 20 bytes?
    timestamp_ms: u64,
    requester_address: address,
}

public struct PendingWithdrawal has store {
    txid: address,
    id: address,
    requests: vector<WithdrawalRequestInfo>,
    inputs: vector<Utxo>,
    // change: Option<()>,
    outputs: vector<OutputUtxo>,
    timestamp_ms: u64,
    randomness: vector<u8>,
}

public struct OutputUtxo has drop, store {
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
        },
        btc,
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

    // TODO Check that all requests have a corrisponding output and that the amount is X - required BTC fee

    let mut rng = sui::random::new_generator(r, ctx);
    let randomness = rng.generate_bytes(NUMBER_OF_RANDOM_BYTES);

    PendingWithdrawal {
        id: ctx.fresh_object_address(),
        txid,
        requests,
        inputs,
        outputs,
        // fee,
        timestamp_ms: clock.timestamp_ms(),
        randomness,
    }
}

public(package) fun remove_request(
    self: &mut WithdrawalRequestQueue,
    id: address,
): WithdrawalRequest {
    self.requests.remove(id)
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

public(package) fun create(ctx: &mut TxContext): WithdrawalRequestQueue {
    WithdrawalRequestQueue {
        requests: sui::bag::new(ctx),
        pending_withdrawals: sui::bag::new(ctx),
    }
}

public(package) fun request_into_parts(
    self: WithdrawalRequest,
): (WithdrawalRequestInfo, Balance<BTC>) {
    let WithdrawalRequest { info, btc } = self;
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
    } = self;

    inputs.destroy!(|utxo| {
        utxo.delete();
    });
}
