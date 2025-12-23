module hashi::deposit_queue;

use hashi::utxo::{Utxo, UtxoId};
use sui::{bag::Bag, clock::Clock};

public struct DepositRequestQueue has store {
    // XXX bag or table?
    requests: Bag,
}

public struct DepositRequest has store {
    utxo: Utxo,
    timestamp_ms: u64,
}

public fun deposit_request(utxo: Utxo, clock: &Clock): DepositRequest {
    DepositRequest {
        utxo,
        timestamp_ms: clock.timestamp_ms(),
    }
}

public(package) fun contains(self: &DepositRequestQueue, utxo_id: UtxoId): bool {
    self.requests.contains(utxo_id)
}

public(package) fun remove(self: &mut DepositRequestQueue, utxo_id: UtxoId): DepositRequest {
    self.requests.remove(utxo_id)
}

public(package) fun insert(self: &mut DepositRequestQueue, request: DepositRequest) {
    self.requests.add(request.utxo.id(), request)
}

public(package) fun into_utxo(self: DepositRequest): Utxo {
    let DepositRequest { utxo, timestamp_ms: _ } = self;
    utxo
}

public(package) fun create(ctx: &mut TxContext): DepositRequestQueue {
    DepositRequestQueue {
        requests: sui::bag::new(ctx),
    }
}
