#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo_pool;

use hashi::utxo::{Utxo, UtxoId};
use sui::bag::Bag;

public struct UtxoPool has store {
    // XXX bag or table?
    utxos: Bag,
}

public(package) fun contains(self: &UtxoPool, utxo_id: UtxoId): bool {
    self.utxos.contains(utxo_id)
}

public(package) fun remove(self: &mut UtxoPool, utxo_id: UtxoId): Utxo {
    self.utxos.remove(utxo_id)
}

public(package) fun insert(self: &mut UtxoPool, utxo: Utxo) {
    self.utxos.add(utxo.id(), utxo)
}

public(package) fun create(ctx: &mut TxContext): UtxoPool {
    UtxoPool {
        utxos: sui::bag::new(ctx),
    }
}
