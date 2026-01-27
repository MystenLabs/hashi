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

public(package) fun insert(self: &mut UtxoPool, utxo: Utxo) {
    self.utxos.add(utxo.id(), utxo)
}

public(package) fun create(ctx: &mut TxContext): UtxoPool {
    UtxoPool {
        utxos: sui::bag::new(ctx),
    }
}

/// Remove a UTXO from the UtxoPool and add it to another UtxoPool (the withdrawn pool).
public(package) fun withdraw(self: &mut UtxoPool, withdrawn_pool: &mut UtxoPool, utxo_id: UtxoId) {
    let utxo: Utxo = self.utxos.remove(utxo_id);
    withdrawn_pool.utxos.add(utxo_id, utxo);
}
