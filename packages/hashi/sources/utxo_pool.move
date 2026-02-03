#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo_pool;

use hashi::utxo::{Utxo, UtxoId};
use sui::bag::Bag;

public struct UtxoPool has store {
    active_utxos: Bag, // UtxoId -> Utxo
    spent_utxos: Bag, // UtxoId -> u64 (spent_epoch)
}

public(package) fun create(ctx: &mut TxContext): UtxoPool {
    UtxoPool {
        active_utxos: sui::bag::new(ctx),
        spent_utxos: sui::bag::new(ctx),
    }
}

/// Returns true if the UTXO is either active or has been spent
public(package) fun is_spent_or_active(self: &UtxoPool, utxo_id: UtxoId): bool {
    self.active_utxos.contains(utxo_id) || self.spent_utxos.contains(utxo_id)
}

public(package) fun insert_active(self: &mut UtxoPool, utxo: Utxo) {
    self.active_utxos.add(utxo.id(), utxo)
}

/// Remove a UTXO from active and mark it as spent
public(package) fun spend(self: &mut UtxoPool, utxo_id: UtxoId, epoch: u64): Utxo {
    let utxo: Utxo = self.active_utxos.remove(utxo_id);
    self.spent_utxos.add(utxo_id, epoch);
    utxo
}
