// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo_pool;

use hashi::utxo::{Utxo, UtxoId};
use sui::bag::Bag;

const MAX_SPENT_UTXO_AGE_EPOCHS: u64 = 7;

#[error]
const ESpentUtxoNotExpired: vector<u8> = b"Spent UTXO has not expired yet";

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
    sui::event::emit(UtxoSpentEvent { utxo_id, spent_epoch: epoch });
    utxo
}

/// Delete an expired spent UTXO from the pool.
/// Aborts if the spent UTXO has not expired yet (less than MAX_SPENT_UTXO_AGE_EPOCHS old).
public(package) fun delete_expired_spent_utxo(
    self: &mut UtxoPool,
    utxo_id: UtxoId,
    current_epoch: u64,
) {
    let spent_epoch: u64 = self.spent_utxos.remove(utxo_id);
    assert!(is_spent_utxo_expired(spent_epoch, current_epoch), ESpentUtxoNotExpired);
    sui::event::emit(SpentUtxoDeletedEvent { utxo_id });
}

fun is_spent_utxo_expired(spent_epoch: u64, current_epoch: u64): bool {
    current_epoch > spent_epoch + MAX_SPENT_UTXO_AGE_EPOCHS
}

public struct UtxoSpentEvent has copy, drop {
    utxo_id: UtxoId,
    spent_epoch: u64,
}

public struct SpentUtxoDeletedEvent has copy, drop {
    utxo_id: UtxoId,
}
