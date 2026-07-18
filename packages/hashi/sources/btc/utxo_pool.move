// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// On-chain bookkeeping for the bridge's Bitcoin UTXO set. Confirmed deposit
/// outputs and unconfirmed withdrawal change outputs live in `utxo_records`
/// from insertion until the withdrawal that spends them confirms on Bitcoin,
/// after which their IDs move to `spent_utxos` — kept permanently as replay
/// protection so an already-spent outpoint can never be re-inserted.
#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo_pool;

use hashi::utxo::{Utxo, UtxoId};
use sui::bag::Bag;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EUtxoAlreadyLocked: vector<u8> = b"UTXO is already locked in a pending withdrawal";
#[error]
const EUtxoAlreadyUsed: vector<u8> = b"UTXO is already active or spent";

// ~~~~~~~ Structs ~~~~~~~

/// Tracks a UTXO through its full lifecycle in the pool.
///
/// A UTXO lives in `utxo_records` from the moment it is inserted (either
/// as a confirmed deposit or as a change output from a pending withdrawal)
/// until the withdrawal that spends it is confirmed on Bitcoin.
///
/// `produced_by`: None = confirmed deposit or promoted change output;
///                Some(id) = unconfirmed change output of that withdrawal.
/// `spent_by`:    None = available for coin selection;
///                Some(id) = reserved (locked) by that pending withdrawal to
///                be spent; there is no unlock, so this withdrawal will spend it.
///
/// A UTXO is selectable when `spent_by` is None, regardless of
/// `produced_by`. This allows chaining withdrawals through mempool change
/// outputs before the parent transaction confirms.
public struct UtxoRecord has store {
    utxo: Utxo,
    produced_by: Option<address>,
    spent_by: Option<address>,
    spent_epoch: Option<u64>,
}

public struct UtxoPool has store {
    utxo_records: Bag, // UtxoId -> UtxoRecord
    spent_utxos: Bag, // UtxoId -> u64 (spent_epoch)
}

// ~~~~~~~ Events ~~~~~~~

public struct UtxoSpent has copy, drop {
    utxo_id: UtxoId,
    spent_epoch: u64,
}

/// Emitted when `cleanup_spent` removes a spent UTXO's record. Nodes prune
/// their local `utxo_records` mirror on this event; without it only the
/// leader that executed the cleanup learns the record is gone.
public struct UtxoCleaned has copy, drop {
    utxo_id: UtxoId,
    spent_epoch: u64,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun create(ctx: &mut TxContext): UtxoPool {
    UtxoPool {
        utxo_records: sui::bag::new(ctx),
        spent_utxos: sui::bag::new(ctx),
    }
}

/// Insert a confirmed UTXO (from a deposit) into the pool.
public(package) fun insert_active(self: &mut UtxoPool, utxo: Utxo) {
    let utxo_id = utxo.id();
    self.assert_not_spent_or_active(utxo_id);
    self
        .utxo_records
        .add(
            utxo_id,
            UtxoRecord {
                utxo,
                produced_by: option::none(),
                spent_by: option::none(),
                spent_epoch: option::none(),
            },
        )
}

/// Insert an unconfirmed change UTXO produced by a pending withdrawal.
///
/// The UTXO is immediately selectable (`spent_by = None`) but flagged as
/// unconfirmed until `confirm_pending()` is called after the producing
/// transaction confirms on Bitcoin.
public(package) fun insert_pending(self: &mut UtxoPool, utxo: Utxo, withdrawal_id: address) {
    let utxo_id = utxo.id();
    self
        .utxo_records
        .add(
            utxo_id,
            UtxoRecord {
                utxo,
                produced_by: option::some(withdrawal_id),
                spent_by: option::none(),
                spent_epoch: option::none(),
            },
        )
}

/// Returns true if the UTXO is either in the active records or has been spent.
public(package) fun is_spent_or_active(self: &UtxoPool, utxo_id: UtxoId): bool {
    self.utxo_records.contains(utxo_id) || self.spent_utxos.contains(utxo_id)
}

public(package) fun assert_not_spent_or_active(self: &UtxoPool, utxo_id: UtxoId) {
    assert!(!self.is_spent_or_active(utxo_id), EUtxoAlreadyUsed);
}

/// Return a copy of a UTXO from the pool.
public(package) fun get_utxo(self: &UtxoPool, utxo_id: UtxoId): hashi::utxo::Utxo {
    let record: &UtxoRecord = self.utxo_records.borrow(utxo_id);
    record.utxo
}

/// Lock a UTXO for use in a pending withdrawal. Aborts if already locked.
public(package) fun lock(self: &mut UtxoPool, utxo_id: UtxoId, withdrawal_id: address) {
    let record: &mut UtxoRecord = self.utxo_records.borrow_mut(utxo_id);
    assert!(record.spent_by.is_none(), EUtxoAlreadyLocked);
    record.spent_by = option::some(withdrawal_id);
}

public(package) fun mark_spent(self: &mut UtxoPool, utxo_id: UtxoId, epoch: u64) {
    let record: &mut UtxoRecord = self.utxo_records.borrow_mut(utxo_id);
    record.spent_epoch = option::some(epoch);
    sui::event::emit(UtxoSpent { utxo_id, spent_epoch: epoch });
}

/// Promote a pending change UTXO to confirmed once its producing withdrawal
/// confirms on Bitcoin. If the UTXO was already locked by a subsequent
/// withdrawal, only `produced_by` is cleared; `spent_by` is left intact.
/// No-ops if the UTXO is no longer present (it was already spent).
public(package) fun confirm_pending(self: &mut UtxoPool, utxo_id: UtxoId) {
    if (self.utxo_records.contains(utxo_id)) {
        let record: &mut UtxoRecord = self.utxo_records.borrow_mut(utxo_id);
        record.produced_by = option::none();
    }
}

/// Deferred bookkeeping for a spent UTXO: remove from `utxo_records` and
/// record in `spent_utxos`. Aborts if the UTXO has not been marked spent.
/// No-ops if the record has already been cleaned up.
public(package) fun cleanup_spent(self: &mut UtxoPool, utxo_id: UtxoId) {
    if (self.utxo_records.contains(utxo_id)) {
        let UtxoRecord { utxo, produced_by: _, spent_by: _, spent_epoch } = self
            .utxo_records
            .remove(utxo_id);
        let epoch = spent_epoch.destroy_some();
        utxo.delete();
        self.spent_utxos.add(utxo_id, epoch);
        sui::event::emit(UtxoCleaned { utxo_id, spent_epoch: epoch });
    };
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun utxo_cleaned_fields(event: &UtxoCleaned): (UtxoId, u64) {
    (event.utxo_id, event.spent_epoch)
}

#[test_only]
public(package) fun has_active_record(self: &UtxoPool, utxo_id: UtxoId): bool {
    self.utxo_records.contains(utxo_id)
}

#[test_only]
public(package) fun has_spent_record(self: &UtxoPool, utxo_id: UtxoId): bool {
    self.spent_utxos.contains(utxo_id)
}
