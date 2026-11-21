module solvency::conservation;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::ghost::ghost_destroy;
use cvlm::manifest::rule;
use cvlm::nondet::nondet;
use hashi::utxo::Utxo;
use hashi::utxo_pool;
use solvency::summaries_utxo_pool::total_active_amount;

public fun cvlm_manifest() {
    rule(b"insert_then_cleanup_tracks_total");
}

/// @ignore
#[test_only]
public fun insert_then_cleanup_tracks_total(ctx: &mut TxContext) {
    // Ghosts are nondeterministically initialized per rule (no initial-state
    // axioms), so this has to be assumed rather than relied on implicitly.
    cvlm_assume_msg(*total_active_amount() == 0, b"Assume ghost starts at zero");

    let utxo: Utxo = nondet();
    let amount = utxo.amount();
    let utxo_id = utxo.id();
    let withdrawal_id: address = nondet();
    let epoch: u64 = nondet();

    let mut pool = utxo_pool::create(ctx);

    pool.insert_active(utxo);
    cvlm_assert(*total_active_amount() == amount);

    pool.lock(utxo_id, withdrawal_id);
    cvlm_assert(*total_active_amount() == 0);

    pool.mark_spent(utxo_id, epoch);
    pool.cleanup_spent(utxo_id);
    cvlm_assert(*total_active_amount() == 0);

    ghost_destroy(pool);
}
