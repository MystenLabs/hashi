module deposit::deposit_sanity;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::ghost::ghost_destroy;
use cvlm::manifest::{rule, target, target_sanity};
use cvlm::nondet::nondet;
use hashi::utxo::Utxo;
use hashi::utxo_pool;
use hashi::utxo_pool::UtxoPool;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"deposit");
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");
    target_sanity();

    rule(b"insert_active_adds_to_pool");
    rule(b"insert_active_pool_inv");
}

/// @ignore
#[test_only]
public fun insert_active_adds_to_pool(ctx: &mut TxContext) {
    let utxo: Utxo = nondet();
    let utxo_id = utxo.id();

    // let mut pool = utxo_pool::create(ctx);
    let mut pool: UtxoPool = nondet();
    pool.insert_active(utxo);

    cvlm_assert(pool.has_active_record(utxo_id));

    ghost_destroy(pool);
}

#[test_only]
public fun insert_active_pool_inv() {
    let mut pool: UtxoPool = nondet();
    
    let arb_utxo: Utxo = nondet();
    let arb_utxo_id = arb_utxo.id();
    let arb_utxo_spent_by = utxo_pool::get_utxo_record_spent_by(&pool, arb_utxo_id);
    cvlm_assume_msg(arb_utxo_spent_by.is_none(), "Arbitrary UTXO is not spent");

    let utxo: Utxo = nondet();
    pool.insert_active(utxo);

    let arb_utxo_spent_by = utxo_pool::get_utxo_record_spent_by(&pool, arb_utxo_id);
    cvlm_assert(arb_utxo_spent_by.is_none());

    ghost_destroy(pool);
}
