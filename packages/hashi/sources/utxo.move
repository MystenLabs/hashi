#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo;

use std::string::String;
use sui::{bag::Bag, balance::Balance, object_bag::ObjectBag};

public struct Utxo has store {
    id: UtxoId,
    // In satoshis
    amount: u64,
    derivation_path: Option<address>,
}

/// txid:vout
public struct UtxoId has copy, drop, store {
    // a 32 byte sha256 of the transaction
    txid: address,
    // Out position of the UTXO
    vout: u32,
}

public fun utxo_id(txid: address, vout: u32): UtxoId {
    UtxoId { txid, vout }
}

public(package) fun utxo_id_from_bcs(raw: vector<u8>): UtxoId {
    let mut bcs = sui::bcs::new(raw);
    let txid = bcs.peel_address();
    let vout = bcs.peel_u32();
    bcs.into_remainder_bytes().destroy_empty();
    UtxoId { txid, vout }
}

public fun utxo(utxo_id: UtxoId, amount: u64, derivation_path: Option<address>): Utxo {
    Utxo { id: utxo_id, amount, derivation_path }
}

public fun id(self: &Utxo): UtxoId {
    self.id
}

public fun amount(self: &Utxo): u64 {
    self.amount
}

public fun derivation_path(self: &Utxo): Option<address> {
    self.derivation_path
}

public(package) fun delete(utxo: Utxo) {
    let Utxo { id: _, amount: _, derivation_path: _ } = utxo;
}
