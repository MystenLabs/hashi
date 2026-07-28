// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Bitcoin UTXO value types shared by the deposit and withdrawal flows. A
/// `UtxoId` identifies an outpoint (txid:vout) and a `Utxo` pairs it with
/// its satoshi amount and an optional derivation path (the Sui address a
/// deposit mints to). The constructors are `public` so PTBs can assemble
/// UTXOs when calling into the bridge; everything else is package-only.
#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo;

// ~~~~~~~ Structs ~~~~~~~

/// txid:vout
public struct UtxoId has copy, drop, store {
    // a 32 byte sha256 of the transaction
    txid: address,
    // Out position of the UTXO
    vout: u32,
}

public struct Utxo has copy, drop, store {
    id: UtxoId,
    // In satoshis
    amount: u64,
    derivation_path: Option<address>,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun utxo_id(txid: address, vout: u32): UtxoId {
    UtxoId { txid, vout }
}

public fun utxo(utxo_id: UtxoId, amount: u64, derivation_path: Option<address>): Utxo {
    Utxo { id: utxo_id, amount, derivation_path }
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun id(self: &Utxo): UtxoId {
    self.id
}

public(package) fun amount(self: &Utxo): u64 {
    self.amount
}

public(package) fun derivation_path(self: &Utxo): Option<address> {
    self.derivation_path
}

public(package) fun delete(utxo: Utxo) {
    let Utxo { id: _, amount: _, derivation_path: _ } = utxo;
}
