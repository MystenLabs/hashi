// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Bitcoin UTXO value types shared by the deposit and withdrawal flows. A
/// `UtxoId` identifies an outpoint (txid:vout) and a `Utxo` pairs it with
/// its satoshi amount and an optional derivation path (the Sui address a
/// deposit mints to). `SpendData` is what signing needs to spend a UTXO
/// through its 2-of-2 leaf. The constructors are `public` so PTBs can assemble
/// UTXOs when calling into the bridge; everything else is package-only.
#[allow(unused_function, unused_field, unused_use)]
module hashi::utxo;

const SIGHASH_TYPE_DEFAULT: u8 = 0;

#[error]
const ESpendKeyPathMismatch: vector<u8> = b"Spend data key path does not match the UTXO";
#[error]
const EUnsupportedSighashType: vector<u8> = b"Spend data sighash type is not supported";

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

public struct SpendData has copy, drop, store {
    script_pubkey: vector<u8>,
    leaf_script: vector<u8>,
    control_block: vector<u8>,
    key_path: address,
    sighash_type: u8,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun utxo_id(txid: address, vout: u32): UtxoId {
    UtxoId { txid, vout }
}

public fun utxo(utxo_id: UtxoId, amount: u64, derivation_path: Option<address>): Utxo {
    Utxo { id: utxo_id, amount, derivation_path }
}

public fun spend_data(
    script_pubkey: vector<u8>,
    leaf_script: vector<u8>,
    control_block: vector<u8>,
    key_path: address,
    sighash_type: u8,
): SpendData {
    SpendData { script_pubkey, leaf_script, control_block, key_path, sighash_type }
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

public(package) fun script_pubkey(self: &SpendData): &vector<u8> {
    &self.script_pubkey
}

public(package) fun expected_key_path(utxo: &Utxo): address {
    utxo.derivation_path().destroy_with_default(@0x0)
}

public(package) fun assert_spend_data(self: &SpendData, key_path: address) {
    assert!(self.key_path == key_path, ESpendKeyPathMismatch);
    assert!(self.sighash_type == SIGHASH_TYPE_DEFAULT, EUnsupportedSighashType);
}

#[test_only]
public fun spend_data_for_testing(utxo: &Utxo): SpendData {
    spend_data(vector[], vector[], vector[], expected_key_path(utxo), SIGHASH_TYPE_DEFAULT)
}
