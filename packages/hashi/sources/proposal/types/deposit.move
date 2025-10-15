// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use std::type_name::{Self, TypeName};

#[error]
const ETypeNameMismatch: vector<u8> = b"Type name mismatch";

public struct Deposit has store {
    amount: u64,
    recipient: address,
    type_name: TypeName,
}

public fun new(amount: u64, recipient: address, type_name: TypeName): Deposit {
    Deposit { amount, recipient, type_name }
}

public fun execute<T: drop>(
    self: Proposal<Deposit>,
    hashi: &mut Hashi,
    ctx: &mut TxContext,
) {
    let Deposit { amount, recipient, type_name } = self.execute(hashi);
    assert!(type_name == type_name::with_defining_ids<T>(), ETypeNameMismatch);
    let coin = hashi.treasury().mint<T>(amount, ctx);
    transfer::public_transfer(coin, recipient);
}
