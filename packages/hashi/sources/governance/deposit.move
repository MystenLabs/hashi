// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deposit;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use std::type_name;

const THRESHOLD: u64 = 10000;

public struct Deposit<phantom T> has store, drop {
    amount: u64,
    recipient: address,
}

public fun new<T>(amount: u64, recipient: address): Deposit<T> {
    Deposit<T> { amount, recipient }
}

public fun execute<T: drop>(
    self: Proposal<Deposit<T>>,
    hashi: &mut Hashi,
    ctx: &mut TxContext,
) {
    let Deposit<T> { amount, recipient } = self.execute(hashi);
    let coin = hashi.treasury().mint<T>(amount, ctx);
    transfer::public_transfer(coin, recipient);
}

// NOTE: This will need to be called for each coin type before the register proposal
// of that coin type can be executed
public fun register_proposal_type<T>(hashi: &mut Hashi) {
    hashi
        .config()
        .register_proposal_type(
            type_name::with_defining_ids<Deposit<T>>(),
            THRESHOLD,
            false,
        );
}
