// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Container for the package's governance proposals, hung off `Hashi`.
/// Active and executed proposals live in two separate object bags so that
/// each set can be enumerated directly, and executed proposals are archived
/// indefinitely to keep historical governance actions inspectable.
module hashi::proposals;

use sui::object_bag::{Self, ObjectBag};

// ~~~~~~~ Structs ~~~~~~~

/// Two-bag store for governance proposals. Listing "active proposals"
/// and "executed proposals" is then a direct walk over the relevant
/// bag instead of a filter over a single combined bag.
public struct Proposals has store {
    /// Proposals that have been created but not yet executed.
    active: ObjectBag,
    /// Proposals that have executed successfully. Kept indefinitely
    /// so historical governance actions remain inspectable.
    executed: ObjectBag,
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun create(ctx: &mut TxContext): Proposals {
    Proposals {
        active: object_bag::new(ctx),
        executed: object_bag::new(ctx),
    }
}

public(package) fun active(self: &Proposals): &ObjectBag {
    &self.active
}

public(package) fun active_mut(self: &mut Proposals): &mut ObjectBag {
    &mut self.active
}

public(package) fun executed(self: &Proposals): &ObjectBag {
    &self.executed
}

public(package) fun executed_mut(self: &mut Proposals): &mut ObjectBag {
    &mut self.executed
}
