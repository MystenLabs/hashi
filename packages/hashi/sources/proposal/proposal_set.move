// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal_set;

use sui::bag::{Self, Bag};

public struct ProposalSet has store {
    proposals: Bag,
    seq_num: u64,
}

public struct ProposalKey<phantom T> has copy, drop, store {
    seq_num: u64,
}

public(package) fun create(ctx: &mut TxContext): ProposalSet {
    ProposalSet {
        proposals: bag::new(ctx),
        seq_num: 0,
    }
}

public(package) fun add<T: store>(set: &mut ProposalSet, proposal: T) {
    let seq_num = set.get_and_increment_seq_num();
    set.proposals.add(ProposalKey<T> { seq_num }, proposal);
}

public(package) fun get_and_increment_seq_num(self: &mut ProposalSet): u64 {
    let current_seq_num = self.seq_num;
    self.seq_num = current_seq_num + 1;
    current_seq_num
}

// TODO: determine if sequential execution order is needed for some proposal types
