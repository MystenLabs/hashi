// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::deny;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;

// ~~~~~~~ Errors ~~~~~~~
#[error]
const EProposalIdMismatch: vector<u8> = b"Proposal denial mismatch";

public struct Deny has store, drop {
    proposal_id: ID,
}

public fun new(proposal_id: ID): Deny {
    Deny { proposal_id }
}

public fun execute<T: drop>(
    self: Proposal<Deny>,
    hashi: &mut Hashi,
    proposal: Proposal<T>,
) {
    let Deny { proposal_id } = self.execute(hashi);
    assert!(proposal.id() == proposal_id, EProposalIdMismatch);
    proposal.delete<T>();
}
