// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::upgrade;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use std::type_name;
use sui::package::UpgradeTicket;

const THRESHOLD: u64 = 10000;

public struct Upgrade has store, drop {
    digest: vector<u8>,
}

public fun new(digest: vector<u8>): Upgrade {
    Upgrade { digest }
}

public fun execute(self: Proposal<Upgrade>, hashi: &mut Hashi): UpgradeTicket {
    let Upgrade { digest } = self.execute(hashi);
    hashi.config().authorize_upgrade(digest)
}

public fun register_proposal_type(hashi: &mut Hashi) {
    hashi
        .config()
        .register_proposal_type(
            type_name::with_defining_ids<Upgrade>(),
            THRESHOLD,
            true,
        );
}
