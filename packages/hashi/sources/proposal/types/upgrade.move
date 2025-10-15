// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::upgrade;
use hashi::hashi::Hashi;
use hashi::proposal::Proposal;
use sui::package::UpgradeTicket;

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
