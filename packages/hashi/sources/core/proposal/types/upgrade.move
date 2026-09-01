// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Package-upgrade governance with an atomic version policy.
///
/// The proposal records whether the new version must be exclusive. The
/// approved choice is carried from `execute` to `finalize_upgrade` in a hot
/// potato, so the transaction sender cannot substitute a different policy
/// while publishing the package.
///
/// An exclusive upgrade commits the new package and replaces the enabled set
/// with the new version in the same programmable transaction. A non-exclusive
/// upgrade preserves every enabled version and adds the new one.
module hashi::upgrade;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, package::{UpgradeTicket, UpgradeReceipt}, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Structs ~~~~~~~

public struct Upgrade has copy, drop, store {
    digest: vector<u8>,
    exclusive: bool,
}

/// Binds the committee-approved version policy to the upgrade transaction.
///
/// No abilities are intentional: callers cannot forge, copy, drop, or store
/// this value and must consume it in `finalize_upgrade` in the same PTB.
public struct UpgradeAuthorization {
    exclusive: bool,
}

// ~~~~~~~ Events ~~~~~~~

public struct PackageUpgraded has copy, drop {
    package: ID,
    version: u64,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    digest: vector<u8>,
    exclusive: bool,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    proposal::create(
        hashi,
        validator_address,
        Upgrade { digest, exclusive },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

/// Execute an approved proposal and bind its version policy to the ticket.
public fun execute(
    hashi: &mut Hashi,
    proposal_id: ID,
    clock: &Clock,
): (UpgradeTicket, UpgradeAuthorization) {
    let Upgrade { digest, exclusive } = proposal::execute(hashi, proposal_id, clock);
    let ticket = hashi.versioning_mut().authorize_upgrade(digest);
    (ticket, UpgradeAuthorization { exclusive })
}

/// Commit the package and its approved version policy atomically.
public fun finalize_upgrade(
    hashi: &mut Hashi,
    receipt: UpgradeReceipt,
    authorization: UpgradeAuthorization,
) {
    hashi.versioning().assert_version_enabled();
    let UpgradeAuthorization { exclusive } = authorization;
    let upgrade_package = receipt.package();
    hashi.versioning_mut().commit_upgrade(receipt, exclusive);
    let version = hashi.versioning().upgrade_cap().version();
    sui::event::emit(PackageUpgraded { package: upgrade_package, version });
}
