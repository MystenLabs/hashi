// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Package upgrade governance module.
///
/// ## Upgrade Flow
///
/// 1. A committee member calls `upgrade::propose()` with the new package digest
/// 2. Committee members vote on the `Proposal<Upgrade>` until quorum is reached
/// 3. `upgrade::execute(Proposal<Upgrade>, &mut Hashi)` -> `UpgradeTicket`
///    - Authorizes the upgrade using the stored `UpgradeCap`
/// 4. `sui::package::upgrade(UpgradeTicket, ...)` -> `UpgradeReceipt`
///    - Performed by the Sui runtime during package publish transaction
/// 5. `config::commit_upgrade(UpgradeReceipt)`
///    - Commits the upgrade to the `UpgradeCap` and auto-enables the new version
module hashi::upgrade;

use hashi::{hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, package::{UpgradeTicket, UpgradeReceipt}, vec_map::VecMap};

const THRESHOLD_BPS: u64 = 10000;

public struct Upgrade has drop, store {
    digest: vector<u8>,
}

public fun propose(
    hashi: &mut Hashi,
    digest: vector<u8>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.config().assert_version_enabled();
    proposal::create(hashi, Upgrade { digest }, THRESHOLD_BPS, metadata, clock, ctx)
}

/// Executes an approved upgrade proposal.
///
/// Returns an `UpgradeTicket` that must be used in the same transaction
/// to publish the new package. The Sui runtime will return an `UpgradeReceipt`
/// which must then be passed to `finalize_upgrade()` to finalize the upgrade.
public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock): UpgradeTicket {
    let Upgrade { digest } = proposal::execute(hashi, proposal_id, clock);
    hashi.config_mut().authorize_upgrade(digest)
}

public fun finalize_upgrade(hashi: &mut Hashi, receipt: UpgradeReceipt) {
    hashi.config().assert_version_enabled();
    let upgrade_package = receipt.package();
    hashi.config_mut().commit_upgrade(receipt);
    let version = hashi.config().upgrade_cap().version();
    hashi::proposal_events::emit_package_upgraded_event(upgrade_package, version);
}
