// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module hashi::proposal_thresholds;
use hashi::claim::Claim;
use hashi::deny::Deny;
use hashi::hashi::Hashi;
use hashi::register_coin::RegisterCoin;
use hashi::upgrade::Upgrade;

const CONFIG_THRESHOLD_BPS: u64 = 10000;
const DENY_THRESHOLD_BPS: u64 = 10000;
const CLAIM_THRESHOLD_BPS: u64 = 10000;
const REGISTER_COIN_THRESHOLD_BPS: u64 = 10000;

/// Initialize default proposal thresholds in a single place.
///
/// This module depends on proposal type modules, but no core module
/// (like `hashi::hashi` or `hashi::config`) depends on this module.
/// Call this once during setup to avoid per-type initialize functions.
public fun initialize_default_thresholds(hashi: &mut Hashi) {
    let cfg = hashi::hashi::config(hashi);

    hashi::config::set_proposal_threshold<Upgrade>(
        cfg,
        CONFIG_THRESHOLD_BPS,
    );
    hashi::config::set_proposal_threshold<Deny>(
        cfg,
        DENY_THRESHOLD_BPS,
    );
    hashi::config::set_proposal_threshold<Claim>(
        cfg,
        CLAIM_THRESHOLD_BPS,
    );
    hashi::config::set_proposal_threshold<RegisterCoin>(
        cfg,
        REGISTER_COIN_THRESHOLD_BPS,
    );
}
