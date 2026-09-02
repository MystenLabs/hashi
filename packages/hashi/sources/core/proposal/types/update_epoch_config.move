// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for updating entries in the EPOCH config, the store
/// `start_reconfig` copies wholesale onto each new committee. A change lands
/// in the next committee formed after execution and never touches the
/// current epoch's committee, which keeps reading its own pinned copy.
///
/// Every entry must refer to an existing key with a matching value type and
/// pass `mpc_config::is_valid_value` (the MPC parameters live here), so
/// governance can tune parameters but never introduce unknown keys or change
/// an entry's type. The keys the package pins for the deployment's lifetime
/// are refused here as on `update_config`. New keys go through `add_config`.
module hashi::update_epoch_config;

use hashi::{btc_config, config, config_value::Value, hashi::Hashi, mpc_config, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error(code = 0)]
const EInvalidConfigEntry: vector<u8> =
    b"Unknown epoch config key, wrong value type, or out-of-range value in proposed entry";

#[error(code = 1)]
const ENoEntriesProvided: vector<u8> =
    b"UpdateEpochConfig proposal must contain at least one entry";

#[error(code = 2)]
const EProtectedConfigKey: vector<u8> = b"Config key cannot be changed through UpdateEpochConfig";

// ~~~~~~~ Structs ~~~~~~~

public struct UpdateEpochConfig has copy, drop, store {
    entries: VecMap<String, Value>,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    entries: VecMap<String, Value>,
    metadata: VecMap<String, String>,
    clock: &Clock,
    ctx: &mut TxContext,
): ID {
    hashi.versioning().assert_version_enabled();
    assert!(!entries.is_empty(), ENoEntriesProvided);
    proposal::create(
        hashi,
        validator_address,
        UpdateEpochConfig { entries },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi.versioning().assert_version_enabled();
    let UpdateEpochConfig { entries } = proposal::execute(hashi, proposal_id, clock);
    let (keys, values) = entries.into_keys_values();
    keys.zip_do!(values, |key, value| {
        // The keys the package pins for the deployment's lifetime are refused
        // on every config proposal, whichever store they are aimed at.
        assert!(
            config::is_governable_key(&key) && btc_config::is_governable_key(&key),
            EProtectedConfigKey,
        );
        assert!(
            hashi.epoch_config().is_valid_config_update(&key, &value)
                && mpc_config::is_valid_value(&key, &value),
            EInvalidConfigEntry,
        );
        hashi.epoch_config_mut().upsert(*key.as_bytes(), value);
    });
}
