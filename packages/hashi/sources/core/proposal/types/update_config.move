// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for updating entries in the INSTANT config, the store
/// whose values take effect the moment the proposal executes. A proposal
/// carries a map of key/value entries; on execution every entry must refer to
/// an existing key with a matching value type and must not be one of the keys
/// the package pins for the deployment's lifetime (the guardian BTC public key
/// and the Bitcoin chain id) before being upserted, so governance can tune
/// parameters but never introduce unknown keys, change an entry's type, or
/// rewrite a pinned key. New keys go through `add_config`; the epoch-scoped
/// store, including the MPC parameters, through `update_epoch_config`.
module hashi::update_config;

use hashi::{btc_config, config, config_value::Value, hashi::Hashi, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error]
const EInvalidConfigEntry: vector<u8> =
    b"Unknown instant config key or wrong value type in proposed entry";

#[error]
const ENoEntriesProvided: vector<u8> = b"UpdateConfig proposal must contain at least one entry";

#[error]
const EProtectedConfigKey: vector<u8> = b"Config key cannot be changed through UpdateConfig";

// ~~~~~~~ Structs ~~~~~~~

public struct UpdateConfig has copy, drop, store {
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
        UpdateConfig { entries },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    let UpdateConfig { entries } = proposal::execute(hashi, proposal_id, clock);
    let (keys, values) = entries.into_keys_values();
    keys.zip_do!(values, |key, value| {
        assert!(
            config::is_governable_key(&key) && btc_config::is_governable_key(&key),
            EProtectedConfigKey,
        );
        assert!(hashi.config().is_valid_config_update(&key, &value), EInvalidConfigEntry);
        hashi.config_mut().upsert(*key.as_bytes(), value);
    });
}
