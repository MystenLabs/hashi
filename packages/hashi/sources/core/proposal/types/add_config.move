// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Governance proposal for introducing NEW keys into either config store,
/// which is how a node-side parameter becomes governable without a package
/// upgrade: the Move package never reads the key, the node does.
///
/// `epoch` selects the store. Keys added to the epoch config are copied onto
/// every committee formed from then on and are read by nodes from the
/// committee's pinned snapshot, so they change only at epoch boundaries; keys
/// added to the instant config are read live from the `Hashi` object.
///
/// The proposal is insert-only: every entry must name a key absent from the
/// target store, so a typo can never silently create a second copy of an
/// existing parameter (updates go through `update_config` and
/// `update_epoch_config`, which are equally strict the other way). The value
/// fixes the key's type for good, since the update proposals enforce type
/// stability. Entries bound for the epoch config also pass
/// `mpc_config::is_valid_value`, which keeps the reserved MPC keys out.
module hashi::add_config;

use hashi::{config_value::Value, hashi::Hashi, mpc_config, proposal};
use std::string::String;
use sui::{clock::Clock, vec_map::VecMap};

// ~~~~~~~ Constants ~~~~~~~

const THRESHOLD_BPS: u64 = 6667;

// ~~~~~~~ Errors ~~~~~~~

#[error(code = 0)]
const EKeyAlreadyExists: vector<u8> = b"Config key already exists in the target store";

#[error(code = 1)]
const EInvalidConfigEntry: vector<u8> = b"Proposed entry is not allowed in the epoch config";

#[error(code = 2)]
const ENoEntriesProvided: vector<u8> = b"AddConfig proposal must contain at least one entry";

// ~~~~~~~ Structs ~~~~~~~

public struct AddConfig has copy, drop, store {
    /// `true` targets the epoch config, `false` the instant config.
    epoch: bool,
    entries: VecMap<String, Value>,
}

// ~~~~~~~ Public Functions ~~~~~~~

public fun propose(
    hashi: &mut Hashi,
    validator_address: address,
    epoch: bool,
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
        AddConfig { epoch, entries },
        THRESHOLD_BPS,
        metadata,
        clock,
        ctx,
    )
}

public fun execute(hashi: &mut Hashi, proposal_id: ID, clock: &Clock) {
    hashi.versioning().assert_version_enabled();
    let AddConfig { epoch, entries } = proposal::execute(hashi, proposal_id, clock);
    let (keys, values) = entries.into_keys_values();
    let store = if (epoch) hashi.epoch_config_mut() else hashi.config_mut();
    keys.zip_do!(values, |key, value| {
        assert!(!store.contains(*key.as_bytes()), EKeyAlreadyExists);
        assert!(!epoch || mpc_config::is_valid_value(&key, &value), EInvalidConfigEntry);
        store.upsert(*key.as_bytes(), value);
    });
}
