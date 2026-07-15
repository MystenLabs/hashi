// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// The root shared object of the bridge. `Hashi` aggregates every subsystem —
/// committee set, config, versioning, treasury, governance proposals, and TOB
/// certificate storage — and hangs per-chain state (e.g. `BitcoinState`) off
/// its `UID` as dynamic fields. It also provides the package-wide guards
/// (pause, reconfig, committee-signature verification) that entry functions
/// in other modules call through, and the one-time `finish_publish` launch
/// switch that hands the package `UpgradeCap` into on-chain custody.
module hashi::hashi;

use hashi::{
    bitcoin_state::{Self, BitcoinState},
    committee::{CertifiedMessage, Committee, CommitteeSignature},
    committee_set::CommitteeSet,
    config::Config,
    config_registry::{ConfigRegistry, PendingUpdate},
    proposals::{Self, Proposals},
    threshold,
    treasury::Treasury,
    versioning::{Self, Versioning}
};
use std::string::String;
use sui::{bag::{Self, Bag}, dynamic_field as df};

// ~~~~~~~ Errors ~~~~~~~

#[error]
const ESystemPaused: vector<u8> = b"System is currently paused";
#[error]
const EReconfiguring: vector<u8> = b"System is currently reconfiguring";
#[error]
const ENoCommittee: vector<u8> = b"No committee exists for the current epoch";
#[error]
const EWrongUpgradeCap: vector<u8> = b"Upgrade cap does not belong to this package";

// ~~~~~~~ Structs ~~~~~~~

public struct Hashi has key {
    id: UID,
    committee_set: CommitteeSet,
    config: Config,
    versioning: Versioning,
    treasury: Treasury,
    proposals: Proposals,
    /// TOB certificates by (epoch, batch_index) -> EpochCertsV1
    tob: Bag,
    /// Number of presignatures consumed in the current epoch.
    /// Used by recovering nodes to derive `(batch_index, index_in_batch)`.
    num_consumed_presigs: u64,
    /// Governed metadata for config keys (pinning, updatability, constraints).
    /// Appended (with the field below) so the Rust mirror, which deserializes
    /// this struct by field order, only ever appends.
    config_registry: ConfigRegistry,
    /// Governance-scheduled value changes, committed into `config` by the
    /// first reconfig whose next epoch reaches each entry's activation epoch.
    pending_config_updates: sui::vec_map::VecMap<std::string::String, PendingUpdate>,
}

// ~~~~~~~ Entry Functions ~~~~~~~

// The launch switch. Finalizes input parameters, registers BTC, and hands
// the package's `UpgradeCap` into on-chain custody (`Versioning`) — which is
// what unlocks genesis: validators can register beforehand, but
// `reconfig::start_reconfig` refuses to form the initial committee until the
// cap is registered here. The publisher holds the cap through the
// validator-registration window and calls this once the expected committee
// has registered. `Option::fill` inside `set_upgrade_cap` (and the write-once
// BTC currency/treasury registration) make this call-once.
//
// The guardian URL and BTC key are both required: the guardian is a
// load-bearing component of every deposit address (2-of-2 taproot leaf)
// and every withdrawal signature, so a deploy without them would produce
// a non-functional bridge.
entry fun finish_publish(
    self: &mut Hashi,
    upgrade_cap: sui::package::UpgradeCap,
    bitcoin_chain_id: address,
    guardian_url: String,
    guardian_btc_public_key: vector<u8>,
    bitcoin_confirmation_threshold: Option<u64>,
    bitcoin_deposit_time_delay_ms: Option<u64>,
    coin_registry: &mut sui::coin_registry::CoinRegistry,
    ctx: &mut TxContext,
) {
    self.versioning.assert_version_enabled();

    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    // Ensure that the provided cap is for this package
    assert!(upgrade_cap.package() == this_package_id, EWrongUpgradeCap);

    self.versioning_mut().set_upgrade_cap(upgrade_cap);
    hashi::btc_config::set_bitcoin_chain_id(self.config_mut(), bitcoin_chain_id);

    self.config_mut().set_guardian_url(guardian_url);
    self.config_mut().set_guardian_btc_public_key(guardian_btc_public_key);

    // Register the keys set above so the registry mirrors the config's key
    // set at every point (registered => present). Registration aborts on
    // duplicates, which also makes this function call-once along this path.
    hashi::btc_config::register_chain_id_key(&mut self.config_registry);
    hashi::config::register_guardian_keys(&mut self.config_registry);

    if (bitcoin_confirmation_threshold.is_some()) {
        hashi::btc_config::set_bitcoin_confirmation_threshold(
            self.config_mut(),
            bitcoin_confirmation_threshold.destroy_some(),
        );
    } else {
        bitcoin_confirmation_threshold.destroy_none();
    };

    if (bitcoin_deposit_time_delay_ms.is_some()) {
        hashi::btc_config::set_bitcoin_deposit_time_delay_ms(
            self.config_mut(),
            bitcoin_deposit_time_delay_ms.destroy_some(),
        );
    } else {
        bitcoin_deposit_time_delay_ms.destroy_none();
    };

    let (treasury_cap, metadata_cap) = hashi::btc::create(coin_registry, ctx);
    self.treasury.register_treasury_cap(treasury_cap);
    self.treasury.register_metadata_cap(metadata_cap);
}

// ~~~~~~~ Package Functions ~~~~~~~

public(package) fun assert_unpaused(self: &Hashi) {
    // Check if state is PAUSED
    assert!(!self.config().paused(), ESystemPaused);
}

/// Verify a committee signature over a message.
/// Returns the certified message (message + signature + stake support).
public(package) fun verify<T>(
    self: &Hashi,
    intent: u16,
    message: T,
    sig: CommitteeSignature,
): CertifiedMessage<T> {
    let threshold =
        threshold::certificate_threshold(self.current_committee().total_weight() as u16) as u64;
    self.current_committee().verify_certificate(intent, message, sig, threshold)
}

/// Verify a committee signature against a specific committee (not necessarily current).
/// Used by reconfig which verifies against the next epoch's committee.
public(package) fun verify_with_committee<T>(
    _self: &Hashi,
    committee: &Committee,
    intent: u16,
    message: T,
    sig: CommitteeSignature,
): CertifiedMessage<T> {
    let threshold = threshold::certificate_threshold(committee.total_weight() as u16) as u64;
    committee.verify_certificate(intent, message, sig, threshold)
}

public(package) fun assert_not_reconfiguring(self: &Hashi) {
    // Check that we are not reconfiguring
    assert!(!self.committee_set().is_reconfiguring(), EReconfiguring);
    // Check that we still don't need to do genesis
    assert!(self.committee_set().has_committee(self.committee_set().epoch()), ENoCommittee);
}

public(package) fun id(self: &Hashi): &UID {
    &self.id
}

public(package) fun config(self: &Hashi): &Config {
    &self.config
}

public(package) fun config_registry(self: &Hashi): &ConfigRegistry {
    &self.config_registry
}

public(package) fun config_registry_mut(self: &mut Hashi): &mut ConfigRegistry {
    &mut self.config_registry
}

public(package) fun pending_config_updates(
    self: &Hashi,
): &sui::vec_map::VecMap<std::string::String, PendingUpdate> {
    &self.pending_config_updates
}

public(package) fun pending_config_updates_mut(
    self: &mut Hashi,
): &mut sui::vec_map::VecMap<std::string::String, PendingUpdate> {
    &mut self.pending_config_updates
}

/// Commit every scheduled update whose activation epoch has arrived. Runs in
/// start_reconfig before `pin`, so a value scheduled for epoch E is first
/// snapshotted by exactly the reconfig that forms epoch E's committee; the
/// global config stays the single source of truth for pinning.
public(package) fun commit_pending_config_updates(self: &mut Hashi, next_epoch: u64) {
    let due = self.pending_config_updates.keys().filter!(|key| {
        hashi::config_registry::pending_activate_at_epoch(
            self.pending_config_updates.get(key),
        ) <= next_epoch
    });
    due.do!(|key| {
        let (_, pending) = self.pending_config_updates.remove(&key);
        let value = hashi::config_registry::pending_value(&pending);
        // Re-validate against the current spec: it may have narrowed (or the
        // key been made write-once or removed) since scheduling. A stale
        // entry is dropped rather than applied — fail closed toward the
        // spec; aborting here would brick start_reconfig.
        if (
            self.config.is_valid_config_update(&key, &value)
                && self.config_registry.is_valid_update(&key, &value)
        ) {
            self.config.upsert(*key.as_bytes(), value);
        };
    });
}

public(package) fun config_mut(self: &mut Hashi): &mut Config {
    &mut self.config
}

public(package) fun versioning(self: &Hashi): &Versioning {
    &self.versioning
}

public(package) fun versioning_mut(self: &mut Hashi): &mut Versioning {
    &mut self.versioning
}

public(package) fun treasury(self: &Hashi): &Treasury {
    &self.treasury
}

public(package) fun committee_set(self: &Hashi): &CommitteeSet {
    &self.committee_set
}

public(package) fun committee_set_mut(self: &mut Hashi): &mut CommitteeSet {
    &mut self.committee_set
}

public(package) fun current_committee(self: &Hashi): &Committee {
    self.committee_set.current_committee()
}

public(package) fun treasury_mut(self: &mut Hashi): &mut Treasury {
    &mut self.treasury
}

public(package) fun proposals(self: &Hashi): &Proposals {
    &self.proposals
}

public(package) fun proposals_mut(self: &mut Hashi): &mut Proposals {
    &mut self.proposals
}

public(package) fun bitcoin(self: &Hashi): &BitcoinState {
    df::borrow(&self.id, bitcoin_state::key())
}

public(package) fun bitcoin_mut(self: &mut Hashi): &mut BitcoinState {
    df::borrow_mut(&mut self.id, bitcoin_state::key())
}

public(package) fun tob_mut(self: &mut Hashi): &mut Bag {
    &mut self.tob
}

public(package) fun epoch_certs(
    self: &mut Hashi,
    key: hashi::tob::TobKey,
    ctx: &mut TxContext,
): &mut hashi::tob::EpochCertsV1 {
    let epoch = key.epoch();
    if (!self.tob.contains(key)) {
        self.tob.add(key, hashi::tob::create(epoch, key.protocol_type(), ctx));
    };
    self.tob.borrow_mut(key)
}

public(package) fun num_consumed_presigs(self: &Hashi): u64 {
    self.num_consumed_presigs
}

public(package) fun allocate_presigs(self: &mut Hashi, count: u64): u64 {
    let start = self.num_consumed_presigs;
    self.num_consumed_presigs = self.num_consumed_presigs + count;
    start
}

public(package) fun reset_num_consumed_presigs(self: &mut Hashi) {
    self.num_consumed_presigs = 0;
}

// ~~~~~~~ Private Functions ~~~~~~~

#[allow(unused_function)]
fun init(ctx: &mut TxContext) {
    let mut hashi = Hashi {
        id: object::new(ctx),
        committee_set: hashi::committee_set::create(ctx),
        config: {
            let mut config = hashi::config::create();
            hashi::btc_config::init_defaults(&mut config);
            hashi::mpc_config::init_defaults(&mut config);
            config
        },
        versioning: versioning::create(),
        treasury: hashi::treasury::create(ctx),
        proposals: proposals::create(ctx),
        tob: bag::new(ctx),
        num_consumed_presigs: 0,
        config_registry: {
            let mut registry = hashi::config_registry::empty();
            hashi::config::register_core_keys(&mut registry);
            hashi::btc_config::register_keys(&mut registry);
            hashi::mpc_config::register_keys(&mut registry);
            registry
        },
        pending_config_updates: sui::vec_map::empty(),
    };

    df::add(&mut hashi.id, bitcoin_state::key(), bitcoin_state::new(ctx));

    sui::transfer::share_object(hashi);
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
public(package) fun tob_contains(self: &Hashi, key: hashi::tob::TobKey): bool {
    self.tob.contains(key)
}

#[test_only]
public(package) fun epoch_certs_ref(
    self: &Hashi,
    key: hashi::tob::TobKey,
): &hashi::tob::EpochCertsV1 {
    self.tob.borrow(key)
}

#[test_only]
/// Creates a Hashi instance for testing with all components provided
public fun create_for_testing(
    committee_set: CommitteeSet,
    config: Config,
    versioning: Versioning,
    treasury: Treasury,
    proposals: Proposals,
    tob: Bag,
    ctx: &mut TxContext,
): Hashi {
    let mut hashi = Hashi {
        id: object::new(ctx),
        committee_set,
        config,
        versioning,
        treasury,
        proposals,
        tob,
        num_consumed_presigs: 0,
        // Same registry as `init`; tests that need the post-launch keys call
        // `register_launch_keys_for_testing` (or run finish_publish).
        config_registry: {
            let mut registry = hashi::config_registry::empty();
            hashi::config::register_core_keys(&mut registry);
            hashi::btc_config::register_keys(&mut registry);
            hashi::mpc_config::register_keys(&mut registry);
            registry
        },
        pending_config_updates: sui::vec_map::empty(),
    };
    df::add(&mut hashi.id, bitcoin_state::key(), bitcoin_state::new(ctx));
    hashi
}

#[test_only]
/// Registers the keys `finish_publish` would register, for tests that set
/// launch keys via the config setters instead of running finish_publish.
public fun register_launch_keys_for_testing(self: &mut Hashi) {
    hashi::btc_config::register_chain_id_key(&mut self.config_registry);
    hashi::config::register_guardian_keys(&mut self.config_registry);
}

#[test_only]
/// Forwards to `finish_publish` so its guards can be exercised from
/// `hashi::finish_publish_tests` (non-public entry functions are not
/// callable from other modules).
public fun finish_publish_for_testing(
    self: &mut Hashi,
    upgrade_cap: sui::package::UpgradeCap,
    bitcoin_chain_id: address,
    guardian_url: String,
    guardian_btc_public_key: vector<u8>,
    coin_registry: &mut sui::coin_registry::CoinRegistry,
    ctx: &mut TxContext,
) {
    finish_publish(
        self,
        upgrade_cap,
        bitcoin_chain_id,
        guardian_url,
        guardian_btc_public_key,
        option::none(),
        option::none(),
        coin_registry,
        ctx,
    )
}
