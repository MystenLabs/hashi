// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Module: hashi
module hashi::hashi;

use hashi::{
    bitcoin_state::{Self, BitcoinState},
    committee::{CertifiedMessage, Committee, CommitteeSignature},
    committee_set::CommitteeSet,
    config::Config,
    proposals::{Self, Proposals},
    threshold,
    treasury::Treasury
};
use std::string::String;
use sui::{bag::{Self, Bag}, dynamic_field as df};

#[error]
const ESystemPaused: vector<u8> = b"System is currently paused";
#[error]
const EReconfiguring: vector<u8> = b"System is currently reconfiguring";
#[error]
const ENoCommittee: vector<u8> = b"No committee exists for the current epoch";
#[error]
const EWrongUpgradeCap: vector<u8> = b"Upgrade cap does not belong to this package";

public struct Hashi has key {
    id: UID,
    committee_set: CommitteeSet,
    config: Config,
    treasury: Treasury,
    proposals: Proposals,
    /// TOB certificates by (epoch, batch_index) -> EpochCertsV1
    tob: Bag,
    /// Number of presignatures consumed in the current epoch.
    /// Used by recovering nodes to derive `(batch_index, index_in_batch)`.
    num_consumed_presigs: u64,
}

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
        treasury: hashi::treasury::create(ctx),
        proposals: proposals::create(ctx),
        tob: bag::new(ctx),
        num_consumed_presigs: 0,
    };

    df::add(&mut hashi.id, bitcoin_state::key(), bitcoin_state::new(ctx));

    sui::transfer::share_object(hashi);
}

public(package) fun assert_unpaused(self: &Hashi) {
    // Check if state is PAUSED
    assert!(!self.config().paused(), ESystemPaused);
}

/// Verify a committee signature over a message.
/// Returns the certified message (message + signature + stake support).
public(package) fun verify<T>(
    self: &Hashi,
    message: T,
    sig: CommitteeSignature,
): CertifiedMessage<T> {
    let threshold =
        threshold::certificate_threshold(self.current_committee().total_weight() as u16) as u64;
    self.current_committee().verify_certificate(message, sig, threshold)
}

/// Verify a committee signature against a specific committee (not necessarily current).
/// Used by reconfig which verifies against the next epoch's committee.
public(package) fun verify_with_committee<T>(
    _self: &Hashi,
    committee: &Committee,
    message: T,
    sig: CommitteeSignature,
): CertifiedMessage<T> {
    let threshold = threshold::certificate_threshold(committee.total_weight() as u16) as u64;
    committee.verify_certificate(message, sig, threshold)
}

public(package) fun assert_not_reconfiguring(self: &Hashi) {
    // Check that we are not reconfiguring
    assert!(!self.committee_set().is_reconfiguring(), EReconfiguring);
    // Check that we still don't need to do genesis
    assert!(self.committee_set().has_committee(self.committee_set().epoch()), ENoCommittee);
}

// Function that needs to be called immediately after publishing to finalize
// some input parameters, register BTC and the package's UpgradeCap.
entry fun finish_publish(
    self: &mut Hashi,
    upgrade_cap: sui::package::UpgradeCap,
    bitcoin_chain_id: address,
    guardian_url: Option<String>,
    guardian_public_key: Option<vector<u8>>,
    coin_registry: &mut sui::coin_registry::CoinRegistry,
    ctx: &mut TxContext,
) {
    self.config.assert_version_enabled();

    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    // Ensure that the provided cap is for this package
    assert!(upgrade_cap.package() == this_package_id, EWrongUpgradeCap);

    self.config_mut().set_upgrade_cap(upgrade_cap);
    hashi::btc_config::set_bitcoin_chain_id(self.config_mut(), bitcoin_chain_id);

    if (guardian_url.is_some() && guardian_public_key.is_some()) {
        self.config_mut().set_guardian(
            guardian_url.destroy_some(),
            guardian_public_key.destroy_some(),
        );
    } else {
        guardian_url.destroy_none();
        guardian_public_key.destroy_none();
    };

    let (treasury_cap, metadata_cap) = hashi::btc::create(coin_registry, ctx);
    self.treasury.register_treasury_cap(treasury_cap);
    self.treasury.register_metadata_cap(metadata_cap);
}

public(package) fun id(self: &Hashi): &UID {
    &self.id
}

public(package) fun config(self: &Hashi): &Config {
    &self.config
}

public(package) fun config_mut(self: &mut Hashi): &mut Config {
    &mut self.config
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
    protocol_type: hashi::tob::ProtocolType,
    ctx: &mut TxContext,
): &mut hashi::tob::EpochCertsV1 {
    let epoch = key.epoch();
    if (!self.tob.contains(key)) {
        self.tob.add(key, hashi::tob::create(epoch, protocol_type, ctx));
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

// ======== Test-only Functions ========

#[test_only]
/// Creates a Hashi instance for testing with all components provided
public fun create_for_testing(
    committee_set: CommitteeSet,
    config: Config,
    treasury: Treasury,
    proposals: Proposals,
    tob: Bag,
    ctx: &mut TxContext,
): Hashi {
    let mut hashi = Hashi {
        id: object::new(ctx),
        committee_set,
        config,
        treasury,
        proposals,
        tob,
        num_consumed_presigs: 0,
    };
    df::add(&mut hashi.id, bitcoin_state::key(), bitcoin_state::new(ctx));
    hashi
}
