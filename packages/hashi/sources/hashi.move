/// Module: hashi
module hashi::hashi;

use hashi::{
    committee::Committee,
    committee_set::CommitteeSet,
    config::Config,
    proposal_set::{Self, ProposalSet},
    treasury::Treasury
};

public struct Hashi has key {
    id: UID,
    committee_set: CommitteeSet,
    config: Config,
    treasury: Treasury,
    deposit_queue: hashi::deposit_queue::DepositRequestQueue,
    utxo_pool: hashi::utxo_pool::UtxoPool,
    proposals: ProposalSet,
}

#[allow(unused_function)]
fun init(ctx: &mut TxContext) {
    let hashi = Hashi {
        id: object::new(ctx),
        committee_set: hashi::committee_set::create(ctx),
        config: hashi::config::create(),
        treasury: hashi::treasury::create(ctx),
        deposit_queue: hashi::deposit_queue::create(ctx),
        utxo_pool: hashi::utxo_pool::create(ctx),
        proposals: proposal_set::create(ctx),
    };

    sui::transfer::share_object(hashi);
}

entry fun register_btc(
    self: &mut Hashi,
    coin_registry: &mut sui::coin_registry::CoinRegistry,
    ctx: &mut TxContext,
) {
    self.config.assert_version_enabled();

    let (treasury_cap, metadata_cap) = hashi::btc::create(coin_registry, ctx);
    self.treasury.register_treasury_cap(treasury_cap);
    self.treasury.register_metadata_cap(metadata_cap);
}

entry fun register_upgrade_cap(
    self: &mut Hashi,
    upgrade_cap: sui::package::UpgradeCap,
    _ctx: &mut TxContext,
) {
    self.config.assert_version_enabled();

    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    // Ensure that the provided cap is for this package
    assert!(upgrade_cap.package() == this_package_id);

    self.config_mut().set_upgrade_cap(upgrade_cap);
}

entry fun bootstrap(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.config.assert_version_enabled();

    assert!(self.committee_set.epoch() == 0);
    assert!(!self.committee_set.has_committee(ctx.epoch()));

    self.committee_set.bootstrap(sui_system, ctx);
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

public(package) fun proposals_mut(self: &mut Hashi): &mut ProposalSet {
    &mut self.proposals
}

public(package) fun deposit_queue(self: &Hashi): &hashi::deposit_queue::DepositRequestQueue {
    &self.deposit_queue
}

public(package) fun deposit_queue_mut(
    self: &mut Hashi,
): &mut hashi::deposit_queue::DepositRequestQueue {
    &mut self.deposit_queue
}

public(package) fun utxo_pool(self: &Hashi): &hashi::utxo_pool::UtxoPool {
    &self.utxo_pool
}

public(package) fun utxo_pool_mut(self: &mut Hashi): &mut hashi::utxo_pool::UtxoPool {
    &mut self.utxo_pool
}
