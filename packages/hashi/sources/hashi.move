#[allow(unused_function, unused_field, unused_use)]
/// Module: hashi
module hashi::hashi;

use hashi::{btc::BTC, committee_set::CommitteeSet, config::Config, treasury::Treasury};
use std::string::String;
use sui::{balance::Balance, coin::Coin, object_bag::ObjectBag, sui::SUI};

public struct Hashi has key {
    id: UID,
    committees: CommitteeSet,
    config: Config,
    treasury: Treasury,
    deposit_queue: hashi::deposit_queue::DepositRequestQueue,
    utxo_pool: hashi::utxo_pool::UtxoPool,
}

public fun deposit(
    hashi: &mut Hashi,
    request: hashi::deposit_queue::DepositRequest,
    fee: Coin<SUI>,
) {
    hashi.config.assert_version();

    // Check if state is PAUSED
    assert!(!hashi.config.paused());

    // Check that the fee is sufficient
    assert!(hashi.config.deposit_fee() == fee.value());
    hashi.treasury.deposit_fee(fee);

    hashi.deposit_queue.insert(request);
}

public fun confirm_deposit(
    hashi: &mut Hashi,
    utxo_id: hashi::utxo::UtxoId,
    // cert: Cert
    ctx: &mut TxContext,
) {
    hashi.config.assert_version();

    // Check if state is PAUSED
    assert!(!hashi.config.paused());

    let request = hashi.deposit_queue.remove(utxo_id);

    // verify cert over the request
    // cert.verify(&request)

    let utxo = request.into_utxo();
    let derivation_path = utxo.derivation_path();

    if (derivation_path.is_some()) {
        let recipient = derivation_path.destroy_some();
        let amount = utxo.amount();
        // XXX Do we want to check an inflow limit here?
        let btc = hashi.treasury.mint<BTC>(amount, ctx);
        sui::transfer::public_transfer(btc, recipient);
    };

    hashi.utxo_pool.insert(utxo);
}

#[allow(unused_function)]
fun init(ctx: &mut TxContext) {
    let hashi = Hashi {
        id: object::new(ctx),
        committees: hashi::committee_set::create(ctx),
        config: hashi::config::create(),
        treasury: hashi::treasury::create(ctx),
        deposit_queue: hashi::deposit_queue::create(ctx),
        utxo_pool: hashi::utxo_pool::create(ctx),
    };

    sui::transfer::share_object(hashi);
}

entry fun register_btc(
    self: &mut Hashi,
    coin_registry: &mut sui::coin_registry::CoinRegistry,
    ctx: &mut TxContext,
) {
    self.config.assert_version();

    let (treasury_cap, metadata_cap) = hashi::btc::create(coin_registry, ctx);
    self.treasury.register_treasury_cap(treasury_cap);
    self.treasury.register_metadata_cap(metadata_cap);
}

entry fun register_upgrade_cap(
    self: &mut Hashi,
    upgrade_cap: sui::package::UpgradeCap,
    _ctx: &mut TxContext,
) {
    self.config.assert_version();

    let this_package_id = std::type_name::original_id<Hashi>().to_id();
    // Ensure that the provided cap is for this package
    assert!(upgrade_cap.package() == this_package_id);

    sui::dynamic_object_field::add(&mut self.id, b"TODO figure out key", upgrade_cap);
}

// TODO move most/all of these functions to their own module for better orginization
public fun register_validator(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config.assert_version();
    self.committees.new_member(sui_system, public_key, proof_of_possession_signature, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_https_address(self: &mut Hashi, https_address: String, ctx: &mut TxContext) {
    self.config.assert_version();

    self.committees.set_https_address(ctx.sender(), https_address, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_tls_public_key(
    self: &mut Hashi,
    tls_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config.assert_version();

    self.committees.set_tls_public_key(ctx.sender(), tls_public_key, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_next_epoch_encryption_public_key(
    self: &mut Hashi,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config.assert_version();
    self
        .committees
        .set_next_epoch_encryption_public_key(ctx.sender(), next_epoch_encryption_public_key, ctx);
}

entry fun bootstrap(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &TxContext,
) {
    self.config.assert_version();

    assert!(self.committees.epoch() == 0);
    assert!(!self.committees.has_committee(ctx.epoch()));

    self.committees.bootstrap(sui_system, ctx);
}
