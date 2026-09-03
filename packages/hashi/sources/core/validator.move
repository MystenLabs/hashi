// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// `ctx` params stay `&mut` so future versions can create objects in these
// entry points without a signature change.
/// Validator registration and metadata maintenance. Entry points let a Sui
/// validator register as a Hashi committee member and update its next-epoch
/// BLS key, operator address, endpoint URL, TLS key, and next-epoch
/// encryption key. Every mutation emits an event for off-chain watchers.
#[allow(unused_mut_parameter)]
module hashi::validator;

use hashi::hashi::Hashi;
use std::string::String;
use sui::event;

// ~~~~~~~ Events ~~~~~~~

public struct ValidatorRegistered has copy, drop {
    validator: address,
}

public struct ValidatorUpdated has copy, drop {
    validator: address,
}

public struct ValidatorResigned has copy, drop {
    validator: address,
}

public struct ValidatorResignationWithdrawn has copy, drop {
    validator: address,
}

public struct ValidatorDeregistered has copy, drop {
    validator: address,
}

// ~~~~~~~ Entry Functions ~~~~~~~

/// Registration and key/metadata updates (below) are deliberately NOT gated
/// on pause/reconfig: operators must be able to rotate keys and prepare
/// nodes while the system is paused, and blocking updates during reconfig
/// would let a stalled reconfig freeze operator maintenance.
entry fun register(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().new_member(sui_system, ctx);

    event::emit(ValidatorRegistered {
        validator: ctx.sender(),
    });
}

entry fun update_next_epoch_public_key(
    self: &mut Hashi,
    validator: address,
    next_epoch_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    let hashi_id = self.id().uid_to_address();
    self
        .committee_set_mut()
        .set_next_epoch_public_key(
            hashi_id,
            validator,
            next_epoch_public_key,
            proof_of_possession_signature,
            ctx,
        );

    event::emit(ValidatorUpdated { validator });
}

entry fun update_operator_address(
    self: &mut Hashi,
    validator: address,
    operator: address,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().set_operator_address(validator, operator, ctx);

    event::emit(ValidatorUpdated { validator });
}

entry fun update_endpoint_url(
    self: &mut Hashi,
    validator: address,
    endpoint_url: String,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().set_endpoint_url(validator, endpoint_url, ctx);

    event::emit(ValidatorUpdated { validator });
}

entry fun update_tls_public_key(
    self: &mut Hashi,
    validator: address,
    tls_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().set_tls_public_key(validator, tls_public_key, ctx);

    event::emit(ValidatorUpdated { validator });
}

/// Voluntarily resign from the committee, authorized for the validator's
/// own key or its delegated operator key.
///
/// Only sets the resignation flag: the member keeps serving the current
/// epoch (and a pending epoch mid-reconfiguration), the next committee
/// formation skips them, and the registration is deleted separately by the
/// permissionless `remove_inactive_member` once they hold no epoch duties —
/// after which re-joining requires a full re-registration. Revocable via
/// `withdraw_resignation` until the registration is removed.
entry fun resign(self: &mut Hashi, validator: address, ctx: &mut TxContext) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().request_resignation(validator, ctx);
    event::emit(ValidatorResigned { validator });
}

/// Permissionless registry cleanup: delete the registration of a member
/// with no epoch duties (not in the current committee, nor in a pending one
/// mid-reconfiguration) who either voluntarily resigned or is no longer in
/// Sui's active validator set. Deliberately independent of the
/// reconfiguration flow, which never touches the registry.
///
/// Governance-ignored members are not removable — deleting the registration
/// would delete the flag with it, letting them shed the exclusion by simply
/// re-registering.
entry fun remove_inactive_member(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    validator: address,
) {
    self.versioning().assert_version_enabled();
    let is_active_sui_validator = sui_system.active_validator_addresses_ref().contains(&validator);
    self.committee_set_mut().remove_inactive_member(validator, is_active_sui_validator);
    event::emit(ValidatorDeregistered { validator });
}

/// Withdraw a pending resignation. If the next committee already formed
/// without the member, they keep their registration but sit out that one
/// epoch.
entry fun withdraw_resignation(self: &mut Hashi, validator: address, ctx: &mut TxContext) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().clear_resignation(validator, ctx);
    event::emit(ValidatorResignationWithdrawn { validator });
}

entry fun update_next_epoch_encryption_public_key(
    self: &mut Hashi,
    validator: address,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.versioning().assert_version_enabled();
    self
        .committee_set_mut()
        .set_next_epoch_encryption_public_key(validator, next_epoch_encryption_public_key, ctx);

    event::emit(ValidatorUpdated { validator });
}

// ~~~~~~~ Test Helpers ~~~~~~~

#[test_only]
/// Forwards to `resign` so it can be exercised from `hashi::resignation_tests`
/// (non-public entry functions are not callable from other modules).
public fun resign_for_testing(self: &mut Hashi, validator: address, ctx: &mut TxContext) {
    resign(self, validator, ctx)
}

#[test_only]
/// Forwards to `withdraw_resignation` for `hashi::resignation_tests`.
public fun withdraw_resignation_for_testing(
    self: &mut Hashi,
    validator: address,
    ctx: &mut TxContext,
) {
    withdraw_resignation(self, validator, ctx)
}

#[test_only]
/// `remove_inactive_member` with an explicit Sui-validator-set answer, since
/// unit tests cannot construct a `SuiSystemState`.
public fun remove_inactive_member_for_testing(
    self: &mut Hashi,
    validator: address,
    is_active_sui_validator: bool,
) {
    self.versioning().assert_version_enabled();
    self.committee_set_mut().remove_inactive_member(validator, is_active_sui_validator);
    event::emit(ValidatorDeregistered { validator });
}
