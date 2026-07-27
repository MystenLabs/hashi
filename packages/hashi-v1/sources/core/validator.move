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
    self
        .committee_set_mut()
        .set_next_epoch_public_key(
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
