/// Module: validator
module hashi::validator;

use hashi::hashi::Hashi;
use std::string::String;
use sui::event;

public fun register(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    encryption_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self
        .committee_set_mut()
        .new_member(
            sui_system,
            public_key,
            proof_of_possession_signature,
            encryption_public_key,
            ctx,
        );

    event::emit(ValidatorRegistered {
        validator: ctx.sender(),
    });
}

public fun update_next_epoch_public_key(
    self: &mut Hashi,
    validator: address,
    next_epoch_public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
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

public fun update_operator_address(
    self: &mut Hashi,
    validator: address,
    operator: address,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self.committee_set_mut().set_operator_address(validator, operator, ctx);

    event::emit(ValidatorUpdated { validator });
}

public fun update_endpoint_url(
    self: &mut Hashi,
    validator: address,
    endpoint_url: String,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self.committee_set_mut().set_endpoint_url(validator, endpoint_url, ctx);

    event::emit(ValidatorUpdated { validator });
}

public fun update_tls_public_key(
    self: &mut Hashi,
    validator: address,
    tls_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self.committee_set_mut().set_tls_public_key(validator, tls_public_key, ctx);

    event::emit(ValidatorUpdated { validator });
}

public fun update_next_epoch_encryption_public_key(
    self: &mut Hashi,
    validator: address,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self
        .committee_set_mut()
        .set_next_epoch_encryption_public_key(validator, next_epoch_encryption_public_key, ctx);

    event::emit(ValidatorUpdated { validator });
}

public struct ValidatorRegistered has copy, drop {
    validator: address,
}

public struct ValidatorUpdated has copy, drop {
    validator: address,
}
