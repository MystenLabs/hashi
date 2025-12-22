/// Module: validator
module hashi::validator;

use hashi::hashi::Hashi;
use std::string::String;

public fun register(
    self: &mut Hashi,
    sui_system: &sui_system::sui_system::SuiSystemState,
    public_key: vector<u8>,
    proof_of_possession_signature: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self.committee_set_mut().new_member(sui_system, public_key, proof_of_possession_signature, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_https_address(self: &mut Hashi, https_address: String, ctx: &mut TxContext) {
    self.config().assert_version_enabled();

    self.committee_set_mut().set_https_address(ctx.sender(), https_address, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_tls_public_key(
    self: &mut Hashi,
    tls_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();

    self.committee_set_mut().set_tls_public_key(ctx.sender(), tls_public_key, ctx);
}

//TODO require the validator address passed in to better support operator address
public fun update_next_epoch_encryption_public_key(
    self: &mut Hashi,
    next_epoch_encryption_public_key: vector<u8>,
    ctx: &mut TxContext,
) {
    self.config().assert_version_enabled();
    self
        .committee_set_mut()
        .set_next_epoch_encryption_public_key(ctx.sender(), next_epoch_encryption_public_key, ctx);
}
