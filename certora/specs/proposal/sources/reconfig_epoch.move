/// @module Reconfiguration Integrity Properties
/// @contract hashi::reconfig
/// @contract hashi::committee_set
/// @contract hashi::validator
module proposal::reconfig_epoch;

use cvlm::asserts::{cvlm_assert, cvlm_assume_msg};
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use sui_system::sui_system::SuiSystemState;

public fun cvlm_manifest() {
    target(@hashi, b"reconfig", b"start_reconfig");
    target(@hashi, b"reconfig", b"submit_committee_handoff");
    target(@hashi, b"reconfig", b"abort_reconfig");
    target(@hashi, b"validator", b"register");
    target(@hashi, b"validator", b"update_next_epoch_public_key");
    target(@hashi, b"validator", b"update_operator_address");
    target(@hashi, b"validator", b"update_endpoint_url");
    target(@hashi, b"validator", b"update_tls_public_key");
    target(@hashi, b"validator", b"update_next_epoch_encryption_public_key");
    invoker(b"invoke");

    rule(b"start_then_end_sets_sui_epoch");
    rule(b"epoch_only_changes_at_end_reconfig");
    rule(b"start_then_end_advances_epoch");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title A completed reconfiguration sets the epoch to the Sui epoch
/// @description After a successful start_reconfig followed by end_reconfig in the same
///   transaction, the Hashi epoch equals the Sui epoch.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun start_then_end_sets_sui_epoch(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);
    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(hashi.committee_set().epoch() == ctx.epoch());
}

/// @title Only end_reconfig changes the epoch
/// @description For each of start_reconfig, submit_committee_handoff, abort_reconfig
///   and the six validator entry points, a successful call leaves the committee set's
///   epoch unchanged.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun epoch_only_changes_at_end_reconfig(hashi: &mut Hashi, target: Function) {
    let before = hashi.committee_set().epoch();

    invoke(target, hashi);

    cvlm_assert(hashi.committee_set().epoch() == before);
}

/// @title A completed reconfiguration moves the epoch forward
/// @description After a successful start_reconfig followed by end_reconfig in the same
///   transaction, the Hashi epoch is strictly greater than before.
/// @link_property RECONFIG-INTEGRITY
/// @assumption The Sui epoch is greater than the Hashi epoch before the calls
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun start_then_end_advances_epoch(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let before = hashi.committee_set().epoch();
    cvlm_assume_msg(ctx.epoch() > before, b"Sui's epoch has moved past the current Hashi epoch");

    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);
    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(hashi.committee_set().epoch() > before);
}
