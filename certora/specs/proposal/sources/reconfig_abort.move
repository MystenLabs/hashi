/// @module Reconfiguration Integrity Properties
/// @contract hashi::reconfig
/// @contract hashi::committee_set
/// @impact A reconfiguration could complete without the outgoing committee's handoff,
///   set the Hashi epoch out of step with Sui, delete the current committee on abort, or
///   be aborted while it can still complete, leaving Hashi without a committee that can
///   sign.
///
/// @global_assumption Committee certificate verification (hashi::verify and
///   hashi::verify_with_committee) is summarized to always succeed, so end_reconfig and
///   submit_committee_handoff accept any certificate
/// @global_assumption Building the next committee from Sui's validator set
///   (new_committee_from_voting_powers) is summarized to return an arbitrary committee
///   whose epoch is the requested epoch. Its members and weights are unconstrained, and
///   it may be empty
/// @global_assumption A proposal's valid voting power is summarized as one opaque value,
///   not tied to its votes or the committee's weights, so whether quorum is reached is
///   unconstrained
/// @global_assumption Validator BLS key checks are summarized: the proof-of-possession
///   check in update_next_epoch_public_key and the G1 point conversion in register
///   return an arbitrary key and never abort
///
/// @property RECONFIG-INTEGRITY Committee reconfiguration keeps its bookkeeping
///   consistent: the Hashi epoch changes only when a reconfiguration completes, and then
///   to the Sui epoch it started in; the handoff certificate is written at most once and
///   is required after genesis; a reconfiguration can complete only within the Sui epoch
///   it started in and be aborted only after that epoch has passed; and aborting a
///   reconfiguration restores the committee set without removing the current committee
module proposal::reconfig_abort;

use cvlm::asserts::cvlm_assert;
use cvlm::manifest::rule;
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use sui_system::sui_system::SuiSystemState;

public fun cvlm_manifest() {
    rule(b"abort_preserves_current_epoch_and_committee");
    rule(b"start_never_targets_current_committee");
    rule(b"abort_reconfig_requires_matching_epoch");
    rule(b"abort_never_in_start_epoch");
    rule(b"end_reconfig_requires_current_sui_epoch");
}

/// @title abort_reconfig restores the committee set
/// @description After a successful abort_reconfig, the committee set is not
///   reconfiguring and has no handoff certificate, the pending epoch's committee is
///   removed, the Hashi epoch and MPC public key are unchanged, and the current epoch's
///   committee is still stored exactly when it was stored before and is not the
///   pending epoch's. This is the state start_reconfig left behind in the Sui epoch it
///   started in (start_enters_reconfiguring).
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun abort_preserves_current_epoch_and_committee(
    hashi: &mut Hashi,
    epoch: u64,
    ctx: &TxContext,
) {
    let cs = hashi.committee_set();
    let pending = cs.pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };
    let epoch_before = cs.epoch();
    let had_current = cs.has_committee(epoch_before);
    let mpc_key_before = *cs.mpc_public_key();

    hashi::reconfig::abort_reconfig_for_testing(hashi, epoch, ctx);

    let cs = hashi.committee_set();
    cvlm_assert(!cs.is_reconfiguring());
    cvlm_assert(!cs.pending_handoff_cert_is_set());
    cvlm_assert(cs.epoch() == epoch_before);
    cvlm_assert(*cs.mpc_public_key() == mpc_key_before);
    cvlm_assert(!cs.has_committee(next));
    cvlm_assert(cs.has_committee(epoch_before) == (had_current && next != epoch_before));
}

/// @title start_reconfig never targets the current committee's slot
/// @description After a successful start_reconfig, if the pending epoch equals the
///   current Hashi epoch, then that epoch is 0 and no committee was stored for it
///   before the call.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun start_never_targets_current_committee(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    ctx: &TxContext,
) {
    let cs = hashi.committee_set();
    let epoch_before = cs.epoch();
    let had_current = cs.has_committee(epoch_before);

    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    let pending = hashi.committee_set().pending_epoch_change();
    if (*pending.borrow() == epoch_before) {
        cvlm_assert(!had_current);
        cvlm_assert(epoch_before == 0);
    };
}

/// @title abort_reconfig only aborts an overrun pending reconfiguration
/// @description A successful abort_reconfig requires a pending reconfiguration whose
///   epoch equals the epoch argument and differs from the current Sui epoch.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun abort_reconfig_requires_matching_epoch(
    hashi: &mut Hashi,
    epoch: u64,
    ctx: &TxContext,
) {
    let pending = hashi.committee_set().pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };

    hashi::reconfig::abort_reconfig_for_testing(hashi, epoch, ctx);

    cvlm_assert(pending.is_some());
    cvlm_assert(epoch == next);
    cvlm_assert(next != ctx.epoch());
}

/// @title A reconfiguration cannot be aborted in the Sui epoch it started in
/// @description No execution has a successful start_reconfig followed by a successful
///   abort_reconfig in the same Sui epoch.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun abort_never_in_start_epoch(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    epoch: u64,
    ctx: &TxContext,
) {
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);
    hashi::reconfig::abort_reconfig_for_testing(hashi, epoch, ctx);

    cvlm_assert(false);
}

/// @title end_reconfig completes only within the pending reconfiguration's Sui epoch
/// @description A successful end_reconfig requires a pending reconfiguration whose
///   epoch equals the current Sui epoch. With abort_reconfig_requires_matching_epoch,
///   this means completion and abort can never both be possible in one Sui epoch.
/// @link_property RECONFIG-INTEGRITY
/// @status VERIFIED
/// @report reconfig_integrity.conf https://prover.certora.com/output/497546/49ae0e1299c24ec1bdb90559e9b1cf06?anonymousKey=2d65ede760958c2dbd26e1df95f54516a354cfe0
public fun end_reconfig_requires_current_sui_epoch(
    hashi: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let pending = hashi.committee_set().pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };

    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(pending.is_some());
    cvlm_assert(next == ctx.epoch());
}
