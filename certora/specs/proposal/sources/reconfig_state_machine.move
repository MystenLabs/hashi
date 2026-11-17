/// @module Reconfiguration State Machine
/// @contract hashi::reconfig
/// @contract hashi::committee_set
/// @contract hashi::validator
/// @impact A reconfiguration could start twice, change its target epoch mid-flight, or
///   complete or abort from the wrong state, leaving the bridge run by the wrong
///   committee or MPC key.
///
/// @global_assumption Building the new committee in start_reconfig is summarized as an
///   arbitrary committee stamped with the current Sui epoch; its members and weights
///   are unconstrained, and the empty-committee and zero-weight aborts are not modeled
/// @global_assumption Committee certificate verification on the reconfiguration path
///   (hashi::verify_with_committee) is summarized to always succeed, including for
///   unauthenticated, sub-quorum or wrong-epoch certificates
/// @global_assumption BLS public-key registration is summarized: the proof of
///   possession is not checked and the resulting key is arbitrary
/// @global_assumption A proposal's valid voting power is summarized as one opaque value,
///   not tied to its votes or the committee's weights, so whether quorum is reached is
///   unconstrained
///
/// @property RECONFIG-STATE-MACHINE Reconfiguration moves between idle and
///   reconfiguring only through start, handoff, end and abort, each from its required
///   state and with its required effect on the pending epoch, current epoch, MPC key and
///   stored committees, and only one reconfiguration is in flight at a time
module proposal::reconfig_state_machine;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::committee::CommitteeSignature;
use hashi::hashi::Hashi;
use sui::clock::Clock;
use sui_system::sui_system::SuiSystemState;

public fun cvlm_manifest() {
    target(@hashi, b"reconfig", b"start_reconfig");
    target(@hashi, b"reconfig", b"submit_committee_handoff");
    target(@hashi, b"reconfig", b"end_reconfig");
    target(@hashi, b"reconfig", b"abort_reconfig");
    target(@hashi, b"validator", b"register");
    target(@hashi, b"validator", b"update_next_epoch_public_key");
    target(@hashi, b"validator", b"update_operator_address");
    target(@hashi, b"validator", b"update_endpoint_url");
    target(@hashi, b"validator", b"update_tls_public_key");
    target(@hashi, b"validator", b"update_next_epoch_encryption_public_key");
    invoker(b"invoke");

    rule(b"start_enters_reconfiguring");
    rule(b"submit_records_handoff");
    rule(b"end_completes_reconfig");
    rule(b"abort_cancels_reconfig");

    rule(b"start_requires_idle");
    rule(b"submit_requires_busy");
    rule(b"end_requires_busy");
    rule(b"abort_requires_busy");
    rule(b"cannot_start_two_reconfigs");
    rule(b"pending_epoch_fixed_while_reconfiguring");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title start_reconfig enters reconfiguring
/// @description A successful start_reconfig requires an enabled version, no committee
///   stored for the Sui epoch, a current epoch of 0 or different from the Sui epoch, and
///   (at genesis) the upgrade cap in custody. Afterwards the pending epoch is the Sui
///   epoch, the handoff latch is unset, a committee for that epoch is stored, and the
///   current epoch and MPC key are unchanged.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun start_enters_reconfiguring(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    ctx: &TxContext,
) {
    let sui_epoch = ctx.epoch();
    let version_enabled = hashi.versioning().is_version_enabled(hashi::versioning::package_version());
    let had_upgrade_cap = hashi.versioning().has_upgrade_cap();
    let cs = hashi.committee_set();
    let epoch_before = cs.epoch();
    let had_committee_for_sui_epoch = cs.has_committee(sui_epoch);
    let mpc_key_before = *cs.mpc_public_key();

    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    cvlm_assert(version_enabled);
    cvlm_assert(!had_committee_for_sui_epoch);
    cvlm_assert(epoch_before == 0 || epoch_before != sui_epoch);
    cvlm_assert(!mpc_key_before.is_empty() || had_upgrade_cap);

    let cs = hashi.committee_set();
    let pending = cs.pending_epoch_change();
    cvlm_assert(pending.is_some());
    cvlm_assert(*pending.borrow() == sui_epoch);
    cvlm_assert(!cs.pending_handoff_cert_is_set());
    cvlm_assert(cs.has_committee(sui_epoch));
    cvlm_assert(cs.get_committee(sui_epoch).epoch() == sui_epoch);
    cvlm_assert(cs.epoch() == epoch_before);
    cvlm_assert(*cs.mpc_public_key() == mpc_key_before);
}

/// @title submit_committee_handoff records the handoff
/// @description A successful submit_committee_handoff requires an enabled version, a
///   non-empty MPC key (not the initial reconfig) and an unset handoff latch. Afterwards
///   the latch is set, and the pending epoch, current epoch, MPC key and pending
///   committee slot are unchanged.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun submit_records_handoff(
    hashi: &mut Hashi,
    epoch: u64,
    committee_handoff_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let version_enabled = hashi.versioning().is_version_enabled(hashi::versioning::package_version());
    let cs = hashi.committee_set();
    let pending = cs.pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };
    let had_cert = cs.pending_handoff_cert_is_set();
    let was_initial = cs.mpc_public_key().is_empty();
    let epoch_before = cs.epoch();
    let mpc_key_before = *cs.mpc_public_key();
    let had_next_committee = cs.has_committee(next);

    hashi::reconfig::submit_committee_handoff_for_testing(hashi, epoch, committee_handoff_cert, ctx);

    cvlm_assert(version_enabled);
    cvlm_assert(!was_initial);
    cvlm_assert(!had_cert);

    let cs = hashi.committee_set();
    cvlm_assert(cs.pending_handoff_cert_is_set());
    let pending = cs.pending_epoch_change();
    cvlm_assert(pending.is_some());
    cvlm_assert(*pending.borrow() == next);
    cvlm_assert(cs.epoch() == epoch_before);
    cvlm_assert(*cs.mpc_public_key() == mpc_key_before);
    cvlm_assert(cs.has_committee(next) == had_next_committee);
}

/// @title end_reconfig completes the reconfiguration
/// @description A successful end_reconfig requires an enabled version, a stored committee
///   for the pending epoch and, unless this is the initial reconfig, a set handoff latch
///   and no handoff already archived for the outgoing epoch. Afterwards the current
///   epoch is the pending epoch, the MPC key is the submitted key, the new committee is
///   still stored and, unless initial, the handoff is archived under the outgoing epoch.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun end_completes_reconfig(
    hashi: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let version_enabled = hashi.versioning().is_version_enabled(hashi::versioning::package_version());
    let cs = hashi.committee_set();
    let pending = cs.pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };
    let had_next_committee = cs.has_committee(next);
    let had_cert = cs.pending_handoff_cert_is_set();
    let was_initial = cs.mpc_public_key().is_empty();
    let from_epoch = cs.epoch();
    let had_archived_handoff = cs.has_committee_handoff(from_epoch);

    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(version_enabled);
    cvlm_assert(had_next_committee);
    cvlm_assert(was_initial || had_cert);
    cvlm_assert(was_initial || !had_archived_handoff);

    let cs = hashi.committee_set();
    cvlm_assert(cs.epoch() == next);
    cvlm_assert(*cs.mpc_public_key() == mpc_public_key);
    cvlm_assert(cs.has_committee(next));
    if (!was_initial) {
        cvlm_assert(cs.has_committee_handoff(from_epoch));
    };
}

/// @title abort_reconfig cancels the reconfiguration
/// @description A successful reconfig::abort_reconfig requires an enabled version and an
///   epoch argument equal to the pending epoch. Afterwards the current epoch and MPC key
///   are unchanged and the pending epoch's committee is removed.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun abort_cancels_reconfig(hashi: &mut Hashi, proposed_epoch: u64, ctx: &TxContext) {
    let version_enabled = hashi.versioning().is_version_enabled(hashi::versioning::package_version());
    let cs = hashi.committee_set();
    let pending = cs.pending_epoch_change();
    let next = if (pending.is_some()) { *pending.borrow() } else { 0 };
    let epoch_before = cs.epoch();
    let mpc_key_before = *cs.mpc_public_key();

    hashi::reconfig::abort_reconfig_for_testing(hashi, proposed_epoch, ctx);

    cvlm_assert(version_enabled);
    cvlm_assert(proposed_epoch == next);

    let cs = hashi.committee_set();
    cvlm_assert(cs.epoch() == epoch_before);
    cvlm_assert(!cs.has_committee(next));
    cvlm_assert(*cs.mpc_public_key() == mpc_key_before);
}

/// @title start_reconfig moves from idle to reconfiguring
/// @description A successful start_reconfig starts from idle and ends reconfiguring.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun start_requires_idle(hashi: &mut Hashi, sui_system: &SuiSystemState, ctx: &TxContext) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    cvlm_assert(!was_reconfiguring);
    cvlm_assert(hashi.committee_set().is_reconfiguring());
}

/// @title submit_committee_handoff stays reconfiguring
/// @description A successful submit_committee_handoff starts and ends reconfiguring.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun submit_requires_busy(
    hashi: &mut Hashi,
    epoch: u64,
    committee_handoff_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    hashi::reconfig::submit_committee_handoff_for_testing(hashi, epoch, committee_handoff_cert, ctx);

    cvlm_assert(was_reconfiguring);
    cvlm_assert(hashi.committee_set().is_reconfiguring());
}

/// @title end_reconfig moves from reconfiguring to idle
/// @description A successful end_reconfig starts reconfiguring and ends idle.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun end_requires_busy(
    hashi: &mut Hashi,
    mpc_public_key: vector<u8>,
    mpc_cert: CommitteeSignature,
    ctx: &TxContext,
) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    hashi::reconfig::end_reconfig_for_testing(hashi, mpc_public_key, mpc_cert, ctx);

    cvlm_assert(was_reconfiguring);
    cvlm_assert(!hashi.committee_set().is_reconfiguring());
}

/// @title abort_reconfig moves from reconfiguring to idle
/// @description A successful reconfig::abort_reconfig starts reconfiguring and ends idle.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun abort_requires_busy(hashi: &mut Hashi, epoch: u64, ctx: &TxContext) {
    let was_reconfiguring = hashi.committee_set().is_reconfiguring();

    hashi::reconfig::abort_reconfig_for_testing(hashi, epoch, ctx);

    cvlm_assert(was_reconfiguring);
    cvlm_assert(!hashi.committee_set().is_reconfiguring());
}

/// @title Two reconfigurations cannot start back to back
/// @description No execution has two successful start_reconfig calls with nothing in between.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun cannot_start_two_reconfigs(
    hashi: &mut Hashi,
    sui_system: &SuiSystemState,
    ctx: &TxContext,
) {
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);
    hashi::reconfig::start_reconfig(hashi, sui_system, ctx);

    cvlm_assert(false);
}

/// @title The pending epoch cannot change mid-reconfiguration
/// @description For every entry point that can modify the committee set (the reconfig
///   entry points, including abort_reconfig, and the six validator entry points), if a
///   reconfiguration is pending both before and after a successful call, the pending
///   epoch is unchanged.
/// @link_property RECONFIG-STATE-MACHINE
/// @status VERIFIED
/// @report reconfig_state_machine.conf https://prover.certora.com/output/497546/507f35abd0c24f5c9a84ebec08307db7?anonymousKey=6fd3db55705aa550af6afd3df67165592506e3da
public fun pending_epoch_fixed_while_reconfiguring(hashi: &mut Hashi, target: Function) {
    let pending = hashi.committee_set().pending_epoch_change();
    let was_reconfiguring = pending.is_some();
    let next = if (was_reconfiguring) { *pending.borrow() } else { 0 };

    invoke(target, hashi);

    let pending = hashi.committee_set().pending_epoch_change();
    if (was_reconfiguring && pending.is_some()) {
        cvlm_assert(*pending.borrow() == next);
    };
}
