/// @module Gate Checks
/// @contract hashi::deposit
/// @contract hashi::committee_set
/// @impact An entry point could run while its protocol gate should block it: while
///   Hashi is paused, during committee reconfiguration, or on a disabled package
///   version.
///
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
/// @global_assumption Pool BTC, the total amount of UTXOs with spent_by == none, is
///   tracked by the ghost total_active_amount, updated by summaries of insert_active,
///   insert_pending, lock and their batched withdraw-side callers
///
/// @property DEPOSIT-GATE-CHECKS Each deposit entry point succeeds only when the
///   protocol gates it depends on allow it
module deposit::deposit_not_reconfiguring;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");

    invoker(b"invoke");
    rule(b"deposit_is_not_reconfiguring");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title approve_deposit and confirm_deposit are blocked during reconfiguration
/// @description After a successful approve_deposit or confirm_deposit, the committee
///   set is not reconfiguring.
/// @link_property DEPOSIT-GATE-CHECKS
/// @status VERIFIED
/// @report deposit_gate_checks.conf https://prover.certora.com/output/497546/0eb99c4744b54fa9a09a45003eb4fe57?anonymousKey=5c32d7cd389d7bcafc1903084a70f242401513aa
public fun deposit_is_not_reconfiguring(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(!hashi.committee_set().is_reconfiguring());
}
