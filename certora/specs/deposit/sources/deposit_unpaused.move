/// @module Gate Checks
/// @contract hashi::deposit
/// @contract hashi::config
module deposit::deposit_unpaused;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"deposit");
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");

    invoker(b"invoke");
    rule(b"deposit_is_unpaused");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title deposit, approve_deposit and confirm_deposit require Hashi to be unpaused
/// @description After a successful deposit, approve_deposit or confirm_deposit, the
///   config is not paused.
/// @link_property DEPOSIT-GATE-CHECKS
/// @status VERIFIED
/// @report deposit_gate_checks.conf https://prover.certora.com/output/497546/0eb99c4744b54fa9a09a45003eb4fe57?anonymousKey=5c32d7cd389d7bcafc1903084a70f242401513aa
public fun deposit_is_unpaused(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(!hashi.config().paused());
}
