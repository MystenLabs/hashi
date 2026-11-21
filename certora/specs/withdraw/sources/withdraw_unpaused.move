/// @module Gate Checks
/// @contract hashi::withdraw
/// @contract hashi::config
module withdraw::withdraw_unpaused;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_withdrawal_tx");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"confirm_withdrawal");
    target(@hashi, b"withdraw", b"reallocate_presigs");
    target(@hashi, b"withdraw", b"request_withdrawal");

    invoker(b"invoke");
    rule(b"withdraw_is_unpaused");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Withdraw entry points other than cancel and cleanup require Hashi to be unpaused
/// @description After a successful call to any withdraw entry point except
///   cancel_withdrawal and cleanup_spent_utxos, the config is not paused.
/// @link_property WITHDRAW-GATE-CHECKS
/// @status VERIFIED
/// @report withdraw_gate_checks.conf https://prover.certora.com/output/497546/b8f25ee69ba448d8b88059db384da5f3?anonymousKey=b01683c3b3d982881a46fb368f8cfaad325631ac
public fun withdraw_is_unpaused(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(!hashi.config().paused());
}
