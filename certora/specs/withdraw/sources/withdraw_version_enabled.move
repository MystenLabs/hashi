/// @module Gate Checks
/// @contract hashi::withdraw
/// @contract hashi::versioning
module withdraw::withdraw_version_enabled;

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
    target(@hashi, b"withdraw", b"cleanup_spent_utxos");
    target(@hashi, b"withdraw", b"request_withdrawal");
    target(@hashi, b"withdraw", b"cancel_withdrawal");
    target(@hashi, b"withdraw", b"archive_confirmed_withdrawals");
    target(@hashi, b"withdraw", b"archive_withdrawal_requests");
    target(@hashi, b"withdraw", b"finish_archive_withdrawal_txns");

    invoker(b"invoke");
    rule(b"withdraw_is_version_enabled");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Withdraw entry points require an enabled package version
/// @description After a successful call to any of the twelve withdraw entry points, from
///   request_withdrawal through cleanup_spent_utxos and the three archival entry points,
///   the current package version is enabled.
/// @link_property WITHDRAW-GATE-CHECKS
/// @status VERIFIED
/// @report withdraw_gate_checks.conf https://prover.certora.com/output/497546/b8f25ee69ba448d8b88059db384da5f3?anonymousKey=b01683c3b3d982881a46fb368f8cfaad325631ac
public fun withdraw_is_version_enabled(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(hashi.versioning().is_version_enabled(hashi::versioning::package_version()));
}
