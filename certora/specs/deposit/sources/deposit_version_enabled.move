/// @module Gate Checks
/// @contract hashi::deposit
/// @contract hashi::versioning
module deposit::deposit_version_enabled;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"deposit", b"deposit");
    target(@hashi, b"deposit", b"approve_deposit");
    target(@hashi, b"deposit", b"confirm_deposit");
    target(@hashi, b"deposit", b"delete_expired_deposit");

    invoker(b"invoke");
    rule(b"deposit_is_version_enabled");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Deposit entry points require an enabled package version
/// @description After a successful deposit, approve_deposit, confirm_deposit or
///   delete_expired_deposit, the current package version is enabled.
/// @link_property DEPOSIT-GATE-CHECKS
/// @status VERIFIED
/// @report deposit_gate_checks.conf https://prover.certora.com/output/497546/0eb99c4744b54fa9a09a45003eb4fe57?anonymousKey=5c32d7cd389d7bcafc1903084a70f242401513aa
public fun deposit_is_version_enabled(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(hashi.versioning().is_version_enabled(hashi::versioning::package_version()));
}
