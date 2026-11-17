/// @module Gate Checks
/// @contract hashi::withdraw
/// @contract hashi::committee_set
///
/// @global_assumption The loops in the withdrawal flow are summarized by opaque
///   per-call amounts: the input UTXO total (locked from the pool and used for fee
///   accounting), the change UTXO total (returned to the pool), the per-request output
///   total, the committed requests' balance total, and the request and output counts.
///   None of these is tied to the actual UTXOs or requests
/// @global_assumption The only relationship assumed between those amounts is that the
///   per-request output total plus request count times the per-user miner fee equals
///   the committed requests' balance total. Dust and destination-address checks on
///   withdrawal outputs are not modeled
/// @global_assumption Committee certificate verification (hashi::verify) is summarized
///   to always succeed, which over-approximates who can call certified entry points
///
/// @property WITHDRAW-GATE-CHECKS Each withdraw entry point succeeds only when the
///   protocol gates it depends on allow it
module withdraw::withdraw_not_reconfiguring;

use cvlm::asserts::cvlm_assert;
use cvlm::function::Function;
use cvlm::manifest::{invoker, rule, target};
use hashi::hashi::Hashi;

public fun cvlm_manifest() {
    target(@hashi, b"withdraw", b"approve_request");
    target(@hashi, b"withdraw", b"commit_withdrawal_tx");
    target(@hashi, b"withdraw", b"commit_input_signatures");
    target(@hashi, b"withdraw", b"finalize_withdrawal");
    target(@hashi, b"withdraw", b"reallocate_presigs");

    invoker(b"invoke");
    rule(b"withdraw_is_not_reconfiguring");
}

native fun invoke(target: Function, hashi: &mut Hashi);

/// @title Committee-driven withdraw steps are blocked during reconfiguration
/// @description After a successful approve_request, commit_withdrawal_tx,
///   commit_input_signatures, finalize_withdrawal or reallocate_presigs, the
///   committee set is not reconfiguring.
/// @link_property WITHDRAW-GATE-CHECKS
/// @status VERIFIED
/// @report withdraw_gate_checks.conf https://prover.certora.com/output/497546/b8f25ee69ba448d8b88059db384da5f3?anonymousKey=b01683c3b3d982881a46fb368f8cfaad325631ac
public fun withdraw_is_not_reconfiguring(hashi: &mut Hashi, target: Function) {
    invoke(target, hashi);
    cvlm_assert(!hashi.committee_set().is_reconfiguring());
}
