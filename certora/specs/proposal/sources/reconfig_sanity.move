module proposal::reconfig_sanity;

use cvlm::manifest::{target, target_sanity};

/// Sanity coverage for the reconfiguration entry points, in the style of
/// `setup::deposit_sanity` / `setup::withdraw_sanity`.
///
/// These two targets are the package's smoke test for
/// `summaries_committee::verify_certificate_summary`: both reach
/// `committee::verify_certificate` — and its unbounded signers-bitmap loop
/// — through `hashi::verify_with_committee` (`reconfig.move:93` and
/// `:131`), which is the path the `verify_summary` used by `setup` and
/// `solvency` does NOT cover. With the summary in place neither entry
/// point contains a symbolic loop; without it, neither is tractable.
///
/// `start_reconfig` (`reconfig.move:59-79`) is deliberately EXCLUDED. It
/// does not call `verify_with_committee` at all, and it reaches a second,
/// still-unsummarized loop:
/// `committee_set::new_committee_from_voting_powers`'s
/// `while (!validator_set.is_empty())` (`committee_set.move:399-427`),
/// which walks Sui's active validator set and then calls
/// `committee::new_committee` — whose own `members.do_ref!` (`:93-97`)
/// computing `total_weight` is a third. Add it here once those are
/// summarized (loops #4 and #5 in the audit's loop inventory).
public fun cvlm_manifest() {
    target(@hashi, b"reconfig", b"end_reconfig");
    target(@hashi, b"reconfig", b"submit_committee_handoff");
    target_sanity();
}
