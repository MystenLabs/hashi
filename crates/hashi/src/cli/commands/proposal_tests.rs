// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::cli::client::locate_proposal;
use crate::onchain::types::ProposalType;
use sui_rpc::proto::sui::rpc::v2::CleverError;
use sui_rpc::proto::sui::rpc::v2::ExecutionError;
use sui_rpc::proto::sui::rpc::v2::MoveAbort;
use sui_rpc::proto::sui::rpc::v2::MoveLocation;
use sui_rpc::proto::sui::rpc::v2::clever_error::Value;
use sui_rpc::proto::sui::rpc::v2::execution_error::ErrorDetails;
use sui_rpc::proto::sui::rpc::v2::execution_error::ExecutionErrorKind;

const RPC: &str = "http://fullnode.invalid:443";

fn proposal(id: u8, created_ms: u64) -> Proposal {
    Proposal {
        id: Address::new([id; 32]),
        timestamp_ms: created_ms,
        proposal_type: ProposalType::UpdateConfig,
    }
}

fn hex(id: u8) -> String {
    Address::new([id; 32]).to_hex()
}

// ===== locating a proposal in the two bags =====

#[test]
fn an_open_proposal_is_found_in_the_active_bag() {
    let active = [proposal(1, 0)];
    let executed = [proposal(2, 0)];
    assert!(matches!(
        locate_proposal(&active, &executed, &Address::new([1; 32])),
        ProposalLocation::Active(p) if p.id == Address::new([1; 32])
    ));
}

#[test]
fn an_executed_proposal_is_found_in_the_executed_bag() {
    let active = [proposal(1, 0)];
    let executed = [proposal(2, 0)];
    assert!(matches!(
        locate_proposal(&active, &executed, &Address::new([2; 32])),
        ProposalLocation::Executed(p) if p.id == Address::new([2; 32])
    ));
}

#[test]
fn an_unknown_id_is_missing() {
    let active = [proposal(1, 0)];
    let executed = [proposal(2, 0)];
    assert!(matches!(
        locate_proposal(&active, &executed, &Address::new([3; 32])),
        ProposalLocation::Missing
    ));
}

// ===== refusing actions on proposals that are not open =====

#[test]
fn an_open_proposal_passes_through() {
    let got = open_proposal(
        ProposalLocation::Active(proposal(1, 0)),
        &hex(1),
        ProposalAction::Vote,
        RPC,
    )
    .unwrap();
    assert_eq!(got.id, Address::new([1; 32]));
}

#[test]
fn voting_on_an_executed_proposal_is_refused_by_name_and_type() {
    let err = open_proposal(
        ProposalLocation::Executed(proposal(2, 0)),
        &hex(2),
        ProposalAction::Vote,
        RPC,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains(&hex(2)), "{err}");
    assert!(err.contains("UpdateConfig"), "{err}");
    assert!(err.contains("has already been executed"), "{err}");
    assert!(err.contains("voting is closed"), "{err}");
    assert!(err.contains("hashi proposal view"), "{err}");
}

#[test]
fn removing_a_vote_from_an_executed_proposal_is_refused() {
    let err = open_proposal(
        ProposalLocation::Executed(proposal(2, 0)),
        &hex(2),
        ProposalAction::RemoveVote,
        RPC,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("has already been executed"), "{err}");
    assert!(err.contains("cannot be removed"), "{err}");
}

#[test]
fn executing_an_executed_proposal_is_refused() {
    let err = open_proposal(
        ProposalLocation::Executed(proposal(2, 0)),
        &hex(2),
        ProposalAction::Execute,
        RPC,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("has already been executed"), "{err}");
    assert!(err.contains("nothing to execute"), "{err}");
}

#[test]
fn a_missing_proposal_names_the_rpc_and_the_expiry_path() {
    let err = open_proposal(
        ProposalLocation::Missing,
        &hex(3),
        ProposalAction::Vote,
        RPC,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains(&hex(3)), "{err}");
    assert!(err.contains(RPC), "{err}");
    assert!(err.contains("expired"), "{err}");
    assert!(err.contains("hashi proposal list"), "{err}");
}

// ===== the status line =====

#[test]
fn status_reads_active_with_its_expiry_before_seven_days() {
    let created = 1_700_000_000_000;
    let status = proposal_status(&ProposalLocation::Active(proposal(1, created)), created + 1);
    assert!(status.starts_with("Active (expires "), "{status}");
}

#[test]
fn status_reads_expired_after_seven_days() {
    let created = 1_700_000_000_000;
    let week = 1000 * 60 * 60 * 24 * 7;
    let status = proposal_status(
        &ProposalLocation::Active(proposal(1, created)),
        created + week + 1,
    );
    assert!(status.starts_with("Expired on "), "{status}");
}

#[test]
fn status_reads_executed_for_the_executed_bag() {
    assert_eq!(
        proposal_status(&ProposalLocation::Executed(proposal(2, 0)), u64::MAX),
        "Executed"
    );
}

// ===== decoding Move aborts =====

fn move_abort(module: &str, code: u64, clever: Option<(&str, &str)>) -> ExecutionError {
    // The SDK protos are non-exhaustive, so they are built by mutation.
    let mut location = MoveLocation::default();
    location.module = Some(module.to_owned());
    location.function_name = Some("borrow_child_object_mut".to_owned());
    let mut abort = MoveAbort::default();
    abort.abort_code = Some(code);
    abort.location = Some(location);
    abort.clever_error = clever.map(|(name, rendered)| {
        let mut clever = CleverError::default();
        clever.constant_name = Some(name.to_owned());
        clever.value = Some(Value::Rendered(rendered.to_owned()));
        clever
    });
    let mut error = ExecutionError::default();
    error.kind = Some(ExecutionErrorKind::MoveAbort as i32);
    error.error_details = Some(ErrorDetails::Abort(abort));
    error
}

#[test]
fn a_bag_miss_is_explained_as_the_proposal_leaving_the_active_bag() {
    let text = explain_execution_error(&move_abort("dynamic_field", 1, None)).unwrap();
    assert!(
        text.contains("no longer in the active proposal bag"),
        "{text}"
    );
    assert!(text.contains("executed"), "{text}");
}

#[test]
fn a_clever_constant_is_named_rendered_and_hinted() {
    let text = explain_execution_error(&move_abort(
        "proposal",
        1,
        Some(("EVoteAlreadyCounted", "Vote already counted")),
    ))
    .unwrap();
    assert!(
        text.starts_with("EVoteAlreadyCounted: Vote already counted"),
        "{text}"
    );
    assert!(text.contains("already voted"), "{text}");
}

#[test]
fn an_unknown_clever_constant_is_still_named() {
    let text =
        explain_execution_error(&move_abort("btc_config", 9, Some(("ESomethingNew", "New"))))
            .unwrap();
    assert_eq!(text, "ESomethingNew: New");
}

#[test]
fn a_hashi_abort_with_code_one_is_not_mistaken_for_the_bag_miss() {
    // Same numeric code as the framework abort, different module, no clever
    // payload: nothing certain can be said, so nothing is claimed.
    assert_eq!(
        explain_execution_error(&move_abort("proposal", 1, None)),
        None
    );
}

#[test]
fn a_non_abort_failure_is_left_alone() {
    let mut error = ExecutionError::default();
    error.kind = Some(ExecutionErrorKind::InsufficientGas as i32);
    assert_eq!(explain_execution_error(&error), None);
}

// ===== exclusive-upgrade acknowledgement (moved from the module) =====

#[test]
fn exclusive_digest_is_refused_without_acknowledgement() {
    let err = check_exclusive_digest_acknowledged(Some("ab"), true, false).unwrap_err();
    // Pin both remedies the message offers: the verified path and the
    // explicit acknowledgement.
    assert!(err.to_string().contains("--package-path"));
    assert!(err.to_string().contains("--allow-unverified-exclusive"));
}

#[test]
fn exclusive_digest_is_allowed_with_acknowledgement() {
    check_exclusive_digest_acknowledged(Some("ab"), true, true).unwrap();
}

#[test]
fn other_flag_combinations_are_unaffected() {
    // A non-exclusive upgrade digest stays recoverable on-chain.
    check_exclusive_digest_acknowledged(Some("ab"), false, false).unwrap();
    // --package-path runs the pre-flight, so nothing needs acknowledging.
    check_exclusive_digest_acknowledged(None, true, false).unwrap();
}
