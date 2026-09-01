// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `proposal execute-upgrade` accepts exactly the upgrade payload (which needs
//! the execute + publish + finalize PTB); everything else belongs to
//! `proposal execute`.

use hashi::cli::commands::proposal::is_upgrade_proposal;
use hashi::onchain::types::ProposalType;

#[test]
fn the_upgrade_payload_reaches_the_upgrade_flow() {
    assert!(is_upgrade_proposal(&ProposalType::Upgrade));
}

#[test]
fn non_upgrade_payloads_are_refused() {
    for proposal_type in [
        ProposalType::UpdateConfig,
        ProposalType::EnableVersion,
        ProposalType::DisableVersion,
        ProposalType::EmergencyPause,
        ProposalType::AbortReconfig,
        ProposalType::UpdateGuardian,
        ProposalType::IgnoreMember,
        ProposalType::Unknown("something_new".to_string()),
    ] {
        assert!(
            !is_upgrade_proposal(&proposal_type),
            "{proposal_type:?} must not reach the upgrade flow"
        );
    }
}
