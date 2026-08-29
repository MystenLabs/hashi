// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! `proposal execute-upgrade` dispatches on the proposal's type: the two
//! upgrade payloads go through their own module's `execute` and
//! `finalize_upgrade`; everything else belongs to `proposal execute`.

use hashi::cli::commands::proposal::UpgradeProposalKind;
use hashi::cli::commands::proposal::upgrade_proposal_kind;
use hashi::onchain::types::ProposalType;

#[test]
fn upgrade_payloads_map_to_their_module() {
    assert_eq!(
        upgrade_proposal_kind(&ProposalType::Upgrade),
        Some(UpgradeProposalKind::Legacy)
    );
    assert_eq!(
        upgrade_proposal_kind(&ProposalType::UpgradeV2),
        Some(UpgradeProposalKind::V2)
    );
    assert_eq!(UpgradeProposalKind::Legacy.module(), "upgrade");
    assert_eq!(UpgradeProposalKind::V2.module(), "upgrade_v2");
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
        assert_eq!(
            upgrade_proposal_kind(&proposal_type),
            None,
            "{proposal_type:?} must not reach the upgrade flow"
        );
    }
}
