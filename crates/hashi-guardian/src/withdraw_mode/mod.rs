// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdraw-mode flows (enabled when CEREMONY_MODE=false): standard withdrawal,
//! committee updates, provisioner init, and heartbeats. `verify_hashi_cert` is
//! the committee-certificate check shared by `standard_withdrawal` and
//! `committee_update`.

pub mod committee_update;
pub mod genesis;
pub mod heartbeat;
pub mod operator_activate;
pub mod provisioner_init;
pub mod provisioner_rotate_cert;
pub mod standard_withdrawal;

use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;

/// Verify the committee certificate on `signed_request` meets the certificate
/// threshold for `committee`. This matches the threshold at which Hashi's leader
/// stops collecting signatures; a higher configured threshold could reject an
/// otherwise-valid certificate.
pub fn verify_hashi_cert<T: hashi_types::intent::IntentMessage>(
    committee: &HashiCommittee,
    signed_request: &HashiSigned<T>,
) -> GuardianResult<()> {
    let threshold = certificate_threshold(committee.total_weight());
    committee
        .verify_signature_and_weight(signed_request, threshold)
        .map_err(|e| InvalidInputs(format!("signature verification failed {:?}", e)))
}
