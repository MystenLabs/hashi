// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Withdraw-mode flows (enabled when CEREMONY_MODE=false): standard withdrawal,
//! committee updates, provisioner init, and heartbeats. `verify_hashi_cert` is
//! the committee-certificate check shared by `standard_withdrawal` and
//! `committee_update`.

pub mod committee_update;
pub mod genesis;
pub mod heartbeat;
pub mod provisioner_init;
pub mod standard_withdrawal;

use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;
use std::sync::Arc;

/// Verify the committee certificate on `signed_request` meets `threshold`.
pub fn verify_hashi_cert<T: hashi_types::intent::IntentMessage>(
    committee: Arc<HashiCommittee>,
    threshold: u64,
    signed_request: &HashiSigned<T>,
) -> GuardianResult<()> {
    committee
        .verify_signature_and_weight(signed_request, threshold)
        .map_err(|e| InvalidInputs(format!("signature verification failed {:?}", e)))
}
