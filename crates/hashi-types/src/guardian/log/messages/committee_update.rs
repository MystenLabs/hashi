// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::ObjectKeyPattern;
use super::super::S3_DIR_COMMITTEE_UPDATE;
use crate::committee::CommitteeSignature;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize)]
pub enum CommitteeUpdateLogMessage {
    /// `from_epoch` is the guardian's current epoch at the time; the
    /// applied epoch is `new_committee.epoch`. Both are recorded because
    /// hashi reconfig is sparse — `new_committee.epoch` is not
    /// necessarily `from_epoch + 1`.
    Success {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
    },
    /// `from_epoch` is the guardian's current epoch at the time;
    /// `new_committee` is what was proposed (and rejected).
    Failure {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
        error: String,
    },
}

impl CommitteeUpdateLogMessage {
    /// Success keys lead with the new epoch (zero-padded) so a lex listing
    /// is epoch-sorted; failures lead with `failure-` so they sort after
    /// all successes, leaving the lex-last success key as the latest
    /// successfully-applied epoch.
    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        match self {
            Self::Success { new_committee, .. } => ObjectKeyPattern::Fixed(format!(
                "{S3_DIR_COMMITTEE_UPDATE}/{:020}-{session_id}.json",
                new_committee.epoch,
            )),
            Self::Failure { new_committee, .. } => ObjectKeyPattern::RandomSuffix(format!(
                "{S3_DIR_COMMITTEE_UPDATE}/failure-{:020}-{session_id}-",
                new_committee.epoch,
            )),
        }
    }
}
