// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_COMMITTEE_UPDATE;
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
        /// The Hashi shared-object id the transition cert was verified
        /// against, for audit self-description.
        hashi_object_id: sui_sdk_types::Address,
    },
    /// `from_epoch` is the guardian's current epoch at the time;
    /// `new_committee` is what was proposed (and rejected).
    Failure {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
        error: String,
        /// The Hashi shared-object id the transition cert was checked
        /// against, for audit self-description.
        hashi_object_id: sui_sdk_types::Address,
    },
}

impl CommitteeUpdateLogMessage {
    /// The slash-terminated prefix containing committee-update records.
    pub fn object_key_dir() -> String {
        format!("{S3_DIR_COMMITTEE_UPDATE}/")
    }

    fn failure_object_key_prefix() -> String {
        format!("{}failure-", Self::object_key_dir())
    }

    /// Return whether `object_key` belongs to a failed committee update.
    pub fn is_failure_object_key(object_key: &str) -> bool {
        object_key.starts_with(&Self::failure_object_key_prefix())
    }

    /// Success keys lead with the new epoch (zero-padded) so a lex listing
    /// is epoch-sorted; failures lead with `failure-` so they sort after
    /// all successes, leaving the lex-last success key as the latest
    /// successfully-applied epoch.
    pub fn object_key_pattern(&self, session_id: &str) -> ObjectKeyPattern {
        match self {
            Self::Success { new_committee, .. } => ObjectKeyPattern::Fixed(format!(
                "{}{:020}-{session_id}.json",
                Self::object_key_dir(),
                new_committee.epoch,
            )),
            Self::Failure { new_committee, .. } => ObjectKeyPattern::RandomSuffix(format!(
                "{}{:020}-{session_id}-",
                Self::failure_object_key_prefix(),
                new_committee.epoch,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_failure_object_keys() {
        assert!(CommitteeUpdateLogMessage::is_failure_object_key(
            "committee-update/failure-00000000000000000009-session-abcd1234.json"
        ));
        assert!(!CommitteeUpdateLogMessage::is_failure_object_key(
            "committee-update/00000000000000000009-session.json"
        ));
        assert!(!CommitteeUpdateLogMessage::is_failure_object_key(
            "ceremony/failure-example.json"
        ));
    }
}
