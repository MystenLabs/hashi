// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3_DIR_COMMITTEE_UPDATE;
use crate::committee::CommitteeSignature;
use serde::Deserialize;
use serde::Serialize;

/// A successfully applied committee transition.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitteeUpdateLogMessage {
    /// The guardian's current epoch at the time. Hashi reconfig is sparse, so
    /// `new_committee.epoch` is not necessarily `from_epoch + 1`.
    pub from_epoch: u64,
    pub new_committee: crate::move_types::Committee,
    pub request_sign: CommitteeSignature,
}

impl CommitteeUpdateLogMessage {
    /// The slash-terminated prefix containing committee-update records.
    pub fn object_key_dir() -> String {
        format!("{S3_DIR_COMMITTEE_UPDATE}/")
    }

    /// Keys lead with the zero-padded new epoch, so the lexicographically last
    /// key identifies the latest applied committee.
    pub fn object_key(&self) -> String {
        format!(
            "{}{:020}.json",
            Self::object_key_dir(),
            self.new_committee.epoch,
        )
    }
}
