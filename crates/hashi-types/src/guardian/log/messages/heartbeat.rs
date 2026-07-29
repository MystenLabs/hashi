// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::ObjectKeyPattern;
use super::super::S3_DIR_HEARTBEAT;
use crate::guardian::UnixMillis;
use crate::guardian::s3_utils::S3HourScopedDirectory;
use crate::guardian::unix_millis_to_seconds;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatLogMessage {
    pub seq: u64,
}

impl HeartbeatLogMessage {
    pub fn new(seq: u64) -> Self {
        Self { seq }
    }

    pub fn object_key(&self, session_id: &str, timestamp_ms: UnixMillis) -> String {
        format!(
            "{}{session_id}-{:020}.json",
            S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, unix_millis_to_seconds(timestamp_ms)),
            self.seq,
        )
    }

    pub fn object_key_pattern(
        &self,
        session_id: &str,
        timestamp_ms: UnixMillis,
    ) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(self.object_key(session_id, timestamp_ms))
    }
}
