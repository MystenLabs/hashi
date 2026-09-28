// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::S3HourDirectory;
use crate::guardian::UnixMillis;
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
            S3HourDirectory::heartbeat(unix_millis_to_seconds(timestamp_ms)),
            self.seq,
        )
    }
}
