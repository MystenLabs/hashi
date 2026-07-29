// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::ObjectKeyPattern;
use super::super::S3_DIR_GENESIS;
use serde::Deserialize;
use serde::Serialize;

/// First-deploy committee written at `genesis/record.json` once KP-authorized PI
/// reaches threshold.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GenesisLogMessage {
    pub committee: crate::move_types::Committee,
}

impl GenesisLogMessage {
    pub fn object_key() -> String {
        format!("{S3_DIR_GENESIS}/record.json")
    }

    pub fn object_key_pattern(&self) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(Self::object_key())
    }
}
