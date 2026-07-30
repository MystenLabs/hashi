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
    /// The slash-terminated prefix containing the genesis record.
    pub fn object_key_dir() -> String {
        format!("{S3_DIR_GENESIS}/")
    }

    pub fn object_key() -> String {
        format!("{}record.json", Self::object_key_dir())
    }

    pub fn object_key_pattern(&self) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(Self::object_key())
    }
}
