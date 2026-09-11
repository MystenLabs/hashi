// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::super::log_layout::ObjectKeyPattern;
use super::super::log_layout::S3_DIR_GENESIS;
use serde::Deserialize;
use serde::Serialize;

/// V1 first-deploy committee, retained for deployed log compatibility.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GenesisLogMessageV1 {
    pub committee: crate::move_types::Committee,
}

/// Current first-deploy committee written at `genesis/record.json` once
/// KP-authorized PI reaches threshold.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GenesisLogMessageV2 {
    pub committee: crate::move_types::Committee,
    /// The Hashi shared-object id this guardian was bootstrapped for, for
    /// audit self-description (the authoritative pin lives in `InitConfig`,
    /// covered by `config_hash`).
    pub hashi_object_id: sui_sdk_types::Address,
}

/// Writer-facing alias for the current genesis log schema.
pub type GenesisLogMessage = GenesisLogMessageV2;

impl GenesisLogMessageV1 {
    pub fn object_key_pattern(&self) -> ObjectKeyPattern {
        ObjectKeyPattern::Fixed(GenesisLogMessage::object_key())
    }
}

impl GenesisLogMessageV2 {
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
