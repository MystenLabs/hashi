// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The versioned `LogMessage` family the enclave emits. The `LogRecord` wrapper
//! that carries these to S3 lives in `super::log_record`.

use super::config::S3ObjectLockPolicy;
use super::log_layout::ObjectKeyPattern;
use super::log_messages::CeremonyLogMessage;
use super::log_messages::CeremonyProposalLogMessage;
use super::log_messages::CommitteeUpdateLogMessage;
use super::log_messages::GenesisLogMessageV1;
use super::log_messages::HeartbeatLogMessage;
use super::log_messages::InitLogMessage;
use super::log_messages::KpShareStateLogMessage;
use super::log_messages::WithdrawalLogMessage;
use crate::guardian::UnixMillis;
use serde::Deserialize;
use serde::Serialize;
use std::time::Duration;

/// The wire message stored in a [`crate::guardian::log::LogRecord`]. Its version is serialized
/// as the record's sibling `schema_version` field rather than as an additional
/// JSON enum layer.
///
/// Readers match these variants exhaustively at their consumption boundary so
/// adding a schema version requires each reader to opt in explicitly.
#[derive(Debug)]
pub enum VersionedLogMessage {
    V1(LogMessageV1),
}

impl From<LogMessageV1> for VersionedLogMessage {
    fn from(message: LogMessageV1) -> Self {
        Self::V1(message)
    }
}

impl Serialize for VersionedLogMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::V1(message) => message.serialize(serializer),
        }
    }
}

/// Schema-version-1 log messages emitted by the guardian enclave.
/// Uses an enum discriminator for automatic domain separation between variants.
///
/// When variants, payload fields, or serialization change, update the dummy
/// corpus and its coverage in `log_record::tests`; see `fixtures/README.md`.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV1 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessage>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessageV1>),
    CeremonyProposal(Box<CeremonyProposalLogMessage>),
}

/// Writer-facing alias for the log-message schema emitted by guardians.
pub type LogMessage = LogMessageV1;

/// Schema-independent category of a Guardian log payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogType {
    Heartbeat,
    Init,
    Withdrawal,
    CeremonyCompleted,
    CeremonyProposal,
    KpShareState,
    CommitteeUpdate,
    Genesis,
}

impl LogType {
    pub(super) const fn object_lock_duration(self, policy: S3ObjectLockPolicy) -> Duration {
        match self {
            Self::Heartbeat | Self::CeremonyProposal | Self::KpShareState => policy.short_lived,
            Self::Init
            | Self::Withdrawal
            | Self::CeremonyCompleted
            | Self::CommitteeUpdate
            | Self::Genesis => policy.long_lived,
        }
    }
}

trait LogMessageSchema {
    fn log_type(&self) -> LogType;

    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern;
}

macro_rules! impl_log_message_schema {
    ($schema:ty $(, $proposal_variant:ident)?) => {
        impl LogMessageSchema for $schema {
            fn log_type(&self) -> LogType {
                match self {
                    Self::Heartbeat(..) => LogType::Heartbeat,
                    Self::Init(..) => LogType::Init,
                    Self::Withdrawal(..) => LogType::Withdrawal,
                    Self::Ceremony(..) => LogType::CeremonyCompleted,
                    Self::KpShareState(..) => LogType::KpShareState,
                    Self::CommitteeUpdate(..) => LogType::CommitteeUpdate,
                    Self::Genesis(..) => LogType::Genesis,
                    $(Self::$proposal_variant(..) => LogType::CeremonyProposal,)?
                }
            }

            fn object_key_pattern(
                &self,
                session_id: &str,
                timestamp_ms: UnixMillis,
            ) -> ObjectKeyPattern {
                match self {
                    Self::Heartbeat(message) => {
                        message.object_key_pattern(session_id, timestamp_ms)
                    }
                    Self::Init(message) => message.object_key_pattern(session_id),
                    Self::Withdrawal(message) => {
                        message.object_key_pattern(session_id, timestamp_ms)
                    }
                    Self::Ceremony(message) => message.object_key_pattern(session_id),
                    Self::KpShareState(message) => message.object_key_pattern(session_id),
                    Self::CommitteeUpdate(message) => message.object_key_pattern(session_id),
                    Self::Genesis(message) => message.object_key_pattern(),
                    $(Self::$proposal_variant(message) => message.object_key_pattern(session_id),)?
                }
            }
        }
    };
}

impl_log_message_schema!(LogMessageV1, CeremonyProposal);

impl VersionedLogMessage {
    pub const SCHEMA_VERSION_V1: u64 = 1;

    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => Self::SCHEMA_VERSION_V1,
        }
    }

    pub fn as_attestation_log(&self) -> Option<&InitLogMessage> {
        let init = match self {
            Self::V1(LogMessageV1::Init(init)) => init.as_ref(),
            _ => return None,
        };
        matches!(init, InitLogMessage::OIAttestationUnsigned { .. }).then_some(init)
    }

    pub fn is_unsigned(&self) -> bool {
        self.as_attestation_log().is_some()
    }

    pub fn log_type(&self) -> LogType {
        match self {
            Self::V1(message) => message.log_type(),
        }
    }

    pub(super) fn object_key_pattern(
        &self,
        session_id: &str,
        timestamp_ms: UnixMillis,
    ) -> ObjectKeyPattern {
        match self {
            Self::V1(message) => message.object_key_pattern(session_id, timestamp_ms),
        }
    }
}
