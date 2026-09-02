// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The versioned `LogMessage` family the enclave emits. The `LogRecord` wrapper
//! that carries these to S3 lives in `super::log_record`.

use super::config::S3ObjectLockPolicy;
use super::log_layout::ObjectKeyPattern;
use super::log_messages::CeremonyLogMessage;
use super::log_messages::CommitteeUpdateLogMessage;
use super::log_messages::GenesisLogMessage;
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
    V2(LogMessageV2),
}

impl From<LogMessageV1> for VersionedLogMessage {
    fn from(message: LogMessageV1) -> Self {
        Self::V1(message)
    }
}

impl From<LogMessageV2> for VersionedLogMessage {
    fn from(message: LogMessageV2) -> Self {
        Self::V2(message)
    }
}

impl Serialize for VersionedLogMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::V1(message) => message.serialize(serializer),
            Self::V2(message) => message.serialize(serializer),
        }
    }
}

/// Schema-version-1 log messages. KP-share state uses the same scalar-recipient
/// payload as V2 to preserve deployed signed JSON bytes.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV1 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessage>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// Schema-version-2 log messages emitted by the guardian enclave.
/// Uses an enum discriminator for automatic domain separation between variants.
// TODO(testnet-wipe): Collapse the V1/V2 compatibility layer into a single log
// schema once existing testnet records no longer need to be read.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV2 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessage>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// Writer-facing alias for the log-message schema emitted by guardians.
pub type LogMessage = LogMessageV2;

/// Schema-independent category of a Guardian log payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogType {
    Heartbeat,
    Init,
    Withdrawal,
    Ceremony,
    KpShareState,
    CommitteeUpdate,
    Genesis,
}

impl LogType {
    pub(super) const fn object_lock_duration(self, policy: S3ObjectLockPolicy) -> Duration {
        match self {
            Self::Heartbeat | Self::KpShareState => policy.short_lived,
            Self::Init
            | Self::Withdrawal
            | Self::Ceremony
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
    ($schema:ty) => {
        impl LogMessageSchema for $schema {
            fn log_type(&self) -> LogType {
                match self {
                    Self::Heartbeat(..) => LogType::Heartbeat,
                    Self::Init(..) => LogType::Init,
                    Self::Withdrawal(..) => LogType::Withdrawal,
                    Self::Ceremony(..) => LogType::Ceremony,
                    Self::KpShareState(..) => LogType::KpShareState,
                    Self::CommitteeUpdate(..) => LogType::CommitteeUpdate,
                    Self::Genesis(..) => LogType::Genesis,
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
                }
            }
        }
    };
}

impl_log_message_schema!(LogMessageV1);
impl_log_message_schema!(LogMessageV2);

impl VersionedLogMessage {
    pub const SCHEMA_VERSION_V1: u64 = 1;
    pub const SCHEMA_VERSION_V2: u64 = 2;

    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => Self::SCHEMA_VERSION_V1,
            Self::V2(_) => Self::SCHEMA_VERSION_V2,
        }
    }

    pub fn as_attestation_log(&self) -> Option<&InitLogMessage> {
        let init = match self {
            Self::V1(LogMessageV1::Init(init)) | Self::V2(LogMessageV2::Init(init)) => {
                init.as_ref()
            }
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
            Self::V2(message) => message.log_type(),
        }
    }

    pub(super) fn object_key_pattern(
        &self,
        session_id: &str,
        timestamp_ms: UnixMillis,
    ) -> ObjectKeyPattern {
        match self {
            Self::V1(message) => message.object_key_pattern(session_id, timestamp_ms),
            Self::V2(message) => message.object_key_pattern(session_id, timestamp_ms),
        }
    }
}
