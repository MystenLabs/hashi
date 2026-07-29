// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The versioned `LogMessage` family the enclave emits and conversion into the
//! current message shape. The `LogRecord` wrapper that carries these to S3 lives
//! in `super::record`.

use super::LogType;
use super::ObjectKeyPattern;
use super::messages::CeremonyLogMessage;
use super::messages::CommitteeUpdateLogMessage;
use super::messages::GenesisLogMessage;
use super::messages::HeartbeatLogMessage;
use super::messages::InitLogMessage;
use super::messages::KpShareStateLogMessageV1;
use super::messages::KpShareStateLogMessageV2;
use super::messages::WithdrawalLogMessage;
use crate::guardian::GuardianError;
use crate::guardian::UnixMillis;
use serde::Deserialize;
use serde::Serialize;

/// The wire message stored in a [`super::LogRecord`]. Its version is serialized
/// as the record's sibling `schema_version` field rather than as an additional
/// JSON enum layer.
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

/// Schema-version-1 log messages. Its legacy KP-share payload is retained so
/// readers can verify signatures over records emitted before KP shares
/// supported multiple certificates.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV1 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessageV1>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// Current log schema emitted by the guardian enclave.
/// Uses an enum discriminator for automatic domain separation between variants.
// TODO(testnet-wipe): Collapse the V1/V2 compatibility layer into a single log
// schema once existing testnet records no longer need to be read.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessageV2 {
    Heartbeat(HeartbeatLogMessage),
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    KpShareState(Box<KpShareStateLogMessageV2>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
    Genesis(Box<GenesisLogMessage>),
}

/// The current normalized log-message shape exposed to writers and verified
/// readers. Wire-version handling remains internal to [`VersionedLogMessage`].
pub type LogMessage = LogMessageV2;

trait LogMessageSchema {
    fn is_allowed_unsigned(&self) -> bool;

    fn log_type(&self) -> LogType;

    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern;
}

macro_rules! impl_log_message_schema {
    ($schema:ty) => {
        impl LogMessageSchema for $schema {
            fn is_allowed_unsigned(&self) -> bool {
                matches!(
                    self,
                    Self::Init(init_message)
                        if matches!(
                            **init_message,
                            InitLogMessage::OIAttestationUnsigned { .. }
                        )
                )
            }

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

impl LogMessageV1 {
    fn into_current(self) -> Result<LogMessage, GuardianError> {
        Ok(match self {
            LogMessageV1::Heartbeat(message) => LogMessage::Heartbeat(message),
            LogMessageV1::Init(message) => LogMessage::Init(message),
            LogMessageV1::Withdrawal(message) => LogMessage::Withdrawal(message),
            LogMessageV1::Ceremony(message) => LogMessage::Ceremony(message),
            LogMessageV1::KpShareState(message) => {
                LogMessage::KpShareState(Box::new((*message).into_current()?))
            }
            LogMessageV1::CommitteeUpdate(message) => LogMessage::CommitteeUpdate(message),
            LogMessageV1::Genesis(message) => LogMessage::Genesis(message),
        })
    }
}

impl LogMessageV2 {
    pub fn into_init_log(self) -> Option<InitLogMessage> {
        match self {
            Self::Init(init_message) => Some(*init_message),
            _ => None,
        }
    }
}

impl VersionedLogMessage {
    pub const SCHEMA_VERSION_V1: u64 = 1;
    pub const SCHEMA_VERSION_V2: u64 = 2;

    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => Self::SCHEMA_VERSION_V1,
            Self::V2(_) => Self::SCHEMA_VERSION_V2,
        }
    }

    pub fn is_allowed_unsigned(&self) -> bool {
        match self {
            Self::V1(message) => message.is_allowed_unsigned(),
            Self::V2(message) => message.is_allowed_unsigned(),
        }
    }

    pub fn must_be_signed(&self) -> bool {
        !self.is_allowed_unsigned()
    }

    pub(super) fn log_type(&self) -> LogType {
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

    pub fn into_current(self) -> Result<LogMessage, GuardianError> {
        match self {
            Self::V1(message) => message.into_current(),
            Self::V2(message) => Ok(message),
        }
    }
}
