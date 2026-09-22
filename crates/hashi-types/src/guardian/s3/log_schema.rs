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
/// Each `into_<message_kind>()` extractor returns the natural payload type for
/// that message kind, independently of the record's schema version. Its return
/// type can evolve to represent payload differences explicitly. Version dispatch
/// remains exhaustive inside the extractor, without implicit payload conversion.
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

impl LogMessageSchema for LogMessageV1 {
    fn log_type(&self) -> LogType {
        match self {
            Self::Heartbeat(..) => LogType::Heartbeat,
            Self::Init(..) => LogType::Init,
            Self::Withdrawal(..) => LogType::Withdrawal,
            Self::Ceremony(..) => LogType::CeremonyCompleted,
            Self::KpShareState(..) => LogType::KpShareState,
            Self::CommitteeUpdate(..) => LogType::CommitteeUpdate,
            Self::Genesis(..) => LogType::Genesis,
            Self::CeremonyProposal(..) => LogType::CeremonyProposal,
        }
    }

    fn object_key_pattern(&self, session_id: &str, timestamp_ms: UnixMillis) -> ObjectKeyPattern {
        match self {
            Self::Heartbeat(message) => message.object_key_pattern(session_id, timestamp_ms),
            Self::Init(message) => message.object_key_pattern(session_id),
            Self::Withdrawal(message) => message.object_key_pattern(session_id, timestamp_ms),
            Self::Ceremony(message) => message.object_key_pattern(session_id),
            Self::KpShareState(message) => message.object_key_pattern(session_id),
            Self::CommitteeUpdate(message) => message.object_key_pattern(session_id),
            Self::Genesis(message) => message.object_key_pattern(),
            Self::CeremonyProposal(message) => message.object_key_pattern(session_id),
        }
    }
}

impl VersionedLogMessage {
    pub const SCHEMA_VERSION_V1: u64 = 1;

    pub fn schema_version(&self) -> u64 {
        match self {
            Self::V1(_) => Self::SCHEMA_VERSION_V1,
        }
    }

    /// Consume a heartbeat payload, or return `None` for another message kind.
    pub fn into_heartbeat(self) -> Option<HeartbeatLogMessage> {
        match self {
            Self::V1(LogMessageV1::Heartbeat(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume an init payload, or return `None` for another message kind.
    pub fn into_init(self) -> Option<Box<InitLogMessage>> {
        match self {
            Self::V1(LogMessageV1::Init(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a withdrawal payload, or return `None` for another message kind.
    pub fn into_withdrawal(self) -> Option<Box<WithdrawalLogMessage>> {
        match self {
            Self::V1(LogMessageV1::Withdrawal(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a ceremony payload, or return `None` for another message kind.
    pub fn into_ceremony(self) -> Option<Box<CeremonyLogMessage>> {
        match self {
            Self::V1(LogMessageV1::Ceremony(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a KP share state payload, or return `None` for another message kind.
    pub fn into_kp_share_state(self) -> Option<Box<KpShareStateLogMessage>> {
        match self {
            Self::V1(LogMessageV1::KpShareState(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a committee update payload, or return `None` for another message kind.
    pub fn into_committee_update(self) -> Option<Box<CommitteeUpdateLogMessage>> {
        match self {
            Self::V1(LogMessageV1::CommitteeUpdate(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a genesis payload, or return `None` for another message kind.
    pub fn into_genesis(self) -> Option<Box<GenesisLogMessageV1>> {
        match self {
            Self::V1(LogMessageV1::Genesis(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    /// Consume a ceremony proposal payload, or return `None` for another message kind.
    pub fn into_ceremony_proposal(self) -> Option<Box<CeremonyProposalLogMessage>> {
        match self {
            Self::V1(LogMessageV1::CeremonyProposal(message)) => Some(message),
            Self::V1(_) => None,
        }
    }

    pub fn as_attestation_log(&self) -> Option<&InitLogMessage> {
        let init = match self {
            Self::V1(LogMessageV1::Init(init)) => init.as_ref(),
            Self::V1(_) => return None,
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
