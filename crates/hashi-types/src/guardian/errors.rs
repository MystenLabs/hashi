// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use super::SessionID;
use super::lifecycle::EnclaveLifecycle;
use super::time_utils::UnixSeconds;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuardianError {
    // ========================================================================
    // Errors requiring corrected input/data or investigation
    // ========================================================================
    InternalError(String),
    /// S3 API, object-lock, or version-history failures.
    S3Error(String),
    /// Persisted S3 guardian log data failed structural or authenticity validation.
    InvalidS3Log(String),
    InvalidInputs(String),
    Unauthenticated(String),

    // ========================================================================
    // Errors that may succeed after configuration, lifecycle, or transient
    // state changes
    // ========================================================================
    /// The guardian build is absent from the configured PCR allowlist.
    BuildNotAllowlisted(String),
    /// The guardian build does not match the configured current build.
    BuildNotCurrent(String),
    LifecycleMismatch {
        expected: EnclaveLifecycle,
        actual: EnclaveLifecycle,
    },
    LimiterSequenceMismatch {
        expected: u64,
        actual: u64,
    },
    /// The standby session has not produced its first visible heartbeat.
    CurrentSessionHeartbeatMissing {
        session_id: SessionID,
        retry_after_secs: UnixSeconds,
    },
    /// The standby session's latest heartbeat is too old for activation.
    CurrentSessionHeartbeatStale {
        session_id: SessionID,
        heartbeat_age_secs: UnixSeconds,
        max_age_secs: UnixSeconds,
    },
    /// A prior session remains inside the activation quiet period.
    PriorSessionHeartbeatStillRecent {
        session_id: SessionID,
        heartbeat_age_secs: UnixSeconds,
        required_quiet_secs: UnixSeconds,
    },
    RateLimitExceeded,
    /// A service condition known to be temporary and safe for callers to retry.
    Unavailable(String),
}

pub type GuardianResult<T> = Result<T, GuardianError>;

impl GuardianError {
    /// Returns how long a caller should wait before retrying, when the error
    /// describes a condition that becomes ready on a known schedule.
    pub fn retry_after_secs(&self) -> Option<UnixSeconds> {
        match self {
            Self::CurrentSessionHeartbeatMissing {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            Self::PriorSessionHeartbeatStillRecent {
                heartbeat_age_secs,
                required_quiet_secs,
                ..
            } => Some(required_quiet_secs.saturating_sub(*heartbeat_age_secs)),
            _ => None,
        }
    }
}

/// Low-level error returned by signature and attestation verifiers.
///
/// This remains source-neutral so higher-level layers can convert it to
/// [`GuardianError::Unauthenticated`] for inbound RPC evidence or
/// [`GuardianError::InvalidS3Log`] for persisted S3 evidence. Client tooling
/// may instead wrap it with its own context.
///
/// It is intended to be converted rather than exposed directly as the final
/// RPC, API, or application error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoVerificationError(String);

impl CryptoVerificationError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub type CryptoVerificationResult<T> = Result<T, CryptoVerificationError>;

impl std::fmt::Display for CryptoVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CryptoVerificationError {}

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::InternalError(e) => write!(f, "InternalError: {}", e),
            GuardianError::S3Error(e) => write!(f, "S3Error: {}", e),
            GuardianError::InvalidS3Log(e) => write!(f, "InvalidS3Log: {}", e),
            GuardianError::InvalidInputs(e) => write!(f, "InvalidInputs: {}", e),
            GuardianError::Unauthenticated(e) => write!(f, "Unauthenticated: {}", e),
            GuardianError::BuildNotAllowlisted(e) => write!(f, "BuildNotAllowlisted: {}", e),
            GuardianError::BuildNotCurrent(e) => write!(f, "BuildNotCurrent: {}", e),
            GuardianError::LifecycleMismatch { expected, actual } => write!(
                f,
                "LifecycleMismatch: expected {expected:?}, but enclave is {actual:?}"
            ),
            GuardianError::LimiterSequenceMismatch { expected, actual } => write!(
                f,
                "LimiterSequenceMismatch: expected {expected}, got {actual}"
            ),
            GuardianError::CurrentSessionHeartbeatMissing {
                session_id,
                retry_after_secs,
            } => write!(
                f,
                "CurrentSessionHeartbeatMissing: no heartbeat found for session {session_id}; \
                 retry in {retry_after_secs}s"
            ),
            GuardianError::CurrentSessionHeartbeatStale {
                session_id,
                heartbeat_age_secs,
                max_age_secs,
            } => write!(
                f,
                "CurrentSessionHeartbeatStale: session {session_id} last heartbeated \
                 {heartbeat_age_secs}s ago; expected a heartbeat within {max_age_secs}s"
            ),
            GuardianError::PriorSessionHeartbeatStillRecent {
                session_id,
                heartbeat_age_secs,
                required_quiet_secs,
            } => write!(
                f,
                "PriorSessionHeartbeatStillRecent: session {session_id} heartbeated \
                 {heartbeat_age_secs}s ago; required quiet period is {required_quiet_secs}s; retry \
                 in {}s",
                required_quiet_secs.saturating_sub(*heartbeat_age_secs)
            ),
            GuardianError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            GuardianError::Unavailable(e) => write!(f, "Unavailable: {}", e),
        }
    }
}

impl std::error::Error for GuardianError {}
