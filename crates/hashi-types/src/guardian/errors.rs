// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use super::lifecycle::EnclaveLifecycle;

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
        operation: String,
        expected: EnclaveLifecycle,
        actual: EnclaveLifecycle,
    },
    RateLimitExceeded,
    /// A service condition known to be temporary and safe for callers to retry.
    Unavailable(String),
}

pub type GuardianResult<T> = Result<T, GuardianError>;

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
            GuardianError::LifecycleMismatch {
                operation,
                expected,
                actual,
            } => write!(
                f,
                "LifecycleMismatch: {operation} requires {expected:?}, but enclave is {actual:?}"
            ),
            GuardianError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            GuardianError::Unavailable(e) => write!(f, "Unavailable: {}", e),
        }
    }
}

impl std::error::Error for GuardianError {}
