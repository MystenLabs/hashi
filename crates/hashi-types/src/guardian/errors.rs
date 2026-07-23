// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use super::lifecycle::EnclaveLifecycle;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuardianError {
    InternalError(String),
    /// S3 API, object-lock, or version-history failures.
    S3Error(String),
    /// Persisted guardian log data failed structural or authenticity validation.
    InvalidGuardianLog(String),
    InvalidInputs(String),
    Unauthenticated(String),
    /// The guardian build does not satisfy the configured PCR/build policy.
    GuardianBuildNotAccepted(String),
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

/// A trust or authenticity check failed.
///
/// Verification code does not know whether the untrusted value came from an
/// RPC caller, S3, or another service. The boundary that knows the source maps
/// this into the appropriate service error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    Invalid(String),
    PcrMismatch(String),
}

impl VerificationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub fn pcr_mismatch(message: impl Into<String>) -> Self {
        Self::PcrMismatch(message.into())
    }
}

pub type VerificationResult<T> = Result<T, VerificationError>;

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) | Self::PcrMismatch(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for VerificationError {}

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::InternalError(e) => write!(f, "InternalError: {}", e),
            GuardianError::Unavailable(e) => write!(f, "Unavailable: {}", e),
            GuardianError::InvalidGuardianLog(e) => write!(f, "InvalidGuardianLog: {}", e),
            GuardianError::InvalidInputs(e) => write!(f, "InvalidInputs: {}", e),
            GuardianError::Unauthenticated(e) => write!(f, "Unauthenticated: {}", e),
            GuardianError::GuardianBuildNotAccepted(e) => {
                write!(f, "GuardianBuildNotAccepted: {}", e)
            }
            GuardianError::LifecycleMismatch {
                operation,
                expected,
                actual,
            } => write!(
                f,
                "LifecycleMismatch: {operation} requires {expected:?}, but enclave is {actual:?}"
            ),
            GuardianError::S3Error(e) => write!(f, "S3Error: {}", e),
            GuardianError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
        }
    }
}

impl std::error::Error for GuardianError {}
