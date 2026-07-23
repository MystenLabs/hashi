// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde::Serialize;

use super::lifecycle::EnclaveLifecycle;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum GuardianError {
    InternalError(String),
    /// Internal errors related to S3
    S3Error(String),
    InvalidInputs(String),
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

impl std::fmt::Display for GuardianError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardianError::InternalError(e) => write!(f, "InternalError: {}", e),
            GuardianError::Unavailable(e) => write!(f, "Unavailable: {}", e),
            GuardianError::InvalidInputs(e) => write!(f, "InvalidInputs: {}", e),
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
