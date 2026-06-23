// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian-signed envelope and its intent-based domain separation.
//!
//! `IntentType` is a registry: each signable type maps to exactly one intent
//! value, and `GuardianSigned::{new,verify}` mix that value into the signed
//! bytes so a signature over one type can never be replayed as another.

use super::GuardianError::InvalidInputs;
use super::GuardianInfo;
use super::GuardianResult;
use super::LogMessage;
use super::RotateKpsResponse;
use super::SetupNewKeyResponse;
use super::StandardWithdrawalResponse;
use super::UnixMillis;
use ed25519_consensus::Signature as GuardianSignature;
use ed25519_consensus::SigningKey;
use ed25519_consensus::VerificationKey;
use serde::Deserialize;
use serde::Serialize;

/// All possible signing intent types.
/// Using an enum ensures no two types can accidentally share the same intent value.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentType {
    /// Intent for all LogMessage's
    LogMessage = 0,
    /// Intent for SetupNewKeyResponse
    SetupNewKeyResponse = 1,
    /// Intent for StandardWithdrawalResponse
    StandardWithdrawalResponse = 2,
    /// Intent for GuardianInfo
    GuardianInfo = 3,
    /// Intent for RotateKpsResponse
    RotateKpsResponse = 4,
}

/// Trait for types that can be signed, providing domain separation via an intent.
pub trait SigningIntent {
    const INTENT: IntentType;
}

impl SigningIntent for LogMessage {
    const INTENT: IntentType = IntentType::LogMessage;
}

impl SigningIntent for SetupNewKeyResponse {
    const INTENT: IntentType = IntentType::SetupNewKeyResponse;
}

impl SigningIntent for StandardWithdrawalResponse {
    const INTENT: IntentType = IntentType::StandardWithdrawalResponse;
}

impl SigningIntent for GuardianInfo {
    const INTENT: IntentType = IntentType::GuardianInfo;
}

impl SigningIntent for RotateKpsResponse {
    const INTENT: IntentType = IntentType::RotateKpsResponse;
}

/// Guardian-signed wrapper - adds timestamp and signature to any data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianSigned<T> {
    pub data: T,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: UnixMillis,
    pub signature: GuardianSignature,
}

/// Methods for `Signed<T>` wrapper - signing and verification
impl<T: Serialize + SigningIntent> GuardianSigned<T> {
    /// Create a new signed payload (used by enclave)
    /// Includes intent byte for domain separation to prevent cross-type signature attacks
    pub fn new(data: T, signing_key: &SigningKey, timestamp_ms: UnixMillis) -> Self {
        let tuple = (T::INTENT, &data, timestamp_ms);
        let signing_payload = bcs::to_bytes(&tuple).expect("serialization should not fail");
        let signature = signing_key.sign(&signing_payload);
        Self {
            data,
            timestamp_ms,
            signature,
        }
    }

    /// Verify signature and extract payload
    /// Checks intent byte to ensure signature is for the correct type
    pub fn verify(self, pub_key: &VerificationKey) -> GuardianResult<T> {
        let tuple = (T::INTENT, &self.data, self.timestamp_ms);
        let msg_bytes = bcs::to_bytes(&tuple).expect("serialization should not fail");
        pub_key
            .verify(&self.signature, &msg_bytes)
            .map_err(|_| InvalidInputs("signature invalid".into()))?;
        Ok(self.data)
    }
}

impl<T> GuardianSigned<T> {
    /// Move out the payload WITHOUT verifying the signature. The node uses this
    /// on guardian responses it has already authenticated over TLS; the ed25519
    /// signing key is verified only by KPs/monitors on the S3 audit logs.
    pub fn into_data_unchecked(self) -> T {
        self.data
    }
}
