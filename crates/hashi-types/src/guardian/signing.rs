// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian-signed envelope and its intent-based domain separation.
//!
//! `IntentType` is a registry: each signable type maps to exactly one intent
//! value, and `GuardianSigned::{new,verify}` mix that value into the signed
//! bytes so a signature over one type can never be replayed as another.

use super::GuardianError::InternalError;
use super::GuardianError::InvalidInputs;
use super::GuardianInfo;
use super::GuardianResult;
use super::LogMessage;
use super::RotateKpsResponse;
use super::SetupNewKeyResponse;
use super::SingleProvisionerInitRequest;
use super::StandardWithdrawalResponse;
use super::UnixMillis;
use crate::pgp::Fingerprint;
use crate::pgp::PgpPublicCert;
use crate::pgp::sign_detached_via_gpg;
use crate::pgp::verify_detached_signature;
use ed25519_consensus::Signature as GuardianSignature;
use ed25519_consensus::SigningKey;
use ed25519_consensus::VerificationKey;
use serde::Deserialize;
use serde::Serialize;
use std::path::Path;

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

/// All possible KP signing intent types.
///
/// These signatures are detached OpenPGP signatures produced by KPs, not
/// enclave ed25519 signatures. Each KP-submitted request type gets a stable
/// intent so a signature for one request cannot be replayed as another request
/// with the same BCS shape.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KpSigningIntentType {
    /// One KP's share submission to the provisioning relay.
    ProvisionerInitRelaySubmission = 0,
}

/// Trait for KP-submitted request payloads that need detached signatures.
pub trait KpSigningIntent {
    const INTENT: KpSigningIntentType;
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

impl KpSigningIntent for SingleProvisionerInitRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerInitRelaySubmission;
}

/// KP-signed wrapper - adds signer cert and detached OpenPGP signature to any
/// KP-submitted request payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KpSigned<T> {
    pub data: T,
    pub signer_cert: PgpPublicCert,
    pub signature: String,
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

impl<T: Serialize + KpSigningIntent> KpSigned<T> {
    /// Create a new signed KP payload by invoking `gpg --detach-sign` for the
    /// signer certificate's fingerprint. Includes the KP intent in the signed
    /// bytes; payload types carry any request-specific replay-binding fields.
    pub fn new(
        data: T,
        signer_cert: PgpPublicCert,
        gpg_home: Option<&Path>,
    ) -> GuardianResult<Self> {
        let signing_payload = Self::signed_bytes(&data);
        let signature =
            sign_detached_via_gpg(&signing_payload, &signer_cert.fingerprint(), gpg_home)
                .map_err(|e| InternalError(format!("KP signing failed: {e}")))?;
        Ok(Self {
            data,
            signer_cert,
            signature,
        })
    }

    /// The exact bytes a key provisioner detached-signs for a typed guardian
    /// request. Binds the request intent and request payload.
    pub fn signed_bytes(data: &T) -> Vec<u8> {
        let tuple = (T::INTENT, data);
        bcs::to_bytes(&tuple).expect("serialization should not fail")
    }

    /// Verify signature and extract the payload.
    /// Checks intent byte to ensure signature is for the correct request type.
    pub fn verify(self) -> GuardianResult<T> {
        let msg_bytes = Self::signed_bytes(&self.data);
        verify_detached_signature(&msg_bytes, &self.signature, &self.signer_cert)
            .map_err(|e| InvalidInputs(format!("KP signature verification failed: {e}")))?;
        Ok(self.data)
    }

    pub fn signer_fingerprint(&self) -> Fingerprint {
        self.signer_cert.fingerprint()
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
