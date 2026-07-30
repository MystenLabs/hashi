// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian- and KP-signed envelopes with intent-based domain separation.
//!
//! [`GuardianSigned`] uses Ed25519 signatures produced by the Guardian, while
//! [`KpSigned`] uses detached OpenPGP signatures produced by key provisioners.
//! Both serialize a payload together with its signing intent so a signature for
//! one payload type cannot be replayed as another.

use super::CryptoVerificationError;
use super::CryptoVerificationResult;
use super::GuardianError::InternalError;
use super::GuardianInfo;
use super::GuardianResult;
use super::LogEntry;
use super::ProvisionerRotateCertRequest;
use super::ProvisionerRotateCertResponse;
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
pub enum GuardianSigningIntentType {
    /// Intent for LogEntry.
    LogMessage = 0,
    /// Intent for SetupNewKeyResponse.
    SetupNewKeyResponse = 1,
    /// Intent for StandardWithdrawalResponse.
    StandardWithdrawalResponse = 2,
    /// Intent for GuardianInfo.
    GuardianInfo = 3,
    /// Intent for RotateKpsResponse.
    RotateKpsResponse = 4,
    /// Intent for ProvisionerRotateCertResponse.
    ProvisionerRotateCertResponse = 5,
}

/// Guardian-signed payloads and their intent-based domain separation.
pub trait GuardianSigningIntent: Serialize {
    const INTENT: GuardianSigningIntentType;
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
    /// Intent for SingleProvisionerInitRequest.
    SingleProvisionerInitRequest = 0,
    /// Intent for ProvisionerRotateCertRequest.
    ProvisionerRotateCertRequest = 1,
}

/// KP-signed payloads and their intent-based domain separation.
pub trait KpSigningIntent: Serialize {
    const INTENT: KpSigningIntentType;
}

/// KP-signed wrapper - adds signer cert and detached OpenPGP signature to any
/// KP-submitted request payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KpSigned<T> {
    pub data: T,
    pub signer_cert: PgpPublicCert,
    pub signature: String,
}

/// A timestamped response produced by the Guardian.
///
/// The timestamp is response metadata rather than a property of every
/// Guardian-signed payload. Wrapping this value in [`GuardianSigned`] keeps the
/// timestamp authenticated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianResponse<T> {
    pub response: T,
    /// Milliseconds since Unix epoch.
    pub timestamp_ms: UnixMillis,
}

/// A signed, timestamped response produced by the Guardian.
pub type GuardianSignedResponse<T> = GuardianSigned<GuardianResponse<T>>;

/// Guardian-signed wrapper - adds a signature to any signable payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GuardianSigned<T> {
    pub data: T,
    pub signature: GuardianSignature,
}

impl GuardianSigningIntent for LogEntry {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::LogMessage;
}

impl GuardianSigningIntent for SetupNewKeyResponse {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::SetupNewKeyResponse;
}

impl GuardianSigningIntent for StandardWithdrawalResponse {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::StandardWithdrawalResponse;
}

impl GuardianSigningIntent for GuardianInfo {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::GuardianInfo;
}

impl GuardianSigningIntent for RotateKpsResponse {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::RotateKpsResponse;
}

impl GuardianSigningIntent for ProvisionerRotateCertResponse {
    const INTENT: GuardianSigningIntentType =
        GuardianSigningIntentType::ProvisionerRotateCertResponse;
}

impl KpSigningIntent for SingleProvisionerInitRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::SingleProvisionerInitRequest;
}

impl KpSigningIntent for ProvisionerRotateCertRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerRotateCertRequest;
}

impl<T> GuardianResponse<T> {
    pub fn new(response: T, timestamp_ms: UnixMillis) -> Self {
        Self {
            response,
            timestamp_ms,
        }
    }

    pub fn into_response(self) -> T {
        self.response
    }
}

impl<T: GuardianSigningIntent> GuardianSigningIntent for GuardianResponse<T> {
    const INTENT: GuardianSigningIntentType = T::INTENT;
}

impl<T> GuardianSigned<T> {
    fn signed_bytes(data: &T) -> Vec<u8>
    where
        T: GuardianSigningIntent,
    {
        bcs::to_bytes(&(T::INTENT, data)).expect("serialization should not fail")
    }

    /// Sign a payload with intent-based domain separation.
    pub fn sign(data: T, signing_key: &SigningKey) -> Self
    where
        T: GuardianSigningIntent,
    {
        let signature = signing_key.sign(&Self::signed_bytes(&data));
        Self { data, signature }
    }

    /// Verify the Guardian signature without consuming the signed payload.
    pub fn verify_signature(&self, pub_key: &VerificationKey) -> CryptoVerificationResult<()>
    where
        T: GuardianSigningIntent,
    {
        pub_key
            .verify(&self.signature, &Self::signed_bytes(&self.data))
            .map_err(|_| CryptoVerificationError::new("signature invalid"))
    }

    /// Move out the payload WITHOUT verifying the signature. The node uses this
    /// on guardian responses it has already authenticated over TLS; the ed25519
    /// signing key is verified only by KPs/monitors on the S3 audit logs.
    pub fn into_data_unchecked(self) -> T {
        self.data
    }
}

impl<T: KpSigningIntent> KpSigned<T> {
    /// Sign a KP payload by invoking `gpg --detach-sign` for the
    /// signer certificate's fingerprint. Includes the KP intent in the signed
    /// bytes; payload types carry any request-specific replay-binding fields.
    pub fn sign(
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

    /// Verify the signature without consuming the signed request.
    /// Checks the intent byte to ensure the signature is for this request type.
    pub fn verify_signature(&self) -> CryptoVerificationResult<()> {
        let msg_bytes = Self::signed_bytes(&self.data);
        verify_detached_signature(&msg_bytes, &self.signature, &self.signer_cert).map_err(|e| {
            CryptoVerificationError::new(format!("KP signature verification failed: {e}"))
        })?;
        Ok(())
    }

    pub fn signer_fingerprint(&self) -> Fingerprint {
        self.signer_cert.fingerprint()
    }
}
