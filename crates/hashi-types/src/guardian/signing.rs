// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian-signed envelope and its intent-based domain separation.
//!
//! `GuardianSigningIntentType` is a registry: each signable type maps to
//! exactly one intent value, and `GuardianSigned::{sign,authenticate}` mix that
//! value into the signed bytes so a signature over one type can never be
//! replayed as another.

use super::CryptoVerificationError;
use super::CryptoVerificationResult;
use super::GuardianError::InternalError;
use super::GuardianInfo;
use super::GuardianResult;
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
    /// Intent for key-bound guardian log records.
    LogMessage = 0,
    /// Intent for SetupNewKeyResponse
    SetupNewKeyResponse = 1,
    /// Intent for StandardWithdrawalResponse
    StandardWithdrawalResponse = 2,
    /// Intent for GuardianInfo
    GuardianInfo = 3,
    /// Intent for RotateKpsResponse
    RotateKpsResponse = 4,
    /// Intent for ProvisionerRotateCertResponse
    ProvisionerRotateCertResponse = 5,
}

/// Guardian-signed payloads and their intent-based domain separation.
pub trait GuardianSigningIntent: Serialize {
    const INTENT: GuardianSigningIntentType;
}

fn guardian_signing_bytes<T: GuardianSigningIntent>(data: &T, timestamp_ms: UnixMillis) -> Vec<u8> {
    bcs::to_bytes(&(T::INTENT, data, timestamp_ms)).expect("serialization should not fail")
}

pub(crate) fn sign_guardian_payload<T: GuardianSigningIntent>(
    data: &T,
    timestamp_ms: UnixMillis,
    signing_key: &SigningKey,
) -> GuardianSignature {
    signing_key.sign(&guardian_signing_bytes(data, timestamp_ms))
}

pub(crate) fn verify_guardian_payload_signature<T: GuardianSigningIntent>(
    data: &T,
    timestamp_ms: UnixMillis,
    signature: &GuardianSignature,
    pub_key: &VerificationKey,
) -> CryptoVerificationResult<()> {
    pub_key
        .verify(signature, &guardian_signing_bytes(data, timestamp_ms))
        .map_err(|_| CryptoVerificationError::new("signature invalid"))
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
    /// One KP's request to replace one certificate wrapping its committed share.
    ProvisionerRotateCertRequest = 1,
}

/// KP-signed payloads and their intent-based domain separation.
pub trait KpSigningIntent: Serialize {
    const INTENT: KpSigningIntentType;
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
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerInitRelaySubmission;
}

impl KpSigningIntent for ProvisionerRotateCertRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerRotateCertRequest;
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

impl<T: GuardianSigningIntent> GuardianSigned<T> {
    /// Sign a payload with intent-based domain separation.
    pub fn sign(data: T, signing_key: &SigningKey, timestamp_ms: UnixMillis) -> Self {
        let signature = sign_guardian_payload(&data, timestamp_ms, signing_key);
        Self {
            data,
            timestamp_ms,
            signature,
        }
    }

    /// Verify the Guardian signature without consuming the signed payload.
    pub fn verify_signature(&self, pub_key: &VerificationKey) -> CryptoVerificationResult<()> {
        verify_guardian_payload_signature(&self.data, self.timestamp_ms, &self.signature, pub_key)
    }

    /// Authenticate the Guardian signer and extract the payload.
    ///
    /// The caller remains responsible for authorizing the signing key for the
    /// requested operation and current state.
    pub fn authenticate(self, pub_key: &VerificationKey) -> CryptoVerificationResult<T> {
        self.verify_signature(pub_key)?;
        Ok(self.data)
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

    /// Authenticate the KP signer and extract the payload.
    ///
    /// The caller remains responsible for authorizing the signer fingerprint
    /// for the requested operation and current state.
    pub fn authenticate(self) -> CryptoVerificationResult<T> {
        self.verify_signature()?;
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
