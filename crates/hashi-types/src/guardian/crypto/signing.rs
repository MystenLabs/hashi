// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Guardian- and KP-signed envelopes with intent-based domain separation.
//!
//! [`GuardianSigned`] uses Ed25519 signatures produced by the Guardian, while
//! [`KpSigned`] uses detached OpenPGP signatures produced by key provisioners.
//! Both serialize a payload together with its signing intent so a signature for
//! one payload type cannot be replayed as another.

use crate::guardian::CeremonyConfirmationRequest;
use crate::guardian::CryptoVerificationError;
use crate::guardian::CryptoVerificationResult;
use crate::guardian::GuardianError::InternalError;
use crate::guardian::GuardianInfo;
use crate::guardian::GuardianResult;
use crate::guardian::LogEntry;
use crate::guardian::ProvisionerInitRequest;
use crate::guardian::ProvisionerRotateCertRequest;
use crate::guardian::ProvisionerRotateCertResponse;
use crate::guardian::ProvisionerRotateKpSetRequest;
use crate::guardian::RotateKpSetResponse;
use crate::guardian::SessionBoundRequest;
use crate::guardian::SetupNewKeyResponse;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
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
    LogEntry = 0,
    /// Intent for SetupNewKeyResponse.
    SetupNewKeyResponse = 1,
    /// Intent for StandardWithdrawalResponse.
    StandardWithdrawalResponse = 2,
    /// Intent for GuardianInfo.
    GuardianInfo = 3,
    /// Intent for RotateKpSetResponse.
    RotateKpSetResponse = 4,
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
    /// Intent for ProvisionerInitRequest.
    ProvisionerInitRequest = 0,
    /// Intent for ProvisionerRotateCertRequest.
    ProvisionerRotateCertRequest = 1,
    /// Intent for ProvisionerRotateKpSetRequest.
    ProvisionerRotateKpSetRequest = 2,
    /// Intent for CeremonyConfirmationRequest.
    CeremonyConfirmationRequest = 3,
}

/// KP-signed payloads and their intent-based domain separation.
pub trait KpSigningIntent: Serialize + SessionBoundRequest {
    const INTENT: KpSigningIntentType;
}

/// KP-signed wrapper - adds signer cert and detached OpenPGP signature to any
/// KP-submitted request payload.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct KpSigned<T> {
    data: T,
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
    data: T,
    pub signature: GuardianSignature,
}

impl GuardianSigningIntent for LogEntry {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::LogEntry;
}

impl GuardianSigningIntent for GuardianResponse<SetupNewKeyResponse> {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::SetupNewKeyResponse;
}

impl GuardianSigningIntent for GuardianResponse<StandardWithdrawalResponse> {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::StandardWithdrawalResponse;
}

impl GuardianSigningIntent for GuardianResponse<GuardianInfo> {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::GuardianInfo;
}

impl GuardianSigningIntent for GuardianResponse<RotateKpSetResponse> {
    const INTENT: GuardianSigningIntentType = GuardianSigningIntentType::RotateKpSetResponse;
}

impl GuardianSigningIntent for GuardianResponse<ProvisionerRotateCertResponse> {
    const INTENT: GuardianSigningIntentType =
        GuardianSigningIntentType::ProvisionerRotateCertResponse;
}

impl KpSigningIntent for CeremonyConfirmationRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::CeremonyConfirmationRequest;
}

impl KpSigningIntent for ProvisionerInitRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerInitRequest;
}

impl KpSigningIntent for ProvisionerRotateCertRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerRotateCertRequest;
}

impl KpSigningIntent for ProvisionerRotateKpSetRequest {
    const INTENT: KpSigningIntentType = KpSigningIntentType::ProvisionerRotateKpSetRequest;
}

impl<T> GuardianResponse<T> {
    pub fn new(response: T, timestamp_ms: UnixMillis) -> Self {
        Self {
            response,
            timestamp_ms,
        }
    }
}

// Guardian unchecked access is intentionally narrow: LogRecord's custom wire
// handling and node/proxy/CLI paths that establish trust independently.
// KpSigned has no unchecked extraction; production KP payloads are always
// verified before access.
impl<T> GuardianSigned<T> {
    pub fn from_parts(data: T, signature: GuardianSignature) -> Self {
        Self { data, signature }
    }

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

    /// Verify the Guardian signature and borrow the authenticated payload.
    pub fn verify_signature(&self, pub_key: &VerificationKey) -> CryptoVerificationResult<&T>
    where
        T: GuardianSigningIntent,
    {
        pub_key
            .verify(&self.signature, &Self::signed_bytes(&self.data))
            .map_err(|_| CryptoVerificationError::new("signature invalid"))?;
        Ok(&self.data)
    }

    /// Verify the Guardian signature and move out the authenticated payload.
    pub fn verify_into_data(self, pub_key: &VerificationKey) -> CryptoVerificationResult<T>
    where
        T: GuardianSigningIntent,
    {
        self.verify_signature(pub_key)?;
        Ok(self.data)
    }

    /// Borrow the payload WITHOUT verifying the signature.
    pub(crate) fn data_unchecked(&self) -> &T {
        &self.data
    }

    #[cfg(test)]
    pub(crate) fn data_unchecked_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Move out the payload WITHOUT verifying the signature.
    /// The caller must establish trust in the payload independently.
    pub fn into_data_unchecked(self) -> T {
        self.data
    }

    pub(crate) fn into_parts(self) -> (T, GuardianSignature) {
        (self.data, self.signature)
    }
}

impl<T: KpSigningIntent> KpSigned<T> {
    pub fn from_parts(data: T, signer_cert: PgpPublicCert, signature: String) -> Self {
        Self {
            data,
            signer_cert,
            signature,
        }
    }

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

    /// Verify the signature and borrow the authenticated request.
    /// Checks the intent byte to ensure the signature is for this request type.
    pub fn verify_signature(&self) -> CryptoVerificationResult<&T> {
        let msg_bytes = Self::signed_bytes(&self.data);
        verify_detached_signature(&msg_bytes, &self.signature, &self.signer_cert).map_err(|e| {
            CryptoVerificationError::new(format!("KP signature verification failed: {e}"))
        })?;
        Ok(&self.data)
    }

    /// Verify the KP signature and move out the authenticated payload.
    pub fn verify_into_data(self) -> CryptoVerificationResult<T> {
        self.verify_signature()?;
        Ok(self.data)
    }

    pub(crate) fn into_parts(self) -> (T, PgpPublicCert, String) {
        (self.data, self.signer_cert, self.signature)
    }

    pub fn signer_fingerprint(&self) -> Fingerprint {
        self.signer_cert.fingerprint()
    }
}
