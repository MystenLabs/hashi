// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What key provisioners call: the provisioning [`relay`], and the KP-signed
//! `ConfirmCeremony` and `ProvisionerRotateCert`. Each is checked against the
//! ceremony's committed [`roster`] before it reaches the enclave.

pub mod relay;
pub mod roster;

use hashi_types::guardian::GuardianError;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::KpSigningIntent;
use tonic::Status;

use crate::kp::roster::RosterCache;
use crate::log_store::LogStore;

/// Admission control only: the enclave repeats both checks. Signature first
/// because it needs no roster read.
pub async fn admit<T, P, L>(roster: &RosterCache<L>, request: &P) -> Result<(), Status>
where
    T: KpSigningIntent,
    P: Clone,
    KpSigned<T>: TryFrom<P, Error = GuardianError>,
    L: LogStore,
{
    let signer = verify_kp_signature::<T, P>(request)?.signer_fingerprint();
    roster.authorize(&signer).await
}

fn verify_kp_signature<T, P>(request: &P) -> Result<KpSigned<T>, Status>
where
    T: KpSigningIntent,
    P: Clone,
    KpSigned<T>: TryFrom<P, Error = GuardianError>,
{
    let signed_request = KpSigned::<T>::try_from(request.clone())
        .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))?;
    signed_request
        .verify_signature()
        .map_err(|e| Status::unauthenticated(e.to_string()))?;
    Ok(signed_request)
}
