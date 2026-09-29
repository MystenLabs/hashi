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

pub fn parse<T, P>(request: &P) -> Result<KpSigned<T>, Status>
where
    T: KpSigningIntent,
    P: Clone,
    KpSigned<T>: TryFrom<P, Error = GuardianError>,
{
    KpSigned::<T>::try_from(request.clone())
        .map_err(|e| Status::invalid_argument(format!("malformed request: {e}")))
}

/// Admission control only: the enclave repeats both checks. Signature first
/// because it needs no roster read.
pub async fn admit<'a, T, L>(
    roster: &RosterCache<L>,
    signed: &'a KpSigned<T>,
) -> Result<&'a T, Status>
where
    T: KpSigningIntent,
    L: LogStore,
{
    let payload = signed
        .verify_signature()
        .map_err(|e| Status::unauthenticated(e.to_string()))?;
    roster.authorize(&signed.signer_fingerprint()).await?;
    Ok(payload)
}
