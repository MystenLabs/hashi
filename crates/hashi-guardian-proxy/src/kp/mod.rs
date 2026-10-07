// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! What key provisioners call: the provisioning [`relay`], and the KP-signed
//! `ConfirmCeremony` and `ProvisionerRotateCert`. Each is checked against the
//! ceremony's committed [`roster`] before it reaches the enclave, except
//! `ConfirmCeremony`, which is what commits one and is checked against its
//! proposal.

pub mod relay;
pub mod roster;

use hashi_types::guardian::CeremonyConfirmationRequest;
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

/// [`admit`] for a ceremony confirmation, whose signer the ceremony's own
/// session proposed and no roster has committed yet.
pub async fn admit_confirmation<L: LogStore>(
    roster: &RosterCache<L>,
    signed: &KpSigned<CeremonyConfirmationRequest>,
) -> Result<(), Status> {
    let confirmation = signed
        .verify_signature()
        .map_err(|e| Status::unauthenticated(e.to_string()))?;
    roster
        .authorize_confirmation(
            confirmation.expected_session_id(),
            &signed.signer_fingerprint(),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kp::roster::test_utils::seed_proposal;
    use crate::log_store::test_store::MemStore;
    use hashi_types::guardian::test_utils::mock_attested_kp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;

    /// On a first deploy no roster is committed while the KPs confirm, so
    /// `admit` refuses them all: the proposal is what lets the ceremony finish.
    #[tokio::test]
    async fn a_confirmation_is_admitted_on_its_sessions_proposal() {
        let (cert, secret_armored) = mock_attested_kp_keypair();
        let fingerprint = cert.fingerprint().to_hex();
        let confirmation = CeremonyConfirmationRequest::new("sess-a".into(), [7u8; 32]);
        let signature =
            sign_detached_in_process(&secret_armored, &KpSigned::signed_bytes(&confirmation));
        let signed = KpSigned::from_parts(confirmation, cert.clone(), signature.clone());

        let roster = RosterCache::new(MemStore::default());
        let err = admit(&roster, &signed).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let err = admit_confirmation(&roster, &signed).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let store = MemStore::default();
        seed_proposal(&store, "sess-a", &[&fingerprint]);
        let roster = RosterCache::new(store);
        admit_confirmation(&roster, &signed).await.unwrap();

        // The signature is checked before the proposal is read.
        let other_session = CeremonyConfirmationRequest::new("sess-b".into(), [7u8; 32]);
        let forged = KpSigned::from_parts(other_session, cert, signature);
        let err = admit_confirmation(&roster, &forged).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
