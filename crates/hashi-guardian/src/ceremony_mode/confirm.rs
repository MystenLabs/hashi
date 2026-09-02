// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::CeremonyConfirmationRequest;
use hashi_types::guardian::CeremonyConfirmationResponse;
use hashi_types::guardian::CeremonyStage;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::SessionBoundRequest;
use std::sync::Arc;
use tracing::info;

pub async fn confirm_ceremony(
    enclave: Arc<Enclave>,
    signed: KpSigned<CeremonyConfirmationRequest>,
) -> GuardianResult<CeremonyConfirmationResponse> {
    let lifecycle = enclave.lifecycle();
    if lifecycle != CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
        && lifecycle != CeremonyStage::Completed.into()
    {
        enclave.require_lifecycle(CeremonyStage::AwaitingKeyProvisionerConfirmations.into())?;
    }

    let pending = enclave.pending_ceremony()?;
    let signer_fingerprint = signed.signer_fingerprint().to_hex();
    let request = signed
        .verify_signature()
        .map_err(|error| GuardianError::Unauthenticated(error.to_string()))?;
    request.validate_session(&enclave.s3_session_id())?;
    let share_id = pending.validate_confirmation(&signer_fingerprint, request.ceremony_digest())?;
    let (status, accepted) = pending.record_confirmation(share_id)?;
    if accepted {
        info!(
            share_id = share_id.get(),
            signer_fingerprint,
            have = status.have,
            need = status.need,
            "Accepted key provisioner ceremony confirmation."
        );
    }

    if status.completed && lifecycle == CeremonyStage::AwaitingKeyProvisionerConfirmations.into() {
        enclave.log_ceremony_completion(pending).await?;
        enclave
            .advance_lifecycle_into(CeremonyStage::Completed.into())
            .expect("all KP confirmations should complete the ceremony lifecycle");
        info!("Every key provisioner confirmed the ceremony; ceremony complete.");
    }

    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony_mode::setup::setup_new_key;
    use crate::mock_logger_capturing;
    use crate::test_utils::mock_kp_certs_roster_with_secrets;
    use crate::test_utils::CapturedPuts;
    use crate::test_utils::MockKpSecretKeys;
    use hashi_types::guardian::CeremonyState;
    use hashi_types::guardian::KpCertsRoster;
    use hashi_types::guardian::SessionID;
    use hashi_types::guardian::SetupNewKeyRequest;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;

    const TEST_N: usize = 3;
    const TEST_T: usize = 2;

    struct TestContext {
        enclave: Arc<Enclave>,
        ceremony_digest: [u8; 32],
        roster: KpCertsRoster,
        secret_keys: MockKpSecretKeys,
        captures: CapturedPuts,
    }

    async fn setup_context() -> TestContext {
        let (roster, secret_keys) = mock_kp_certs_roster_with_secrets(TEST_N);
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        let response = setup_new_key(
            enclave.clone(),
            SetupNewKeyRequest::new(roster.clone(), TEST_N, TEST_T).unwrap(),
        )
        .await
        .unwrap()
        .verify_into_data(&enclave.signing_pubkey())
        .unwrap()
        .response;
        TestContext {
            enclave,
            ceremony_digest: CeremonyState::from(response).digest(),
            roster,
            secret_keys,
            captures,
        }
    }

    impl TestContext {
        fn signed_confirmation(&self, index: usize) -> KpSigned<CeremonyConfirmationRequest> {
            self.signed_confirmation_with(index, self.enclave.s3_session_id(), self.ceremony_digest)
        }

        fn signed_confirmation_with(
            &self,
            index: usize,
            session_id: SessionID,
            ceremony_digest: [u8; 32],
        ) -> KpSigned<CeremonyConfirmationRequest> {
            let cert = self
                .roster
                .iter()
                .nth(index)
                .unwrap()
                .pgp_certs()
                .first()
                .unwrap()
                .clone();
            let request = CeremonyConfirmationRequest::new(session_id, ceremony_digest);
            let signature = sign_detached_in_process(
                self.secret_keys.get(&cert.fingerprint().to_hex()).unwrap(),
                &KpSigned::signed_bytes(&request),
            );
            KpSigned::from_parts(request, cert, signature)
        }

        fn completion_count(&self) -> usize {
            self.captures
                .lock()
                .unwrap()
                .iter()
                .filter(|(key, _)| key.starts_with("ceremony-complete/"))
                .count()
        }
    }

    #[tokio::test]
    async fn requires_every_kp_confirmation() {
        let context = setup_context().await;
        assert_eq!(
            context.enclave.lifecycle(),
            CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
        );

        let first = context.signed_confirmation(0);
        let status = confirm_ceremony(context.enclave.clone(), first.clone())
            .await
            .unwrap();
        assert_eq!(status.have, 1);
        assert!(!status.completed);
        let repeated = confirm_ceremony(context.enclave.clone(), first)
            .await
            .unwrap();
        assert_eq!(repeated.have, 1);
        assert_eq!(context.completion_count(), 0);

        for index in 1..TEST_N {
            let status =
                confirm_ceremony(context.enclave.clone(), context.signed_confirmation(index))
                    .await
                    .unwrap();
            assert_eq!(status.have as usize, index + 1);
            assert_eq!(status.need as usize, TEST_N);
            assert_eq!(status.completed, index + 1 == TEST_N);
        }
        assert_eq!(context.enclave.lifecycle(), CeremonyStage::Completed.into());
        assert_eq!(context.completion_count(), 1);
        {
            let captures = context.captures.lock().unwrap();
            let (key, body) = captures
                .iter()
                .find(|(key, _)| key.starts_with("ceremony-complete/"))
                .unwrap();
            assert_eq!(
                key,
                &format!(
                    "ceremony-complete/{:020}-{}.json",
                    0,
                    context.enclave.s3_session_id()
                )
            );
            let json: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(
                json["message"]["CeremonyCompletion"]["ceremony_digest"],
                hex::encode(context.ceremony_digest)
            );
        }
        let repeated = confirm_ceremony(
            context.enclave.clone(),
            context.signed_confirmation(TEST_N - 1),
        )
        .await
        .unwrap();
        assert!(repeated.completed);
        assert_eq!(context.completion_count(), 1);
    }

    #[tokio::test]
    async fn retry_publishes_marker_when_confirmations_are_already_complete() {
        let context = setup_context().await;
        let pending = context.enclave.pending_ceremony().unwrap();
        for share_id in 1..=TEST_N {
            let _ = pending
                .record_confirmation(std::num::NonZeroU16::new(share_id as u16).unwrap())
                .unwrap();
        }
        assert_eq!(
            context.enclave.lifecycle(),
            CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
        );
        assert_eq!(context.completion_count(), 0);

        let status = confirm_ceremony(context.enclave.clone(), context.signed_confirmation(0))
            .await
            .unwrap();

        assert!(status.completed);
        assert_eq!(context.enclave.lifecycle(), CeremonyStage::Completed.into());
        assert_eq!(context.completion_count(), 1);
    }

    #[tokio::test]
    async fn rejects_wrong_ceremony_digest() {
        let context = setup_context().await;
        let signed = context.signed_confirmation_with(0, context.enclave.s3_session_id(), [0; 32]);
        let error = confirm_ceremony(context.enclave.clone(), signed)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GuardianError::InvalidInputs(message) if message.contains("digest")
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_session() {
        let context = setup_context().await;
        let signed =
            context.signed_confirmation_with(0, "other-session".into(), context.ceremony_digest);
        let error = confirm_ceremony(context.enclave.clone(), signed)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            GuardianError::InvalidInputs(message)
                if message.contains("expected guardian session")
        ));
    }

    #[tokio::test]
    async fn rejects_unrostered_signer() {
        let context = setup_context().await;
        let (public, secret) = mock_pgp_keypair();
        let cert = PgpPublicCert::new(public).unwrap();
        let request = CeremonyConfirmationRequest::new(
            context.enclave.s3_session_id(),
            context.ceremony_digest,
        );
        let signature = sign_detached_in_process(&secret, &KpSigned::signed_bytes(&request));
        let error = confirm_ceremony(
            context.enclave.clone(),
            KpSigned::from_parts(request, cert, signature),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, GuardianError::Unauthenticated(_)));
    }
}
