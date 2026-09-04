// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Replace the authenticated KP signer's sole certificate. The live guardian
//! verifies that the caller submitted its currently committed share, then
//! appends a complete `kp-shares/` snapshot with only that share re-encrypted.

use std::sync::Arc;

use crate::Enclave;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::encrypt_share_for_provisioner;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::Unauthenticated;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::KpSigned;
use hashi_types::guardian::ProvisionerRotateCertRequest;
use hashi_types::guardian::ProvisionerRotateCertResponse;
use hashi_types::guardian::SessionBoundRequest;
use tracing::info;

pub async fn provisioner_rotate_cert(
    enclave: Arc<Enclave>,
    signed_request: KpSigned<ProvisionerRotateCertRequest>,
) -> GuardianResult<GuardianSignedResponse<ProvisionerRotateCertResponse>> {
    info!("/provisioner_rotate_cert - Received request.");

    enclave.require_fully_initialized()?;

    let signer_fingerprint = signed_request.signer_fingerprint().to_hex();
    let request = signed_request
        .verify_into_data()
        .map_err(|error| Unauthenticated(error.to_string()))?;

    let live_session_id = enclave.s3_session_id();
    request.validate_session(&live_session_id)?;

    let mut reader = enclave.new_guardian_reader()?;
    let latest_state = reader.read_latest_ceremony_state().await?;
    apply_cert_rotation(&enclave, signer_fingerprint, request, latest_state).await
}

async fn apply_cert_rotation(
    enclave: &Enclave,
    signer_fingerprint: String,
    request: ProvisionerRotateCertRequest,
    latest_state: CeremonyState,
) -> GuardianResult<GuardianSignedResponse<ProvisionerRotateCertResponse>> {
    let (_, expected_cert_seq, new_kp_pgp_cert, encrypted_share) = request.into_parts();
    let share_id = encrypted_share.id;
    let new_recipient_fingerprint = new_kp_pgp_cert.fingerprint().to_hex();

    let enclave_btc_pubkey = enclave.config.enclave_btc_pubkey()?;
    if latest_state.btc_master_pubkey != enclave_btc_pubkey {
        return Err(InvalidInputs(format!(
            "latest ceremony BTC pubkey differs from initialized enclave BTC pubkey: latest \
             {:?}, initialized {enclave_btc_pubkey:?}",
            latest_state.btc_master_pubkey
        )));
    }
    let sharing_seq = latest_state.secret_sharing_instance.sharing_seq();

    if latest_state.cert_seq != expected_cert_seq {
        return Err(InvalidInputs(format!(
            "provisioner_rotate_cert request expected cert_seq {expected_cert_seq}, latest cert_seq \
             is {}",
            latest_state.cert_seq
        )));
    }

    let latest_instance = latest_state.secret_sharing_instance;
    let encrypted_shares = latest_state.encrypted_shares;
    encrypted_shares.validate_share_assignment(&signer_fingerprint, share_id)?;
    let next_cert_seq = latest_state
        .cert_seq
        .checked_add(1)
        .ok_or_else(|| InvalidInputs("cert_seq overflow".into()))?;

    // The KP signature binds the ciphertext and the rest of this request to the
    // current session and cert sequence, so no additional HPKE AAD is needed.
    let share = decrypt_share(&encrypted_share, enclave.encryption_secret_key(), None)?;
    latest_instance.commitments().verify_share(&share)?;

    let replacement_ciphertext = encrypt_share_for_provisioner(&share, &new_kp_pgp_cert);
    let (encrypted_shares, changed_entry) = encrypted_shares.replace_recipient(
        &signer_fingerprint,
        new_recipient_fingerprint.clone(),
        replacement_ciphertext,
    )?;

    enclave
        .log_kp_share_state(sharing_seq, next_cert_seq, encrypted_shares)
        .await?;

    info!(
        sharing_seq,
        cert_seq = next_cert_seq,
        share_id = share_id.get(),
        signer_fingerprint = %signer_fingerprint,
        new_fingerprint = %new_recipient_fingerprint,
        "KP certificate rotation complete",
    );

    Ok(enclave.sign(ProvisionerRotateCertResponse {
        cert_seq: next_cert_seq,
        encrypted_share: changed_entry,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::decrypt_kp_shares;
    use crate::test_utils::mock_kp_certs_roster_with_secrets;
    use crate::test_utils::mock_logger_capturing;
    use crate::OperatorInitTestArgs;
    use hashi_types::bitcoin::create_btc_keypair_for_test;
    use hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey;
    use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
    use hashi_types::guardian::Ciphertext;
    use hashi_types::guardian::GuardianEncryptedShare;
    use hashi_types::guardian::GuardianError::LifecycleMismatch;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::SecretSharingInstance;
    use hashi_types::guardian::SecretSharingParams;
    use hashi_types::guardian::Share;
    use hashi_types::guardian::ShareCommitments;
    use hashi_types::guardian::VersionedLogMessage;
    use hashi_types::pgp::test_utils::mock_pgp_cert;
    use hashi_types::pgp::test_utils::mock_pgp_keypair;
    use hashi_types::pgp::test_utils::sign_detached_in_process;
    use hashi_types::pgp::PgpPublicCert;
    use k256::SecretKey;
    use std::num::NonZeroU16;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;
    const INITIAL_CERT_SEQ: u64 = 7;

    fn signed_rotate_request(
        enclave: &Arc<Enclave>,
        new_cert: PgpPublicCert,
        share: &Share,
        signer_cert: &PgpPublicCert,
        signer_secret: &str,
    ) -> KpSigned<ProvisionerRotateCertRequest> {
        let request = ProvisionerRotateCertRequest::new(
            enclave.s3_session_id(),
            INITIAL_CERT_SEQ,
            new_cert,
            share,
            enclave.encryption_public_key(),
            &mut rand::thread_rng(),
        );
        let signature = sign_detached_in_process(signer_secret, &KpSigned::signed_bytes(&request));
        KpSigned::from_parts(request, signer_cert.clone(), signature)
    }

    async fn initialized_rotation_context() -> (
        Arc<Enclave>,
        Vec<Share>,
        CeremonyState,
        crate::test_utils::MockKpSecretKeys,
        crate::test_utils::CapturedPuts,
        hashi_types::guardian::KpCertRoster,
    ) {
        let secret = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let btc_master_pubkey = k256_sk_to_btc_xonly_pubkey(&secret);
        let params = SecretSharingParams::new(TEST_N, TEST_T).unwrap();
        let (cert_roster, secret_keys) = mock_kp_certs_roster_with_secrets(TEST_N);
        let (encrypted_shares, commitments) = split_and_encrypt_for_kps(
            &secret,
            cert_roster.iter(),
            &params,
            &mut rand::thread_rng(),
        );
        let shares = decrypt_kp_shares(&encrypted_shares, &secret_keys);
        let instance = SecretSharingInstance::new(commitments, TEST_N, TEST_T, 0).unwrap();
        let ceremony_state = CeremonyState {
            secret_sharing_instance: instance,
            btc_master_pubkey,
            cert_seq: INITIAL_CERT_SEQ,
            encrypted_shares,
        };

        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(OperatorInitTestArgs {
            s3_logger: logger,
            ceremony_state: ceremony_state.clone(),
            ..Default::default()
        })
        .await;
        enclave
            .config
            .set_btc_keypair(create_btc_keypair_for_test(&[8u8; 32]))
            .unwrap();

        (
            enclave,
            shares,
            ceremony_state,
            secret_keys,
            captures,
            cert_roster,
        )
    }

    #[tokio::test]
    async fn rotates_only_authenticated_signers_share_and_rejects_another_share() {
        let (enclave, shares, ceremony_state, mut secret_keys, captures, cert_roster) =
            initialized_rotation_context().await;
        let old_encrypted_shares = ceremony_state.encrypted_shares.clone();
        let original_commitments = ceremony_state.secret_sharing_instance.commitments().clone();
        let btc_master_pubkey = ceremony_state.btc_master_pubkey;
        let signer_cert = cert_roster.cert_for_share(shares[0].id).unwrap();
        let signer_fingerprint = signer_cert.fingerprint().to_hex();
        let signer_secret = secret_keys.get(&signer_fingerprint).unwrap();
        let (new_public, new_secret) = mock_pgp_keypair();
        let new_cert = PgpPublicCert::new(new_public).unwrap();
        let new_fingerprint = new_cert.fingerprint().to_hex();

        let signed_wrong_share = signed_rotate_request(
            &enclave,
            new_cert.clone(),
            &shares[1],
            signer_cert,
            signer_secret,
        );
        let wrong_signer_fingerprint = signed_wrong_share.signer_fingerprint().to_hex();
        let wrong_share_request = signed_wrong_share
            .verify_into_data()
            .expect("old certificate should authenticate the request");
        let error = apply_cert_rotation(
            &enclave,
            wrong_signer_fingerprint,
            wrong_share_request,
            ceremony_state.clone(),
        )
        .await
        .expect_err("a signer must not rotate another provisioner's share");
        assert!(matches!(error, InvalidInputs(_)));
        assert!(captures.lock().unwrap().is_empty());

        let signed_request =
            signed_rotate_request(&enclave, new_cert, &shares[0], signer_cert, signer_secret);
        let authenticated_fingerprint = signed_request.signer_fingerprint().to_hex();
        let request = signed_request
            .verify_into_data()
            .expect("old certificate should authenticate the request");
        let signed_response =
            apply_cert_rotation(&enclave, authenticated_fingerprint, request, ceremony_state)
                .await
                .expect("the committed recipient should rotate its sole certificate");
        let response = signed_response
            .verify_into_data(&enclave.signing_pubkey())
            .expect("rotation response should be signed by the enclave")
            .response;

        assert_eq!(response.cert_seq, INITIAL_CERT_SEQ + 1);
        assert_eq!(response.encrypted_share.id, shares[0].id);
        assert_eq!(
            response.encrypted_share.recipient_fingerprint,
            new_fingerprint
        );
        assert!(response
            .encrypted_share
            .armored_ciphertext
            .starts_with("-----BEGIN PGP MESSAGE-----"));

        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0]
            .0
            .starts_with("kp-shares/00000000000000000000/00000000000000000008-"));
        let record: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::KpShareState(persisted)) = record.message()
        else {
            panic!("certificate rotation should persist a V2 KP-share snapshot");
        };
        assert_eq!(persisted.sharing_seq, 0);
        assert_eq!(persisted.cert_seq, INITIAL_CERT_SEQ + 1);
        let (expected_roster, expected_changed_entry) = old_encrypted_shares
            .replace_recipient(
                &signer_fingerprint,
                new_fingerprint.clone(),
                response.encrypted_share.armored_ciphertext.clone(),
            )
            .unwrap();
        assert_eq!(response.encrypted_share, expected_changed_entry);
        assert_eq!(persisted.encrypted_shares, expected_roster);

        secret_keys.insert(new_fingerprint, new_secret);
        let decrypted = decrypt_kp_shares(&persisted.encrypted_shares, &secret_keys);
        for (actual, expected) in decrypted.iter().zip(&shares) {
            assert_eq!(actual.id, expected.id);
            assert_eq!(actual.value, expected.value);
        }
        assert_eq!(
            original_commitments,
            ShareCommitments::from_shares(&decrypted).unwrap()
        );
        assert_eq!(
            enclave.config.enclave_btc_pubkey().unwrap(),
            btc_master_pubkey
        );
    }

    #[tokio::test]
    async fn rejects_wrong_lifecycle_before_verifying_signature() {
        let enclave = Enclave::create_with_random_keys();
        let request = ProvisionerRotateCertRequest::from_encrypted_share_for_testing(
            "mock-session".into(),
            0,
            mock_pgp_cert(),
            GuardianEncryptedShare {
                id: NonZeroU16::new(1).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![],
                    aes_ciphertext: vec![],
                },
            },
        );
        let signed_request =
            KpSigned::from_parts(request, mock_pgp_cert(), "invalid signature".into());

        let err = provisioner_rotate_cert(enclave, signed_request)
            .await
            .expect_err("wrong lifecycle should be rejected first");

        assert!(matches!(err, LifecycleMismatch { .. }));
    }
}
