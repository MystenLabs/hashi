// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::k256_sk_to_btc_xonly_pubkey;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::*;
use k256::SecretKey;
use std::sync::Arc;
use tracing::info;

/// Set up a new BTC key. Flow:
///     1. KPs send their OpenPGP certificates to the operator
///     2. Operator calls setup_new_key
///     3. KPs fetch the proposed ceremony state from `kp-shares/proposed/`
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSignedResponse<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");

    enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;

    let params = request.params();
    let n = params.num_shares();
    let t = params.threshold();
    let key_provisioner_certs_roster = request.kp_certs_roster();
    info!(
        share_count = key_provisioner_certs_roster.num_kps(),
        "Received key provisioner OpenPGP certificate roster."
    );
    for (index, cert) in key_provisioner_certs_roster.iter().enumerate() {
        info!(
            share_id = index + 1,
            recipient_fingerprint = %cert.fingerprint().to_hex(),
            "Received KP certificate."
        );
    }

    info!("Generating new Bitcoin private key.");
    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments, fingerprint_hex, btc_master_pubkey) = {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::random(&mut rng);
        let fp = format!("{:x}", fingerprint(&sk));
        let btc_master_pubkey = k256_sk_to_btc_xonly_pubkey(&sk);
        info!("Splitting secret into {n} shares (threshold: {t}).");
        let (encrypted, commitments) =
            split_and_encrypt_for_kps(&sk, key_provisioner_certs_roster, params, &mut rng);
        (encrypted, commitments, fp, btc_master_pubkey)
    };
    info!(
        bitcoin_key_fingerprint = %fingerprint_hex,
        share_count = encrypted_shares.share_count(),
        "Bitcoin key generated; encrypted one share for each key provisioner."
    );

    let ss_instance = SecretSharingInstance::new(share_commitments.clone(), n, t, 0)
        .expect("(n, t) validated by SetupNewKeyRequest; commitments produced with matching count");

    let proposal = CeremonyProposalLogMessage::new(
        CeremonyLogMessage::NewKey {
            instance: ss_instance.clone(),
            btc_master_pubkey,
        },
        encrypted_shares.clone(),
    );
    info!("Persisting setup proposal to kp-shares/proposed/.");
    enclave.log_ceremony_proposal(proposal.clone()).await?;

    let response = SetupNewKeyResponse {
        encrypted_shares,
        secret_sharing_instance: ss_instance,
        btc_master_pubkey,
    };
    enclave.install_pending_ceremony(proposal)?;
    let response = enclave.sign(response);

    enclave
        .advance_lifecycle_into(CeremonyStage::AwaitingKeyProvisionerConfirmations.into())
        .expect("setup_new_key should await key provisioner confirmations");
    info!("Setup complete; awaiting every key provisioner's confirmation.");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use crate::test_utils::decrypt_kp_shares;
    use crate::test_utils::mock_kp_certs_roster_with_secrets;
    use hashi_types::guardian::crypto::combine_shares;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, crate::test_utils::MockKpSecretKeys) {
        let (roster, secret_keys) = mock_kp_certs_roster_with_secrets(TEST_N);
        (
            SetupNewKeyRequest::new(roster, TEST_N, TEST_T).unwrap(),
            secret_keys,
        )
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        let verification_key = &enclave.signing_pubkey();
        let (request, secret_keys) = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify_into_data(verification_key).unwrap().response;
        assert_eq!(
            enclave.lifecycle(),
            CeremonyStage::AwaitingKeyProvisionerConfirmations.into()
        );

        // Response still carries the armored ciphertexts.
        assert_eq!(validated_resp.encrypted_shares.share_count(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.num_shares(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.threshold(), TEST_T);
        assert_eq!(validated_resp.secret_sharing_instance.sharing_seq(), 0);
        assert_eq!(
            validated_resp.secret_sharing_instance.commitments().len(),
            TEST_N
        );
        let decrypted_shares = decrypt_kp_shares(&validated_resp.encrypted_shares, &secret_keys);
        for share in &decrypted_shares {
            validated_resp
                .secret_sharing_instance
                .commitments()
                .verify_share(share)
                .expect("decrypted setup share should match its commitment");
        }
        let reconstructed = combine_shares(&decrypted_shares[..TEST_T], TEST_T).unwrap();
        assert_eq!(
            k256_sk_to_btc_xonly_pubkey(&reconstructed),
            validated_resp.btc_master_pubkey,
            "threshold decrypted setup shares should reconstruct the ceremony key"
        );

        // Only the session-scoped proposal is visible before KP confirmation.
        let captured = captures.lock().unwrap();
        assert!(!captured.iter().any(|(key, _)| key.starts_with("ceremony/")));
        assert_eq!(captured.len(), 1, "expected only the ceremony proposal");
        let (key, body) = &captured[0];
        assert_eq!(
            key,
            &format!("kp-shares/proposed/{}.json", enclave.s3_session_id())
        );
        let record: LogRecord = serde_json::from_slice(body).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::CeremonyProposal(proposal)) = record.message()
        else {
            panic!("expected V2 CeremonyProposal variant");
        };
        let CeremonyLogMessage::NewKey {
            instance,
            btc_master_pubkey,
        } = &proposal.ceremony
        else {
            panic!("expected NewKey variant");
        };
        assert_eq!(instance, &validated_resp.secret_sharing_instance);
        assert_eq!(instance.sharing_seq(), 0);
        assert_eq!(instance.num_shares(), TEST_N);
        assert_eq!(instance.threshold(), TEST_T);
        assert_eq!(*btc_master_pubkey, validated_resp.btc_master_pubkey);
        assert_eq!(proposal.encrypted_shares, validated_resp.encrypted_shares);
        assert_eq!(proposal.encrypted_shares.share_count(), TEST_N);
        assert!(std::str::from_utf8(body)
            .unwrap()
            .contains("BEGIN PGP MESSAGE"));
    }
}
