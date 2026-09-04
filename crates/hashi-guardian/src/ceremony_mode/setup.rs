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
///     1. KPs send their OpenPGP certificates and attestations to the operator
///     2. Operator calls setup_new_key
///     3. KPs fetch commitments from `ceremony/` and ciphertexts from `kp-shares/`
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSignedResponse<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");

    enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;

    let params = request.params();
    let n = params.num_shares();
    let t = params.threshold();
    let kp_bundles = request.kp_pgp_cert_bundles();
    info!(
        share_count = kp_bundles.len(),
        "Received key provisioner OpenPGP certificate bundles."
    );
    for (index, bundle) in kp_bundles.iter().enumerate() {
        info!(
            share_id = index + 1,
            recipient_fingerprint = %bundle.cert().fingerprint().to_hex(),
            "Received KP certificate bundle."
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
        let (encrypted, commitments) = split_and_encrypt_for_kps(
            &sk,
            kp_bundles.iter().map(KpPgpCertBundle::cert),
            params,
            &mut rng,
        );
        (encrypted, commitments, fp, btc_master_pubkey)
    };
    info!(
        bitcoin_key_fingerprint = %fingerprint_hex,
        share_count = encrypted_shares.share_count(),
        "Bitcoin key generated; encrypted one share for each key provisioner."
    );

    let ss_instance = SecretSharingInstance::new(share_commitments.clone(), n, t, 0)
        .expect("(n, t) validated by SetupNewKeyRequest; commitments produced with matching count");

    info!("Persisting setup sharing_seq=0 cert_seq=0 to kp-shares/ + ceremony/.");
    enclave
        .log_kp_share_state(0, 0, encrypted_shares.clone())
        .await?;

    enclave
        .log_ceremony(CeremonyLogMessage::NewKey {
            instance: ss_instance.clone(),
            btc_master_pubkey,
        })
        .await?;

    let response = SetupNewKeyResponse {
        encrypted_shares,
        secret_sharing_instance: ss_instance,
        btc_master_pubkey,
    };
    enclave.install_pending_ceremony(CeremonyState::from(response.clone()))?;
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
    use crate::test_utils::mock_kp_pgp_cert_bundles_with_secrets;
    use hashi_types::guardian::crypto::combine_shares;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::VersionedLogMessage;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, crate::test_utils::MockKpSecretKeys) {
        let (bundles, secret_keys) = mock_kp_pgp_cert_bundles_with_secrets(TEST_N);
        (
            SetupNewKeyRequest::new(bundles, TEST_N, TEST_T).unwrap(),
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

        // The ceremony log records the instance only — no ciphertexts.
        let captured = captures.lock().unwrap();
        let ceremony_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("ceremony/"))
            .collect();
        assert_eq!(ceremony_logs.len(), 1, "expected one ceremony/ log");
        let (_key, body) = ceremony_logs[0];
        assert!(
            !std::str::from_utf8(body)
                .unwrap()
                .contains("BEGIN PGP MESSAGE"),
            "ceremony log must not contain ciphertexts"
        );

        let record: LogRecord = serde_json::from_slice(body).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::Ceremony(ceremony)) = record.message() else {
            panic!("expected V2 Ceremony variant");
        };
        let CeremonyLogMessage::NewKey {
            instance,
            btc_master_pubkey,
        } = ceremony.as_ref()
        else {
            panic!("expected NewKey variant");
        };
        assert_eq!(instance, &validated_resp.secret_sharing_instance);
        assert_eq!(instance.sharing_seq(), 0);
        assert_eq!(instance.num_shares(), TEST_N);
        assert_eq!(instance.threshold(), TEST_T);
        // The ceremony log records the same BTC master pubkey as the response.
        assert_eq!(*btc_master_pubkey, validated_resp.btc_master_pubkey);

        // The encrypted shares are persisted to kp-shares/ keyed by sharing_seq
        // and cert_seq, and carry the ciphertexts the ceremony log omits.
        let shares_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("kp-shares/"))
            .collect();
        assert_eq!(shares_logs.len(), 1, "expected one kp-shares/ log");
        let (shares_key, shares_body) = shares_logs[0];
        assert_eq!(
            *shares_key,
            format!(
                "kp-shares/{:020}/{:020}-{}.json",
                0,
                0,
                enclave.s3_session_id()
            )
        );
        let shares_record: LogRecord = serde_json::from_slice(shares_body).unwrap();
        let VersionedLogMessage::V2(LogMessageV2::KpShareState(shares)) = shares_record.message()
        else {
            panic!("expected V2 KpShareState variant");
        };
        let shares = shares.as_ref();
        assert_eq!(shares.sharing_seq, 0);
        assert_eq!(shares.cert_seq, 0);
        assert_eq!(shares.encrypted_shares, validated_resp.encrypted_shares);
        assert_eq!(shares.encrypted_shares.share_count(), TEST_N);
        assert!(std::str::from_utf8(shares_body)
            .unwrap()
            .contains("BEGIN PGP MESSAGE"));
    }
}
