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
///     3. KPs fetch commitments from `ceremony/` and ciphertexts from `kp-shares/`
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSigned<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");

    // Serialize the whole ceremony. The exact lifecycle check prevents setup
    // and rotation from interleaving and rejects another ceremony afterward.
    let _guard = enclave.control_lock.lock().await;
    enclave.require_lifecycle(CeremonyStage::OperatorInitialized.into())?;

    let params = request.params();
    let n = params.num_shares();
    let t = params.threshold();
    let key_provisioner_certs_roster = request.kp_certs_roster();
    let certificate_count: usize = key_provisioner_certs_roster
        .iter()
        .map(|set| set.pgp_certs().len())
        .sum();
    info!(
        share_count = key_provisioner_certs_roster.num_kps(),
        certificate_count, "Received key provisioner OpenPGP certificate roster."
    );
    for (index, cert_set) in key_provisioner_certs_roster.iter().enumerate() {
        info!(
            share_id = index + 1,
            certificate_count = cert_set.pgp_certs().len(),
            recipient_fingerprints = ?cert_set.fingerprints(),
            "Received KP certificate set."
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
        ciphertext_count = encrypted_shares.ciphertext_count(),
        "Bitcoin key generated; encrypted each share once per KP certificate."
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

    let response = enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        secret_sharing_instance: ss_instance,
        btc_master_pubkey,
    });

    enclave
        .advance_lifecycle_into(CeremonyStage::Completed.into())
        .expect("setup_new_key should complete a ceremony lifecycle");
    info!("Setup complete.");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use hashi_types::guardian::test_utils::mock_kp_certs_roster;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogMessageV1;
    use hashi_types::guardian::LogRecord;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> SetupNewKeyRequest {
        SetupNewKeyRequest::new(mock_kp_certs_roster(TEST_N), TEST_N, TEST_T).unwrap()
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_ceremony(logger);
        let verification_key = &enclave.signing_pubkey();
        let request = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();
        assert_eq!(enclave.lifecycle(), CeremonyStage::Completed.into());

        // Response still carries the armored ciphertexts.
        assert_eq!(validated_resp.encrypted_shares.share_count(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.num_shares(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.threshold(), TEST_T);
        assert_eq!(validated_resp.secret_sharing_instance.sharing_seq(), 0);
        assert_eq!(
            validated_resp.secret_sharing_instance.commitments().len(),
            TEST_N
        );
        for enc_share in validated_resp.encrypted_shares.iter() {
            for ciphertext in enc_share.ciphertexts_by_fingerprint.values() {
                assert!(ciphertext.starts_with("-----BEGIN PGP MESSAGE-----"));
            }
        }

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
        let LogMessage::V1(LogMessageV1::Ceremony(ceremony)) = record.message else {
            panic!("expected Ceremony variant");
        };
        let CeremonyLogMessage::NewKey {
            instance,
            btc_master_pubkey,
        } = *ceremony
        else {
            panic!("expected NewKey variant");
        };
        assert_eq!(instance.sharing_seq(), 0);
        assert_eq!(instance.num_shares(), TEST_N);
        assert_eq!(instance.threshold(), TEST_T);
        // The ceremony log records the same BTC master pubkey as the response.
        assert_eq!(btc_master_pubkey, validated_resp.btc_master_pubkey);

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
        let LogMessage::V1(LogMessageV1::KpShareState(shares)) = shares_record.message else {
            panic!("expected KpShareState variant");
        };
        assert_eq!(shares.sharing_seq, 0);
        assert_eq!(shares.cert_seq, 0);
        assert_eq!(shares.encrypted_shares.share_count(), TEST_N);
        assert!(std::str::from_utf8(shares_body)
            .unwrap()
            .contains("BEGIN PGP MESSAGE"));
    }
}
