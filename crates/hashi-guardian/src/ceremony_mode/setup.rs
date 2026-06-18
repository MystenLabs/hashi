// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use hashi_types::guardian::crypto::split_and_encrypt_for_kps;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::*;
use k256::SecretKey;
use std::sync::Arc;
use tracing::info;

/// Set up a new BTC key. Flow:
///     1. KPs send their OpenPGP certificates to the operator
///     2. Operator calls setup_new_key
///     3. KPs fetch commitments/roster from `ceremony/` and ciphertexts from `shares/`
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSigned<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");
    // Hold the ceremony guard across the whole flow so concurrent setup_new_key
    // /rotate_kps callers can't both pass the completion check below and run.
    let mut ceremony_complete = enclave.scratchpad.ceremony_complete.lock().await;
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }
    if *ceremony_complete {
        return Err(InvalidInputs("setup or rotation already complete".into()));
    }

    let params = request.params();
    let n = params.num_shares();
    let t = params.threshold();
    let key_provisioner_certs = request.pgp_certs();
    info!(
        "Received {} OpenPGP certificates.",
        key_provisioner_certs.len()
    );

    info!("Generating new Bitcoin private key.");
    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments, fingerprint_hex) = {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::random(&mut rng);
        let fp = format!("{:x}", fingerprint(&sk));
        info!("Splitting secret into {n} shares (threshold: {t}).");
        let (encrypted, commitments) =
            split_and_encrypt_for_kps(&sk, key_provisioner_certs, params, &mut rng);
        (encrypted, commitments, fp)
    };
    info!(
        "Bitcoin key generated with fingerprint {}; all {} shares encrypted.",
        fingerprint_hex, n
    );

    let ss_instance = SecretSharingInstance::new(share_commitments.clone(), n, t, 0)
        .expect("(n, t) validated by SetupNewKeyRequest; commitments produced with matching count");

    info!("Persisting setup sharing_seq=0 to shares/ + ceremony/.");
    enclave.log_shares(0, encrypted_shares.clone()).await?;

    enclave
        .log_ceremony(CeremonyLogMessage::NewKey {
            instance: ss_instance.clone(),
            roster: encrypted_shares.recipient_roster(),
        })
        .await?;

    enclave
        .set_latest_encrypted_shares(encrypted_shares.clone())
        .expect("set_latest_encrypted_shares should work if ceremony_complete=false");

    let response = enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        secret_sharing_instance: ss_instance,
    });

    *ceremony_complete = true;
    info!("Setup complete.");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_logger_capturing;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use hashi_types::pgp::test_utils::mock_pgp_certs;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> SetupNewKeyRequest {
        SetupNewKeyRequest::new(mock_pgp_certs(TEST_N), TEST_N, TEST_T).unwrap()
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let (logger, captures) = mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_s3_logger(logger),
        )
        .await;
        let verification_key = &enclave.signing_pubkey();
        let request = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();

        // Response still carries the armored ciphertexts.
        assert_eq!(validated_resp.encrypted_shares.len(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.num_shares(), TEST_N);
        assert_eq!(validated_resp.secret_sharing_instance.threshold(), TEST_T);
        assert_eq!(validated_resp.secret_sharing_instance.sharing_seq(), 0);
        assert_eq!(
            validated_resp.secret_sharing_instance.commitments().len(),
            TEST_N
        );
        for enc_share in validated_resp.encrypted_shares.iter() {
            assert!(enc_share
                .armored_ciphertext
                .starts_with("-----BEGIN PGP MESSAGE-----"));
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
        let LogMessage::Ceremony(ceremony) = record.message else {
            panic!("expected Ceremony variant");
        };
        let CeremonyLogMessage::NewKey { instance, roster } = *ceremony else {
            panic!("expected NewKey variant");
        };
        assert_eq!(instance.sharing_seq(), 0);
        assert_eq!(instance.num_shares(), TEST_N);
        assert_eq!(instance.threshold(), TEST_T);
        // The roster commits one recipient fingerprint per share.
        assert_eq!(roster.len(), TEST_N);

        // The encrypted shares are persisted to shares/ keyed by sharing_seq,
        // and carry the ciphertexts the ceremony log omits.
        let shares_logs: Vec<_> = captured
            .iter()
            .filter(|(k, _)| k.starts_with("shares/"))
            .collect();
        assert_eq!(shares_logs.len(), 1, "expected one shares/ log");
        let (shares_key, shares_body) = shares_logs[0];
        assert_eq!(
            *shares_key,
            format!("shares/{:020}-{}.json", 0, enclave.s3_session_id())
        );
        let shares_record: LogRecord = serde_json::from_slice(shares_body).unwrap();
        let LogMessage::Shares(shares) = shares_record.message else {
            panic!("expected Shares variant");
        };
        assert_eq!(shares.sharing_seq, 0);
        assert_eq!(shares.encrypted_shares.len(), TEST_N);
        assert!(std::str::from_utf8(shares_body)
            .unwrap()
            .contains("BEGIN PGP MESSAGE"));
    }
}
