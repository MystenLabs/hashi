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
///     2. Operator calls setup_new_key (and optionally returns its response to all KPs)
///     3. KPs fetch the setup_new_key response from `secret_sharing/` in S3
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSigned<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }

    let n = request.num_shares();
    let t = request.threshold();
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
            split_and_encrypt_for_kps(&sk, key_provisioner_certs, t, &mut rng)?;
        (encrypted, commitments, fp)
    };
    info!(
        "Bitcoin key generated with fingerprint {}; all {} shares encrypted.",
        fingerprint_hex, n
    );

    let secret_sharing_config = SecretSharingConfig::new(share_commitments.clone(), n, t, 0)?;

    enclave
        .log_secret_sharing(SecretSharingLogMessage {
            encrypted_shares: encrypted_shares.clone(),
            secret_sharing_config,
        })
        .await?;

    let response = enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    });

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sequoia_openpgp::cert::prelude::CertBuilder;
    use sequoia_openpgp::serialize::Serialize;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> SetupNewKeyRequest {
        let mut public_certs = vec![];
        for _i in 0..TEST_N {
            let (cert, _) = CertBuilder::general_purpose(["kp@example.com"])
                .generate()
                .unwrap();
            let mut armored = Vec::new();
            cert.armored().export(&mut armored).unwrap();
            public_certs.push(PgpPublicCert::new(String::from_utf8(armored).unwrap()).unwrap());
        }

        SetupNewKeyRequest::new(public_certs, TEST_N, TEST_T).unwrap()
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let enclave = Enclave::create_operator_initialized().await;
        let verification_key = &enclave.signing_pubkey();
        let request = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();
        assert_eq!(validated_resp.encrypted_shares.len(), TEST_N);
        assert_eq!(validated_resp.share_commitments.len(), TEST_N);

        for enc_share in validated_resp.encrypted_shares.iter().take(TEST_N) {
            assert!(enc_share
                .armored_ciphertext
                .starts_with("-----BEGIN PGP MESSAGE-----"));
        }
    }
}
