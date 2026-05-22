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
///     1. KPs send their encryption pub keys to the operator
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
    if enclave.is_setup_complete() {
        return Err(InvalidInputs("setup already complete".into()));
    }

    let params = request.params();
    let n = params.num_shares();
    let t = params.threshold();
    let key_provisioner_pks = request.public_keys();
    info!("Received {} public keys.", key_provisioner_pks.len());

    info!("Generating new Bitcoin private key.");
    // Confine the !Send `ThreadRng` to a sync scope so the surrounding async
    // future stays Send.
    let (encrypted_shares, share_commitments, fingerprint_hex) = {
        let mut rng = rand::thread_rng();
        let sk = SecretKey::random(&mut rng);
        let fp = format!("{:x}", fingerprint(&sk));
        info!("Splitting secret into {n} shares (threshold: {t}).");
        let (encrypted, commitments) =
            split_and_encrypt_for_kps(&sk, key_provisioner_pks, params, &mut rng)
                .expect("SetupNewKeyRequest::new validates pubkey count == params.num_shares()");
        (encrypted, commitments, fp)
    };
    info!(
        "Bitcoin key generated with fingerprint {}; all {} shares encrypted.",
        fingerprint_hex, n
    );

    let ss_instance = SecretSharingInstance::new(share_commitments.clone(), n, t, 0)?;

    enclave
        .log_secret_sharing(SecretSharingLogMessage {
            encrypted_shares: encrypted_shares.clone(),
            secret_sharing_instance: ss_instance,
        })
        .await?;

    let response = enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    });

    enclave
        .scratchpad
        .setup_complete
        .set(())
        .map_err(|_| InvalidInputs("setup_complete already set".into()))?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::commit_share;
    use hashi_types::guardian::decrypt_share;
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem;

    const TEST_N: usize = 5;
    const TEST_T: usize = 3;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, Vec<EncSecKey>) {
        let mut private_keys = vec![];
        let mut public_keys = vec![];
        for _i in 0..TEST_N {
            let mut rng = rand::thread_rng();
            let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
            private_keys.push(sk);
            public_keys.push(pk);
        }

        (
            SetupNewKeyRequest::new(public_keys, TEST_N, TEST_T).unwrap(),
            private_keys,
        )
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let enclave = Enclave::create_operator_initialized().await;
        let verification_key = &enclave.signing_pubkey();
        let (request, kp_private_keys) = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();
        assert_eq!(validated_resp.encrypted_shares.len(), TEST_N);

        for (enc_share, sk) in validated_resp
            .encrypted_shares
            .iter()
            .zip(kp_private_keys.iter())
            .take(TEST_N)
        {
            let share = decrypt_share(enc_share, sk, None).unwrap();
            let commitment = commit_share(&share);
            assert!(validated_resp.share_commitments.contains(&commitment));
            println!("Received share: (id) {:?}", enc_share.id);
        }
    }
}
