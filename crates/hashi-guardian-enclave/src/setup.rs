use crate::Enclave;
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::encrypt_share;
use hashi_guardian_shared::crypto::split_secret;
use hashi_guardian_shared::crypto::NUM_OF_SHARES;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use k256::SecretKey;
use std::sync::Arc;
use tracing::info;

/// Set up a new BTC key. Flow:
///     1. KPs send their encryption pub keys to the operator
///     2. Operator calls setup_new_key (and optionally returns its response to all KPs)
///     3. KPs fetch the setup_new_key response from S3
pub async fn setup_new_key(
    enclave: Arc<Enclave>,
    request: SetupNewKeyRequest,
) -> GuardianResult<GuardianSigned<SetupNewKeyResponse>> {
    info!("/setup_new_key - Received request.");
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("call operator_init first".into()));
    }

    let key_provisioner_pks = request.public_keys();
    info!("Received {} public keys.", key_provisioner_pks.len());

    info!("Generating new Bitcoin private key.");
    let sk = SecretKey::random(&mut rand::thread_rng());
    info!(
        "Bitcoin key generated with fingerprint {:x}.",
        fingerprint(&sk)
    );

    info!(
        "Splitting secret into {} shares (threshold: {}).",
        NUM_OF_SHARES, THRESHOLD
    );
    let shares = split_secret(&sk, &mut rand::thread_rng());

    info!("Encrypting shares for key provisioners.");
    let mut encrypted_shares = vec![];
    let mut share_commitments = vec![];
    for i in 0..NUM_OF_SHARES {
        let share = &shares[i];
        let pk = &key_provisioner_pks[i];
        let encrypted = encrypt_share(share, pk, None, &mut rand::thread_rng());
        let commitment = commit_share(share);
        encrypted_shares.push(encrypted);
        share_commitments.push(commitment);
    }
    info!("All {} shares encrypted.", NUM_OF_SHARES);

    // Log to S3. KPs check that S3 has exactly one SetupNewKeySuccess message,
    // which ensures that KPs receive consistent shares w.r.t each other.
    enclave
        .sign_and_log(LogMessage::SetupNewKeySuccess {
            encrypted_shares: encrypted_shares.clone(),
            share_commitments: share_commitments.clone(),
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
    use hashi_guardian_shared::commit_share;
    use hashi_guardian_shared::decrypt_share;
    use hashi_guardian_shared::NUM_OF_SHARES;
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, Vec<EncSecKey>) {
        let mut private_keys = vec![];
        let mut public_keys = vec![];
        for _i in 0..NUM_OF_SHARES {
            let mut rng = rand::thread_rng();
            let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
            private_keys.push(sk);
            public_keys.push(pk);
        }

        (SetupNewKeyRequest::new(public_keys).unwrap(), private_keys)
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let enclave = Enclave::create_operator_initialized_for_setup_mode().await;
        let verification_key = &enclave.signing_pubkey();
        let (request, kp_private_keys) = mock_setup_new_key_request();
        let resp = setup_new_key(enclave.clone(), request).await.unwrap();
        let validated_resp = resp.verify(verification_key).unwrap();
        assert_eq!(validated_resp.encrypted_shares.len(), NUM_OF_SHARES);

        for (i, (enc_share, sk)) in validated_resp
            .encrypted_shares
            .iter()
            .zip(kp_private_keys.iter())
            .enumerate()
            .take(NUM_OF_SHARES)
        {
            let share = decrypt_share(enc_share, sk, None).unwrap();
            let commitment = &validated_resp.share_commitments[i];
            assert_eq!(enc_share.id, commitment.id);
            assert_eq!(commit_share(&share), *commitment);
            println!("Received share: (id) {:?}", enc_share.id);
        }
    }
}
