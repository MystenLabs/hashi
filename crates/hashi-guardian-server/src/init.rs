use crate::s3_logger::test_s3_connectivity;
use crate::setup::k256shares_to_secp_secret_key;
use crate::{Enclave, S3Logger};
use axum::extract::State;
use axum::Json;
use fastcrypto::hash::{Blake2b256, HashFunction};
use hashi_guardian_shared::{
    decrypt, GuardianError, GuardianResult, InitExternalRequest, InitExternalRequestState,
    InitInternalRequest, MyShare, ShareCommitment, ShareValue, SECRET_SHARING_T,
};
use std::sync::Arc;
use tracing::{error, info};
use vsss_rs::{DefaultShare, Share};
use GuardianError::*;

// TODO: Add some kind of authentication, e.g., an API key or token
pub async fn init_enclave_internal(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<InitInternalRequest>,
) -> GuardianResult<()> {
    info!("📥 /configure_s3 - Received request");
    // If the configuration has already been set, return an error
    if enclave.config.s3_logger.get().is_some() {
        return Err(Forbidden("S3 configuration previously set".into()));
    }

    let logger = S3Logger::new(request.config).await?;

    info!("🔍 Testing S3 connectivity...");
    // Test S3 connectivity with the new credentials
    test_s3_connectivity(&logger).await?;

    info!("✅ S3 connectivity test passed");
    info!("💾 Storing S3 configuration...");
    if enclave.config.s3_logger.set(logger).is_err() {
        return Err(GenericError("Failed to set S3 configuration".into()));
    }

    info!(
        "💾 Storing {} share commitments...",
        request.share_commitments.len()
    );
    if enclave
        .scratchpad
        .share_commitments
        .set(request.share_commitments)
        .is_err()
    {
        return Err(GenericError("Failed to set share commitments".into()));
    }

    info!("✅ S3 configuration complete!");
    Ok(())
}

// While accumulating shares, we use the state hash to compare if every KP is inputting the same state.
// When we have enough shares, we actually set all the state variables.
pub async fn init_enclave_external(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<InitExternalRequest>,
) -> GuardianResult<()> {
    info!("📥 /init - Received encrypted share");
    // TODO: Replace with is_fully_initialized?
    if enclave.is_init_external() {
        info!("Enclave initialization already complete!");
        return Err(EnclaveAlreadyInitialized);
    }

    let sk = enclave.config.eph_keys.encryption_keys.secret();
    let share_id = request.encrypted_share.id();
    let enc_share_val = request.encrypted_share.ciphertext();
    let state_hash = Blake2b256::digest(&request.state);
    info!("   Share ID: {:?}", share_id);

    // 1) Decrypt the share!
    info!("🔓 Decrypting share...");
    let serialized_share = decrypt(&enc_share_val, sk, Some(&state_hash.digest))?;
    let share_value = bincode::deserialize::<ShareValue>(&serialized_share)
        .map_err(|e| GenericError(format!("Failed to deserialize share: {}", e)))?;
    let share: MyShare = DefaultShare::with_identifier_and_value(*share_id, share_value);
    info!("✅ Share decrypted successfully");

    // 2) Verify the share against the commitment
    info!("🔍 Verifying share against commitment...");
    let share_commitments = enclave
        .scratchpad
        .share_commitments
        .get()
        .ok_or_else(|| GenericError("No share commitments".to_string()))?;
    verify_share(&share, share_commitments)?;
    info!("✅ Share verified successfully");

    // 3) Set state_hash OR make sure whatever was previously set matches.
    //    Panics upon mismatch.
    info!("🔍 Checking state hash...");
    match enclave.scratchpad.state_hash.get() {
        Some(existing_state_hash) => {
            if *existing_state_hash != state_hash {
                error!("❌ State hash mismatch!");
                // TODO: Figure out a better way to deal with it?
                panic!("State hash mismatch");
            }
            info!("✅ State hash matches existing");
        }
        None => {
            if enclave.scratchpad.state_hash.set(state_hash).is_err() {
                return Err(GenericError("State hash already set!".into()));
            }
            info!("✅ State hash set");
        }
    }

    // MILESTONE: At this point, we are sure it is a legitimate payload (both share & config)!

    // 4) Persist share
    info!("💾 Persisting share...");
    let mut received_shares = enclave
        .scratchpad
        .decrypted_shares
        .lock()
        .map_err(|e| GenericError(format!("Failed to acquire lock on shares: {}", e)))?;
    if !received_shares.insert(share) {
        return Err(GenericError("Duplicate shares!".into()));
    }
    let current_share_count = received_shares.len();
    info!(
        "   Total shares received: {}/{}",
        current_share_count, SECRET_SHARING_T
    );

    // 5) If we have enough shares, finish initialization: combine shares & set config.
    if current_share_count >= SECRET_SHARING_T as usize {
        let vec: Vec<MyShare> = received_shares.iter().cloned().collect::<Vec<_>>();
        finalize_init(&vec, &enclave, request.state)?;
    }

    Ok(())
}

fn finalize_init(
    shares: &[MyShare],
    enclave: &Arc<Enclave>,
    incoming_state: InitExternalRequestState,
) -> GuardianResult<()> {
    info!("🎉 Threshold reached! Combining shares...");
    let secp_sk = k256shares_to_secp_secret_key(shares)?;

    info!("🔑 Setting Bitcoin private key...");
    if enclave.config.bitcoin_key.set(secp_sk).is_err() {
        return Err(GenericError("Bitcoin key already set".into()));
    }
    info!("✅ Bitcoin key set");

    info!("⚙️  Setting withdrawal controls...");
    if enclave
        .config
        .withdraw_controls_config
        .set(incoming_state.withdraw_config)
        .is_err()
    {
        return Err(GenericError("WithdrawControlsConfig already set".into()));
    }

    info!("💾 Setting enclave state...");
    let mut state = enclave
        .state
        .lock()
        .map_err(|e| GenericError(format!("Failed to acquire lock on state: {}", e)))?;
    state.hashi_committee_info = incoming_state.hashi_committee_info;
    state.withdraw_state = incoming_state.withdraw_state;

    info!("🎊 ENCLAVE INITIALIZATION COMPLETE!");
    Ok(())
}

fn verify_share(share: &MyShare, commitments: &[ShareCommitment]) -> GuardianResult<()> {
    let expected_commitment = commitments
        .iter()
        .find(|c| *c.id() == share.identifier)
        .ok_or_else(|| GenericError("No matching share found".to_string()))?;
    let serialized_share_value = bincode::serialize(&share.value)
        .map_err(|e| GenericError(format!("Failed to serialize share: {}", e)))?;
    let actual_digest = Blake2b256::digest(&serialized_share_value);
    if expected_commitment.digest != actual_digest {
        return Err(GenericError("Digest mismatch".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::setup_new_key;
    use hashi_guardian_shared::{encrypt, EncSecKey, SetupNewKeyRequest, SECRET_SHARING_N};
    use hpke::kem::X25519HkdfSha256;
    use hpke::Kem;

    const LIMIT: usize = SECRET_SHARING_N as usize;

    fn mock_setup_new_key_request() -> (SetupNewKeyRequest, Vec<EncSecKey>) {
        let mut private_keys = vec![];
        let mut public_keys = vec![];
        for _i in 0..LIMIT {
            let mut rng = rand::thread_rng();
            let keys = X25519HkdfSha256::gen_keypair(&mut rng);
            private_keys.push(keys.0);
            public_keys.push(keys.1);
        }

        (public_keys.into(), private_keys)
    }

    #[tokio::test]
    async fn test_setup_new_key() {
        let (request, priv_keys) = mock_setup_new_key_request();
        let Json(resp) = setup_new_key(Json(request)).await.unwrap();
        assert_eq!(resp.encrypted_shares.len(), LIMIT as usize);

        for i in 0..LIMIT {
            let enc_share = &resp.encrypted_shares[i];
            let sk = &priv_keys[i];
            let serialized_share = decrypt(enc_share.ciphertext(), &sk, None).unwrap();
            let commitment = &resp.share_commitments[i];
            assert_eq!(*enc_share.id(), *commitment.id());
            assert_eq!(Blake2b256::digest(&serialized_share), *commitment.digest());
            let share = bincode::deserialize::<ShareValue>(&serialized_share).unwrap();
            println!(
                "Received share: (id) {:?} (val) {:?}",
                enc_share.id(),
                share
            );
        }
    }

    #[tokio::test]
    async fn test_init_enclave_external() {
        use crate::Enclave;
        use axum::extract::State;
        use fastcrypto::{ed25519::Ed25519KeyPair, traits::KeyPair as _};
        use hashi_guardian_shared::{InitExternalRequestState, WithdrawConfig};
        use std::sync::Arc;
        use std::time::Duration;

        const THRESHOLD: usize = SECRET_SHARING_T as usize;

        // Step 1: Generate KP encryption keys and setup new key
        let (request, kp_private_keys) = mock_setup_new_key_request();
        let Json(resp) = setup_new_key(Json(request)).await.unwrap();
        let encrypted_shares = resp.encrypted_shares;
        let share_commitments = resp.share_commitments;

        // Step 2: Create mock Enclave with encryption keys
        let mut rng = rand::thread_rng();
        let signing_keys = Ed25519KeyPair::generate(&mut rng);
        let (enc_sk, enc_pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        let encryption_keys = (enc_sk, enc_pk).into();
        let enclave = Arc::new(Enclave::new(signing_keys, encryption_keys));

        // Step 3: Set share commitments in the enclave
        enclave
            .scratchpad
            .share_commitments
            .set(share_commitments.clone())
            .unwrap();

        // Step 4: Create InitExternalRequestState
        let init_state = InitExternalRequestState {
            hashi_committee_info: hashi_guardian_shared::HashiCommittee::default(),
            withdraw_config: WithdrawConfig {
                min_delay: Duration::from_secs(60),
                max_delay: Duration::from_secs(3600),
            },
            withdraw_state: hashi_guardian_shared::WithdrawalState::default(),
            cached_bytes: std::sync::OnceLock::new(),
        };

        // Step 5: Simulate THRESHOLD KPs calling init_enclave_external
        for i in 0..LIMIT {
            let kp_sk = &kp_private_keys[i];
            let encrypted_share = &encrypted_shares[i];

            // Re-encrypt the share for the enclave's encryption key
            let serialized_share = decrypt(encrypted_share.ciphertext(), kp_sk, None).unwrap();
            let new_ciphertext = encrypt(
                &serialized_share,
                enclave.config.eph_keys.encryption_keys.public(),
                Some(&Blake2b256::digest(&init_state).digest),
            )
            .unwrap();
            let new_encrypted_share = hashi_guardian_shared::EncryptedShare {
                id: *encrypted_share.id(),
                ciphertext: new_ciphertext,
            };

            let request = InitExternalRequest {
                encrypted_share: new_encrypted_share,
                state: init_state.clone(),
            };

            let result = init_enclave_external(State(enclave.clone()), Json(request)).await;

            // Check behavior based on whether we've reached/exceeded threshold
            if i == THRESHOLD - 1 {
                // At exactly threshold (first time), call should succeed
                assert!(
                    result.is_ok(),
                    "Should succeed at threshold (iteration {})",
                    i
                );
                assert!(
                    enclave.config.bitcoin_key.get().is_some(),
                    "Bitcoin key should be set after threshold"
                );
                assert!(
                    enclave.config.withdraw_controls_config.get().is_some(),
                    "Withdraw controls config should be set after threshold"
                );
            } else if i >= THRESHOLD {
                // After threshold, subsequent init calls should fail
                assert!(
                    result.is_err(),
                    "Should fail at iteration {}: {:?}",
                    i,
                    result
                );
                if let Err(e) = result {
                    assert_eq!(e, GuardianError::EnclaveAlreadyInitialized);
                }
                assert!(
                    enclave.config.bitcoin_key.get().is_some(),
                    "Bitcoin key should still be set"
                );
            } else {
                // Before threshold, call should succeed
                assert!(result.is_ok(), "Init should succeed before threshold");
                assert!(
                    enclave.config.bitcoin_key.get().is_none(),
                    "Bitcoin key should not be set before threshold"
                );
                assert!(
                    enclave.config.withdraw_controls_config.get().is_none(),
                    "Withdraw controls config should not be set before threshold"
                );
            }
        }

        println!(
            "✅ Successfully initialized enclave with {} shares",
            THRESHOLD
        );
    }
}
