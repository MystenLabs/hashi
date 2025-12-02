use crate::s3_logger::test_s3_connectivity;
use crate::Enclave;
use crate::S3Logger;
use axum::extract::State;
use axum::Json;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::combine_shares;
use hashi_guardian_shared::crypto::decrypt_share;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::*;
use std::sync::Arc;
use tracing::error;
use tracing::info;
use GuardianError::*;

// Receives S3 API keys & share commitments.
// TODO: Another option is to hard-code the share commitments after the key ceremony is over.
// TODO: Log to S3. Q) what are the must log items for security? Enclave attestation & S3-signing-key. Anything else?
pub async fn init_enclave_internal(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<InitInternalRequest>,
) -> GuardianResult<()> {
    info!("/init_internal - Received request");
    // If the configuration has already been set, return an error
    if enclave.s3_logger().is_ok() {
        return Err(OpaqueError("S3 configuration previously set".into()));
    }

    let logger = S3Logger::new(request.config).await?;

    info!("Testing S3 connectivity...");
    // Test S3 connectivity with the new credentials
    test_s3_connectivity(&logger).await?;

    info!("S3 connectivity test passed");
    info!("Storing S3 configuration...");
    enclave.set_s3_logger(logger)?;

    info!(
        "Storing {} share commitments...",
        request.share_commitments.len()
    );
    for (i, share_commitment) in request.share_commitments.iter().enumerate() {
        info!(
            "Share {}: ID {} Digest {:x?}",
            i, share_commitment.id, share_commitment.digest
        );
    }
    enclave.set_share_commitments(request.share_commitments)?;

    info!("S3 configuration complete!");
    Ok(())
}

// Receives btc key share and a bunch of config's ("state") from each KP.
// While accumulating shares, we use the state hash to compare if every KP is giving us the same state.
// When we have enough shares, we actually set all the state variables.
// TODO: Log to S3. Q) what are the must log items for security?
pub async fn init_enclave_external(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<InitExternalRequest>,
) -> GuardianResult<()> {
    info!("/init_external - Received encrypted share");
    if !enclave.is_init_internal() {
        return Err(InternalError(
            "Internal initialization hasn't completed!".into(),
        ));
    }
    if enclave.is_init_external() {
        return Err(InternalError(
            "External (KP) initialization already complete!".into(),
        ));
    }

    let sk = enclave.encryption_secret_key();
    let share_id = request.encrypted_share.id;
    let state_hash = request.state.digest();
    info!("   Share ID: {:?}", share_id);

    // 1) Decrypt the share!
    info!("Decrypting share...");
    let share = decrypt_share(&request.encrypted_share, sk, Some(&state_hash))?;
    info!("Share decrypted successfully");

    // 2) Verify the share against the commitment
    info!("Verifying share against commitment...");
    let share_commitments = enclave.share_commitments()?;
    verify_share(&share, share_commitments)?;
    info!("Share verified successfully");

    // 3) Set state_hash OR make sure whatever was previously set matches.
    //    Panics upon mismatch.
    info!("Checking state hash...");
    match enclave.state_hash() {
        Some(existing_state_hash) => {
            if *existing_state_hash != state_hash {
                error!("State hash mismatch!");
                panic!("State hash mismatch");
            }
            info!("State hash matches existing");
        }
        None => {
            enclave.set_state_hash(state_hash)?;
            info!("State hash set");
        }
    }

    // MILESTONE: At this point, we are sure it is a legitimate payload (both share & config)!

    // 4) Persist share
    info!("Persisting share...");
    let mut received_share_ids = enclave.scratchpad.received_share_ids.lock().await;
    if !received_share_ids.insert(share.id) {
        return Err(InternalError("Duplicate shares!".into()));
    }
    let mut received_shares = enclave.decrypted_shares().lock().await;
    received_shares.push(share);
    let current_share_count = received_shares.len();
    info!(
        "   Total shares received: {}/{}",
        current_share_count, THRESHOLD
    );

    // 5) If we have enough shares, finish initialization: combine shares & set config.
    if current_share_count >= THRESHOLD {
        let vec: Vec<Share> = received_shares.iter().cloned().collect::<Vec<_>>();
        finalize_init(&vec, &enclave, request.state).await?;
    }

    Ok(())
}

async fn finalize_init(
    shares: &[Share],
    enclave: &Arc<Enclave>,
    incoming_state: InitExternalRequestState,
) -> GuardianResult<()> {
    info!("Threshold reached! Combining shares...");
    let secp_sk = combine_shares(shares)?;

    // TODO: Discuss. Find a better solution for prod?
    let sk_hash = Blake2b::<U32>::digest(secp_sk.secret_bytes());
    info!("Bitcoin key created with fingerprint {:x}", sk_hash);

    info!("Setting private key...");
    enclave.set_bitcoin_key(secp_sk)?;

    info!("Setting withdrawal controls...");
    enclave.set_withdraw_controls_config(incoming_state.withdraw_config)?;

    info!("Setting change address...");
    enclave.set_change_address(&incoming_state.change_address)?;

    info!("Setting enclave state...");
    let mut state = enclave.state().await;
    state.hashi_committee_info = incoming_state.hashi_committee_info;
    state.withdraw_state = incoming_state.withdraw_state;

    info!("ENCLAVE INITIALIZATION COMPLETE!");
    Ok(())
}

fn verify_share(share: &Share, commitments: &[ShareCommitment]) -> GuardianResult<()> {
    let commitment = commit_share(share);
    if commitments.contains(&commitment) {
        Ok(())
    } else {
        Err(InternalError("No matching share found".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::setup_new_key;
    use hashi_guardian_shared::crypto::commit_share;
    use hashi_guardian_shared::crypto::encrypt_share;
    use hashi_guardian_shared::crypto::NUM_OF_SHARES;
    use hashi_guardian_shared::test_utils::*;
    use hpke::Serializable;

    #[tokio::test]
    async fn test_setup_new_key() {
        let (pub_keys, priv_keys) = mock_setup_new_key_request();
        let request: Vec<Vec<u8>> = pub_keys.iter().map(|pk| pk.to_bytes().to_vec()).collect();
        let Json(resp) = setup_new_key(Json(request)).await.unwrap();
        assert_eq!(resp.0.len(), NUM_OF_SHARES);

        for (i, (enc_share, sk)) in resp
            .0
            .iter()
            .zip(priv_keys.iter())
            .enumerate()
            .take(NUM_OF_SHARES)
        {
            let share = decrypt_share(enc_share, sk, None).unwrap();
            let commitment = &resp.1[i];
            assert_eq!(enc_share.id, commitment.id);
            assert_eq!(commit_share(&share), *commitment);
            println!(
                "Received share: (id) {:?}",
                enc_share.id
            );
        }
    }

    #[tokio::test]
    async fn test_init_enclave_external() {
        use crate::Enclave;
        use axum::extract::State;

        // Step 1: Generate KP encryption keys and setup new key
        let (pub_keys, kp_private_keys) = mock_setup_new_key_request();
        let request: Vec<Vec<u8>> = pub_keys.iter().map(|pk| pk.to_bytes().to_vec()).collect();
        let Json(resp) = setup_new_key(Json(request)).await.unwrap();
        let encrypted_shares = resp.0;
        let share_commitments = resp.1;

        // Step 2: Create bare enclave (only S3, no bitcoin key/config since we're testing initialization)
        let enclave = Enclave::create_bare_for_test().await;

        // Step 4: Set share commitments in the enclave
        enclave
            .set_share_commitments(share_commitments.clone())
            .unwrap();

        // Step 5: Create InitExternalRequestState
        let init_state = mock_init_external_state();

        // Step 6: Simulate THRESHOLD KPs calling init_enclave_external
        for i in 0..NUM_OF_SHARES {
            // Re-encrypt the share for the enclave's encryption key
            let share = decrypt_share(&encrypted_shares[i], &kp_private_keys[i], None).unwrap();
            let state_digest = init_state.digest();
            let mut rng = rand::thread_rng();
            let new_encrypted_share =
                encrypt_share(&share, enclave.encryption_public_key(), Some(&state_digest), &mut rng)
                    .unwrap();

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
                    enclave.btc_key().is_ok(),
                    "Bitcoin key should be set after threshold"
                );
                assert!(
                    enclave.withdraw_controls_config().is_ok(),
                    "Withdraw controls config should be set after threshold"
                );
                assert!(
                    enclave.change_address().is_ok(),
                    "Change address should be set after threshold"
                );
            } else if i >= THRESHOLD {
                // After threshold, subsequent init calls should fail
                assert!(
                    result.is_err(),
                    "Should fail at iteration {}: {:?}",
                    i,
                    result
                );
                assert!(enclave.btc_key().is_ok(), "Bitcoin key should still be set");
            } else {
                // Before threshold, call should succeed
                assert!(result.is_ok(), "Init should succeed before threshold");
                assert!(
                    enclave.btc_key().is_err(),
                    "Bitcoin key should not be set before threshold"
                );
                assert!(
                    enclave.withdraw_controls_config().is_err(),
                    "Withdraw controls config should not be set before threshold"
                );
                assert!(
                    enclave.change_address().is_err(),
                    "Change address should not be set before threshold"
                );
            }
        }

        println!("Successfully initialized enclave with {} shares", THRESHOLD);
    }
}
