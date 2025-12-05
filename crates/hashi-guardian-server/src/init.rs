use crate::s3_logger::test_s3_connectivity;
use crate::Enclave;
use crate::S3Logger;
use axum::extract::State;
use axum::Json;
use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest;
use hashi_guardian_shared::crypto::combine_shares;
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::decrypt_share;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::*;
use std::sync::Arc;
use tracing::error;
use tracing::info;
use GuardianError::*;

// Receives S3 API keys & share commitments.
// TODO: Log to S3. Q) what are the must log items for security? Enclave attestation & S3-signing-key. Anything else?
pub async fn operator_init(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<OperatorInitRequest>,
) -> GuardianResult<()> {
    info!("/operator_init - Received request");
    // If the configuration has already been set, return an error
    if enclave.s3_logger().is_ok() {
        return Err(OpaqueError("S3 configuration previously set".into()));
    }

    let logger = S3Logger::new(request.config()).await?;

    info!("Testing S3 connectivity...");
    // Test S3 connectivity with the new credentials
    test_s3_connectivity(&logger).await?;

    info!("S3 connectivity test passed");
    info!("Storing S3 configuration...");
    enclave.set_s3_logger(logger)?;

    info!("Setting bitcoin network to {:?}...", request.network());
    enclave.set_bitcoin_network(request.network())?;

    info!(
        "Storing {} share commitments...",
        request.share_commitments().len()
    );
    for (i, share_commitment) in request.share_commitments().iter().enumerate() {
        info!(
            "Share {}: ID {} Digest {:x?}",
            i, share_commitment.id, share_commitment.digest
        );
    }
    enclave.set_share_commitments(request.share_commitments().to_vec())?;



    info!("S3 configuration complete!");
    Ok(())
}

// Receives btc key share and a bunch of config's ("state") from each KP.
// While accumulating shares, we use the state hash to compare if every KP is giving us the same state.
// When we have enough shares, we actually set all the state variables.
// TODO: Log to S3. Q) what are the must log items for security?
pub async fn provisioner_init(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<ProvisionerInitRequest>,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received encrypted share");
    if !enclave.is_operator_init_complete() {
        return Err(InternalError(
            "Operator initialization hasn't completed!".into(),
        ));
    }
    if enclave.is_provisioner_init_complete() {
        return Err(InternalError(
            "Provisioner (KP) initialization already complete!".into(),
        ));
    }

    let sk = enclave.encryption_secret_key();
    let share_id = request.encrypted_share().id;
    let state_hash = request.state().digest();
    info!("   Share ID: {:?}", share_id);

    // 1) Decrypt the share!
    info!("Decrypting share...");
    let share = decrypt_share(request.encrypted_share(), sk, Some(&state_hash))?;
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
    let mut received_shares = enclave.decrypted_shares().lock().await;
    // Check for duplicate share ID (linear search is fine for 5 shares)
    if received_shares.iter().any(|s| s.id == share.id) {
        return Err(InternalError("Duplicate shares!".into()));
    }
    received_shares.push(share);
    let current_share_count = received_shares.len();
    info!(
        "   Total shares received: {}/{}",
        current_share_count, THRESHOLD
    );

    // 5) If we have enough shares, finish initialization: combine shares & set config.
    if current_share_count >= THRESHOLD {
        let vec: Vec<Share> = received_shares.iter().cloned().collect::<Vec<_>>();
        finalize_init(&vec, &enclave, request.state().clone()).await?;
    }

    Ok(())
}

async fn finalize_init(
    shares: &[Share],
    enclave: &Arc<Enclave>,
    incoming_state: ProvisionerInitRequestState,
) -> GuardianResult<()> {
    info!("Threshold reached! Combining shares...");
    let secp_sk = combine_shares(shares)?;

    // TODO: Discuss. Find a better solution for prod?
    let sk_hash = Blake2b::<U32>::digest(secp_sk.secret_bytes());
    info!("Bitcoin key created with fingerprint {:x}", sk_hash);

    info!("Setting private key...");
    enclave.set_bitcoin_key(secp_sk)?;

    info!("Setting rate limiter...");
    enclave.set_rate_limiter(incoming_state.withdrawal_config.hourly_rate_limit)?;

    info!("Setting withdrawal controls...");
    enclave.set_withdraw_controls_config(incoming_state.withdrawal_config)?;

    info!("Setting change address...");
    enclave.set_change_address(incoming_state.change_address)?;

    info!("Setting enclave state...");
    let mut state = enclave.state().await;
    state.hashi_committee_info = incoming_state.hashi_committee_info;
    state.withdraw_state = incoming_state.withdrawal_state;

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
    use bitcoin::Network;
    use super::*;
    use crate::setup::setup_new_key;
    use hashi_guardian_shared::crypto::NUM_OF_SHARES;

    #[tokio::test]
    async fn test_provisioner_init() {
        use crate::Enclave;
        use axum::extract::State;

        // Step 1: Generate KP encryption keys and setup new key
        let enclave = Enclave::create_with_random_keys();
        let verification_key = &enclave.signing_keypair().verification_key();
        let (request, kp_private_keys) = SetupNewKeyRequest::mock_for_testing();
        let Json(resp) = setup_new_key(State(enclave), Json(request)).await.unwrap();
        let validated_resp = validate_signed_response(verification_key, resp).unwrap();
        let encrypted_shares = validated_resp.encrypted_shares;
        let share_commitments = validated_resp.share_commitments;

        // Step 2: Create bare enclave (only S3, no bitcoin key/config since we're testing initialization)
        let enclave = Enclave::create_partially_initialized(Network::Regtest, &share_commitments).await;

        // Step 3: Create ProvisionerInitRequestState
        let init_state = ProvisionerInitRequestState::mock_for_testing();

        // Step 4: Simulate THRESHOLD KPs calling provisioner_init
        for i in 0..NUM_OF_SHARES {
            // Re-encrypt the share for the enclave's encryption key
            let share = decrypt_share(&encrypted_shares[i], &kp_private_keys[i], None).unwrap();
            let mut rng = rand::thread_rng();
            let request = ProvisionerInitRequest::new(
                &share,
                enclave.encryption_public_key(),
                init_state.clone(),
                &mut rng,
            )
            .unwrap();

            let result = provisioner_init(State(enclave.clone()), Json(request)).await;

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
