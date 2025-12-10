use crate::getters::get_attestation_inner;
use crate::Enclave;
use crate::S3Logger;
use axum::extract::State;
use axum::Json;
use hashi_guardian_shared::crypto::combine_shares;
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::decrypt_share;
use hashi_guardian_shared::crypto::Share;
use hashi_guardian_shared::*;
use std::sync::Arc;
use tracing::info;
use GuardianError::*;

/// Receives S3 API keys & share commitments.
pub async fn operator_init(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<OperatorInitRequest>,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");
    // Validation
    if enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Operator init finished".into()));
    }
    if enclave.is_operator_init_partially_complete() {
        panic!("Operator init did not fully complete. Restart!");
    }
    request.validate()?; // check we have received enough share commitments
    info!("Request and enclave state validated.");

    let logger = S3Logger::new(request.config()).await?;

    info!("Storing S3 configuration.");
    enclave.set_s3_logger(logger)?;

    info!("Setting bitcoin network to {:?}.", request.network());
    enclave.set_bitcoin_network(request.network())?;

    info!(
        "Storing {} share commitments.",
        request.share_commitments().len()
    );
    for (i, share_commitment) in request.share_commitments().iter().enumerate() {
        info!(
            "Share {}: ID {} Digest {:x?}.",
            i, share_commitment.id, share_commitment.digest
        );
    }
    enclave.set_share_commitments(request.share_commitments().to_vec())?;

    // Log to S3!
    // 1) Attestation and pub key help authenticate all subsequent enclave-signed messages.
    let signing_pk = enclave.signing_pubkey();
    enclave
        .timestamp_and_log(LogMessage::OperatorInitAttestationUnsigned {
            attestation: get_attestation_inner(&signing_pk)?,
            signing_public_key: signing_pk,
        })
        .await?;

    // 2) Share commitments help KPs confirm that the right private key will be constructed.
    enclave
        .sign_and_log(LogMessage::OperatorInitShareCommitments(
            request.share_commitments().to_vec(),
        ))
        .await?;

    info!("Operator initialization complete.");
    Ok(())
}

/// Receives btc key share and a bunch of config's ("state") from each KP.
/// While accumulating shares, we use the state hash to compare if every KP is giving us the same state.
/// When we have enough shares, we actually set all the state variables.
pub async fn provisioner_init(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<ProvisionerInitRequest>,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Validation: ensure enclave is in the right state & request is as expected
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Do operator init first".into()));
    }
    if enclave.is_provisioner_init_complete() {
        return Err(InvalidInputs("Provisioner init already complete".into()));
    }
    if enclave.is_provisioner_init_partially_complete() {
        panic!("Provisioner init partially complete. Restart!");
    }
    let network = enclave
        .bitcoin_network()
        .expect("btc network should be set after operator_init");
    request.state().validate(network)?;
    info!("Request and enclave state validated.");

    let sk = enclave.encryption_secret_key();
    let share_id = request.encrypted_share().id;
    let state_hash = request.state().digest();
    info!("Share ID: {:?}.", share_id);

    // 1) Decrypt the share
    info!("Decrypting share.");
    let share = decrypt_share(request.encrypted_share(), sk, Some(&state_hash))?;
    info!("Share decrypted.");

    // 2) Verify the share against the commitment
    info!("Verifying share against commitment.");
    let share_commitments = enclave
        .share_commitments()
        .expect("share commitments should be set after operator_init");
    verify_share(&share, share_commitments)?;
    info!("Share verified.");

    // 3) Set state_hash OR make sure whatever was previously set matches. Errors upon mismatch.
    info!("Checking state hash.");
    match enclave.state_hash() {
        Some(existing_state_hash) if *existing_state_hash != state_hash => {
            return Err(InvalidInputs("State hash mismatch".into()));
        }
        Some(_) => info!("State hash matches existing."),
        None => {
            enclave.set_state_hash(state_hash)?;
            info!("State hash set.");
        }
    }

    // MILESTONE: At this point, we are sure it is a legitimate payload (both share & config)

    // 4) Persist share
    info!("Persisting share.");
    let mut received_shares = enclave.decrypted_shares().lock().await;
    let share_id = share.id;
    // Check for duplicate share ID (linear search is fine for small share count)
    if received_shares.iter().any(|s| s.id == share_id) {
        return Err(InvalidInputs("Duplicate share ID".into()));
    }
    received_shares.push(share);
    let current_share_count = received_shares.len();
    info!(
        "Total shares received: {}/{}.",
        current_share_count, THRESHOLD
    );
    // TODO: This S3 log does not serve any security purpose: should we omit it?
    enclave
        .sign_and_log(LogMessage::ProvisionerInitSuccess {
            share_id,
            state_hash,
        })
        .await?;

    // 5) If we have enough shares, finish initialization: combine shares & set config
    if current_share_count >= THRESHOLD {
        let shares_vec: Vec<Share> = received_shares.iter().cloned().collect();
        finalize_init(&shares_vec, &enclave, request.into_state()).await?;
    }

    Ok(())
}

async fn finalize_init(
    shares: &[Share],
    enclave: &Arc<Enclave>,
    incoming_state: ProvisionerInitRequestState,
) -> GuardianResult<()> {
    info!("Threshold reached, combining shares.");
    let secp_sk = combine_shares(shares)?;

    info!("Setting private key.");
    enclave.set_bitcoin_key(secp_sk)?;

    info!("Setting change address.");
    enclave.set_change_address(incoming_state.change_address)?;

    info!("Setting enclave state.");
    let mut state = enclave.state().await;
    state.hashi_committee_info = incoming_state.hashi_committee_info;

    // Log to S3 indicating that withdrawals can be expected henceforth
    enclave
        .sign_and_log(LogMessage::EnclaveFullyInitialized)
        .await?;

    info!("Enclave initialization complete.");
    Ok(())
}

fn verify_share(share: &Share, commitments: &[ShareCommitment]) -> GuardianResult<()> {
    commitments
        .contains(&commit_share(share))
        .then_some(())
        .ok_or_else(|| InvalidInputs("No matching share found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use hashi_guardian_shared::crypto::NUM_OF_SHARES;
    use k256::SecretKey;

    /// Helper: Generate test shares and initialized enclave
    /// Returns (shares, enclave)
    async fn setup_test_shares_and_enclave() -> (Vec<Share>, Arc<Enclave>) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let shares = split_secret(&sk, &mut rand::thread_rng());
        let share_commitments: Vec<ShareCommitment> = shares.iter().map(commit_share).collect();
        let enclave =
            Enclave::create_operator_initialized(Network::Regtest, &share_commitments).await;
        (shares, enclave)
    }

    #[tokio::test]
    async fn test_provisioner_init() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let init_state = ProvisionerInitRequestState::mock_for_testing();

        // Simulate THRESHOLD KPs calling provisioner_init
        for (i, share) in shares.iter().enumerate().take(NUM_OF_SHARES) {
            let request = ProvisionerInitRequest::new(
                share,
                enclave.encryption_public_key(),
                init_state.clone(),
                &mut rand::thread_rng(),
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
                    enclave.change_address().is_err(),
                    "Change address should not be set before threshold"
                );
            }
        }

        println!("Successfully initialized enclave with {} shares", THRESHOLD);
    }

    #[tokio::test]
    async fn test_provisioner_init_before_operator_init() {
        // Create enclave without operator init
        let enclave = Enclave::create_with_random_keys();

        let init_state = ProvisionerInitRequestState::mock_for_testing();
        let share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::ONE,
        };
        let mut rng = rand::thread_rng();
        let request = ProvisionerInitRequest::new(
            &share,
            enclave.encryption_public_key(),
            init_state,
            &mut rng,
        )
        .unwrap();

        let result = provisioner_init(State(enclave), Json(request)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_state_hash_mismatch() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // First KP sends with state1
        let state1 = ProvisionerInitRequestState::mock_for_testing();
        let request1 = ProvisionerInitRequest::new(
            &shares[0],
            enclave.encryption_public_key(),
            state1,
            &mut rand::thread_rng(),
        )
        .unwrap();
        provisioner_init(State(enclave.clone()), Json(request1))
            .await
            .unwrap();

        // Second KP tries to send with different state (different change address)
        let mut state2 = ProvisionerInitRequestState::mock_for_testing();
        state2.change_address = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
            .to_string()
            .parse()
            .unwrap();
        let request2 = ProvisionerInitRequest::new(
            &shares[1],
            enclave.encryption_public_key(),
            state2,
            &mut rand::thread_rng(),
        )
        .unwrap();

        let result = provisioner_init(State(enclave), Json(request2)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_invalid_share() {
        let (_shares, enclave) = setup_test_shares_and_enclave().await;

        // Create a bogus share that won't match any commitment
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32), // Random value that won't match commitment
        };
        let state = ProvisionerInitRequestState::mock_for_testing();
        let request = ProvisionerInitRequest::new(
            &bogus_share,
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        )
        .unwrap();

        let result = provisioner_init(State(enclave), Json(request)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_duplicate_share() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let state = ProvisionerInitRequestState::mock_for_testing();

        // Send first share
        let request1 = ProvisionerInitRequest::new(
            &shares[0],
            enclave.encryption_public_key(),
            state.clone(),
            &mut rand::thread_rng(),
        )
        .unwrap();
        provisioner_init(State(enclave.clone()), Json(request1))
            .await
            .unwrap();

        // Try to send the same share again (duplicate ID)
        let request2 = ProvisionerInitRequest::new(
            &shares[0],
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        )
        .unwrap();
        let result = provisioner_init(State(enclave), Json(request2)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_wrong_network() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // KP sends testnet address (enclave expects regtest)
        let mut state = ProvisionerInitRequestState::mock_for_testing();
        state.change_address = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
            .to_string()
            .parse()
            .unwrap();

        let request = ProvisionerInitRequest::new(
            &shares[0],
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        )
        .unwrap();

        let result = provisioner_init(State(enclave), Json(request)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }
}
