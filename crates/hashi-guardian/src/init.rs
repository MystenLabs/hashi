// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::getters::get_attestation;
use crate::Enclave;
use crate::S3Logger;
use hashi_types::guardian::crypto::combine_shares;
use hashi_types::guardian::crypto::commit_share;
use hashi_types::guardian::crypto::decrypt_share;
use hashi_types::guardian::crypto::Share;
use hashi_types::guardian::s3_utils::S3HourScopedDirectory;
use hashi_types::guardian::time_utils::now_timestamp_secs;
use hashi_types::guardian::InitLogMessage::OIAttestationUnsigned;
use hashi_types::guardian::InitLogMessage::OIGuardianInfo;
use hashi_types::guardian::InitLogMessage::PIEnclaveFullyInitialized;
use hashi_types::guardian::InitLogMessage::PISuccess;
use hashi_types::guardian::*;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use tracing::warn;
use GuardianError::*;

/// How many hour-scoped directories back we scan when rehydrating the
/// wid-keyed response cache from prior-session withdrawal logs. Matches
/// the Object Lock retention window for withdrawal logs (see
/// `S3_OBJECT_LOCK_DURATION_WITHDRAW`) so we never try to read a
/// directory whose entries have expired out from under us.
const REHYDRATE_LOG_HOURS: u64 = 2;

/// Receives S3 API keys & share commitments.
/// Returns an error for malformed requests / dup call & panics for the rest.
pub async fn operator_init(
    enclave: Arc<Enclave>,
    request: OperatorInitRequest,
) -> GuardianResult<()> {
    info!("/operator_init - Received request.");

    // Validation
    if enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Operator init finished".into()));
    }
    if enclave.is_operator_init_partially_complete() {
        // shouldn't reach inside as we panic
        unreachable!("Operator init did not fully complete.");
    }
    info!("Enclave state validated.");

    let (config, commitments, network) = request.into_parts();
    let logger = S3Logger::new_checked(&config).await?;
    info!("S3 connectivity check complete.");

    info!("Storing S3 configuration.");
    enclave
        .config
        .set_s3_logger(logger)
        .expect("Unable to set logger");

    info!("Setting bitcoin network to {:?}.", network);
    enclave
        .config
        .set_bitcoin_network(network)
        .expect("Unable to set network");

    info!("Storing {} share commitments.", commitments.len());
    for (i, share_commitment) in commitments.iter().enumerate() {
        info!(
            "Share {}: ID {} Digest {:x?}.",
            i, share_commitment.id, share_commitment.digest
        );
    }
    enclave
        .set_share_commitments(commitments)
        .expect("Unable to set share commitments");

    // Log to S3!
    // 1) Attestation and pub key help authenticate all subsequent enclave-signed messages.
    let signing_pk = enclave.signing_pubkey();
    enclave
        .log_init(OIAttestationUnsigned {
            attestation: get_attestation(&signing_pk).expect("Unable to get attestation"),
            signing_public_key: signing_pk,
        })
        .await
        .expect("Unable to log OperatorInitAttestationUnsigned");

    // 2) Share commitments help KPs confirm that the right private key will be constructed.
    enclave
        .log_init(OIGuardianInfo(enclave.info()))
        .await
        .expect("Unable to log GuardianInfo");

    enclave
        .scratchpad
        .operator_init_logging_complete
        .set(())
        .expect("operator_init_logging_complete should only be set once");

    info!("Operator initialization complete.");
    Ok(())
}

/// Receives btc key share and a bunch of config's ("state") from each KP.
/// While accumulating shares, we use the state hash to compare if every KP is giving us the same state.
/// When we have enough shares, we actually set all the state variables.
pub async fn provisioner_init(
    enclave: Arc<Enclave>,
    request: ProvisionerInitRequest,
) -> GuardianResult<()> {
    info!("/provisioner_init - Received request.");

    // Ensure only one provisioner_init request runs at a time to keep things simple.
    // We reuse the decrypted_shares mutex lock for this purpose.
    let mut received_shares = enclave.decrypted_shares().lock().await;

    // Validation
    if !enclave.is_operator_init_complete() {
        return Err(InvalidInputs("Do operator init first".into()));
    }
    if enclave.is_provisioner_init_complete() {
        return Err(InvalidInputs("Provisioner init already complete".into()));
    }
    if enclave.is_provisioner_init_partially_complete() {
        debug_assert!(
            false,
            "provisioner_init partially complete; this should not happen"
        );
        return Err(InvalidInputs("Provisioner init partially complete".into()));
    }
    info!("Enclave state validated.");

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

    // 3) Set state_hash OR make sure whatever was previously set matches. Panics upon mismatch.
    info!("Checking state hash.");
    match enclave.state_hash() {
        Some(existing_state_hash) if *existing_state_hash != state_hash => {
            panic!("State hash mismatch")
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

    // Note: This S3 log does not serve any security purpose.
    enclave
        .log_init(PISuccess {
            share_id,
            state_hash,
        })
        .await
        .expect("Unable to log ProvisionerInitSuccess");

    // 5) If we have enough shares, finish initialization: combine shares & set config
    if current_share_count >= THRESHOLD {
        let shares_vec: Vec<Share> = received_shares.iter().cloned().collect();
        finalize_init(&shares_vec, &enclave, request.into_state()).await;

        // Rehydrate the wid-keyed response cache from prior-session
        // withdrawal logs BEFORE we start serving withdrawals. Retries
        // of prior-session wids will hit the cache and return the
        // (re-signed) response instead of going through consume again
        // — preventing double debits across a guardian restart. The
        // KP-side rehydration of `LimiterState` already guarantees
        // `next_seq` is correct; this closes the remaining gap.
        if let Err(e) = rehydrate_response_cache(&enclave).await {
            warn!(
                error = %e,
                "Response cache rehydration failed; proceeding with empty cache. \
                 Retries of prior-session withdrawals may be rejected.",
            );
        }

        // Log to S3 indicating that withdrawals can be expected henceforth
        enclave
            .log_init(PIEnclaveFullyInitialized)
            .await
            .expect("Unable to log EnclaveFullyInitialized");

        enclave
            .scratchpad
            .provisioner_init_logging_complete
            .set(())
            .expect("provisioner_init_logging_complete should only be set once");
    }

    Ok(())
}

/// Read prior-session withdrawal success logs from S3 and repopulate the
/// current session's wid-keyed response cache.
///
/// Each cached entry is re-signed with the new session's Ed25519 key,
/// so clients that fetch the current guardian's signing pubkey and
/// verify responses will accept them. Errors are non-fatal — a cache
/// miss at most causes a double-debit on retry, which is the same
/// behavior we had before this function existed.
async fn rehydrate_response_cache(enclave: &Arc<Enclave>) -> GuardianResult<()> {
    let logger = enclave.config.s3_logger()?;
    let current_session_id = enclave.s3_session_id();
    let start_secs = now_timestamp_secs().saturating_sub(REHYDRATE_LOG_HOURS * 60 * 60);

    // Resolve the signing pubkey of each prior session we will read logs
    // from. We ignore sessions whose attestation can't be fetched —
    // logs we can't verify get skipped rather than trusted blindly.
    let prior_session_pubkeys =
        resolve_prior_session_pubkeys(logger, &current_session_id, start_secs).await?;
    if prior_session_pubkeys.is_empty() {
        info!("No prior sessions detected for response-cache rehydration");
        return Ok(());
    }

    let mut rehydrated = 0usize;
    for hour in 0..=REHYDRATE_LOG_HOURS {
        let dir = S3HourScopedDirectory::new(S3_DIR_WITHDRAW, start_secs + hour * 60 * 60);
        let logs = match logger.list_all_objects_in_dir::<LogRecord>(&dir).await {
            Ok(logs) => logs,
            Err(e) => {
                warn!(
                    dir = %dir,
                    error = %e,
                    "Skipping withdrawal log directory during cache rehydration",
                );
                continue;
            }
        };
        for log in logs {
            let Some(pubkey) = prior_session_pubkeys.get(&log.session_id) else {
                continue;
            };
            let verified = match log.verify(pubkey) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        session_id = %pubkey_session(pubkey),
                        error = ?e,
                        "Skipping unverifiable withdrawal log during cache rehydration",
                    );
                    continue;
                }
            };
            let LogMessage::Withdrawal(withdrawal_message) = verified.message else {
                continue;
            };
            let WithdrawalLogMessage::Success {
                request_data,
                response,
                ..
            } = *withdrawal_message
            else {
                continue;
            };
            // Re-sign with the CURRENT session's key so clients that
            // verify against the new guardian pubkey accept the response.
            let signed = enclave.sign(response);
            enclave.state.cache_response(request_data.wid, signed);
            rehydrated += 1;
        }
    }

    info!(
        rehydrated,
        "Rehydrated wid-keyed response cache from prior-session logs"
    );
    Ok(())
}

/// For every prior session whose heartbeats we can see in the recent
/// window, fetch its OperatorInit attestation and return its Ed25519
/// signing pubkey. Sessions whose attestation is unavailable are
/// silently skipped (we'd be unable to verify their logs anyway).
async fn resolve_prior_session_pubkeys(
    logger: &S3Logger,
    current_session_id: &str,
    start_secs: u64,
) -> GuardianResult<HashMap<String, GuardianPubKey>> {
    let mut session_ids = std::collections::HashSet::new();
    for hour in 0..=REHYDRATE_LOG_HOURS {
        let dir = S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, start_secs + hour * 60 * 60);
        let logs = match logger.list_all_objects_in_dir::<LogRecord>(&dir).await {
            Ok(logs) => logs,
            Err(_) => continue,
        };
        for log in logs {
            if log.session_id != current_session_id {
                session_ids.insert(log.session_id);
            }
        }
    }

    let mut out = HashMap::new();
    for session_id in session_ids {
        match logger.get_attestation(&session_id).await {
            Ok((_attestation, pubkey)) => {
                out.insert(session_id, pubkey);
            }
            Err(e) => {
                warn!(
                    session_id,
                    error = %e,
                    "Could not resolve prior session signing pubkey; logs from this session will be skipped",
                );
            }
        }
    }
    Ok(out)
}

fn pubkey_session(pubkey: &GuardianPubKey) -> String {
    session_id_from_signing_pubkey(pubkey)
}

/// Finalize the initialization process.
/// Panics upon an error as the enclaves state is irrecoverable at this point.
async fn finalize_init(
    shares: &[Share],
    enclave: &Arc<Enclave>,
    incoming_state: ProvisionerInitState,
) {
    info!("Threshold reached, combining shares.");
    let enclave_btc_keypair = combine_shares(shares).expect("Unable to combine shares");

    info!("Setting enclave keypair.");
    enclave
        .config
        .set_btc_keypair(enclave_btc_keypair)
        .expect("Unable to set enclave keypair");

    info!("Setting hashi public key.");
    enclave
        .config
        .set_hashi_btc_pk(incoming_state.hashi_btc_master_pubkey())
        .expect("Unable to set hashi public key");

    info!("Setting withdraw config.");
    enclave
        .config
        .set_withdrawal_config(*incoming_state.withdrawal_config())
        .expect("Unable to set withdraw config");

    info!("Setting enclave mutable state.");
    enclave
        .state
        .init(incoming_state)
        .expect("Unable to init state");

    info!("Enclave initialization complete.");
}

fn verify_share(share: &Share, commitments: &ShareCommitments) -> GuardianResult<()> {
    commitments
        .contains(&commit_share(share))
        .then_some(())
        .ok_or_else(|| InvalidInputs("No matching share found".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperatorInitTestArgs;
    use hashi_types::guardian::crypto::NUM_OF_SHARES;
    use hashi_types::guardian::test_utils::create_btc_keypair;
    use k256::SecretKey;

    /// Helper: Generate test shares and initialized enclave
    /// Returns (shares, enclave)
    async fn setup_test_shares_and_enclave() -> (Vec<Share>, Arc<Enclave>) {
        let sk = SecretKey::random(&mut rand::thread_rng());
        let shares = split_secret(&sk, &mut rand::thread_rng());
        let share_commitments = ShareCommitments::from_shares(&shares).unwrap();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_commitments(share_commitments),
        )
        .await;
        (shares, enclave)
    }

    #[tokio::test]
    async fn test_provisioner_init() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let init_state = ProvisionerInitState::mock_for_testing(None);

        // Simulate THRESHOLD KPs calling provisioner_init
        for (i, share) in shares.iter().enumerate().take(NUM_OF_SHARES) {
            let request = ProvisionerInitRequest::build_from_share_and_state(
                share,
                enclave.encryption_public_key(),
                init_state.clone(),
                &mut rand::thread_rng(),
            );

            let result = provisioner_init(enclave.clone(), request).await;

            // Check behavior based on whether we've reached/exceeded threshold
            if i == THRESHOLD - 1 {
                // At exactly threshold (first time), call should succeed
                assert!(
                    result.is_ok(),
                    "Should succeed at threshold (iteration {})",
                    i
                );
                assert!(
                    enclave.config.enclave_btc_keypair.get().is_some(),
                    "Bitcoin key should be set after threshold"
                );
                assert!(
                    enclave.config.hashi_btc_master_pubkey.get().is_some(),
                    "Hashi BTC key should be set after threshold"
                );
            } else if i >= THRESHOLD {
                // After threshold, subsequent init calls should fail
                assert!(
                    result.is_err(),
                    "Should fail at iteration {}: {:?}",
                    i,
                    result
                );
                assert!(
                    enclave.config.enclave_btc_keypair.get().is_some(),
                    "Bitcoin key should still be set"
                );
            } else {
                // Before threshold, call should succeed
                assert!(result.is_ok(), "Init should succeed before threshold");
                assert!(
                    enclave.config.enclave_btc_keypair.get().is_none(),
                    "Bitcoin key should not be set before threshold"
                );
                assert!(
                    enclave.config.hashi_btc_master_pubkey.get().is_none(),
                    "Hashi BTC key should not be set before threshold"
                );
            }
        }

        println!("Successfully initialized enclave with {} shares", THRESHOLD);
    }

    #[tokio::test]
    async fn test_provisioner_init_before_operator_init() {
        // Create enclave without operator init
        let enclave = Enclave::create_with_random_keys();

        let init_state = ProvisionerInitState::mock_for_testing(None);
        let share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::ONE,
        };
        let mut rng = rand::thread_rng();
        let request = ProvisionerInitRequest::build_from_share_and_state(
            &share,
            enclave.encryption_public_key(),
            init_state,
            &mut rng,
        );

        let result = provisioner_init(enclave, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    #[should_panic = "State hash mismatch"]
    async fn test_provisioner_init_state_hash_mismatch() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;

        // First KP sends with state1
        let state1 = ProvisionerInitState::mock_for_testing(None);
        let request1 = ProvisionerInitRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state1.clone(),
            &mut rand::thread_rng(),
        );
        provisioner_init(enclave.clone(), request1).await.unwrap();

        // Second KP tries to send with different state (different pub key)
        let kp = create_btc_keypair(&[7u8; 32]);
        let state2 = ProvisionerInitState::mock_for_testing(Some(kp));
        assert_ne!(
            state1.hashi_btc_master_pubkey(),
            state2.hashi_btc_master_pubkey()
        );
        let request2 = ProvisionerInitRequest::build_from_share_and_state(
            &shares[1],
            enclave.encryption_public_key(),
            state2,
            &mut rand::thread_rng(),
        );

        // This should panic with "State hash mismatch"
        provisioner_init(enclave, request2).await.unwrap();
    }

    #[tokio::test]
    async fn test_provisioner_init_invalid_share() {
        let (_shares, enclave) = setup_test_shares_and_enclave().await;

        // Create a bogus share that won't match any commitment
        let bogus_share = Share {
            id: std::num::NonZeroU16::new(1).unwrap(),
            value: k256::Scalar::from(42u32), // Random value that won't match commitment
        };
        let state = ProvisionerInitState::mock_for_testing(None);
        let request = ProvisionerInitRequest::build_from_share_and_state(
            &bogus_share,
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        );

        let result = provisioner_init(enclave, request).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }

    #[tokio::test]
    async fn test_provisioner_init_duplicate_share() {
        let (shares, enclave) = setup_test_shares_and_enclave().await;
        let state = ProvisionerInitState::mock_for_testing(None);

        // Send first share
        let request1 = ProvisionerInitRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state.clone(),
            &mut rand::thread_rng(),
        );
        provisioner_init(enclave.clone(), request1)
            .await
            .expect("should not fail");

        // Try to send the same share again (duplicate ID)
        let request2 = ProvisionerInitRequest::build_from_share_and_state(
            &shares[0],
            enclave.encryption_public_key(),
            state,
            &mut rand::thread_rng(),
        );
        let result = provisioner_init(enclave, request2).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), InvalidInputs(_)));
    }
}
