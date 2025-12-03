use crate::Enclave;
use crate::MyRateLimiter;
use axum::extract::State;
use axum::Json;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::Signature;
use bitcoin::Address;
use bitcoin::TxOut;
use hashi_guardian_shared::bitcoin_utils::construct_signing_messages;
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::*;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

/// Max allowed gap between hashi-assigned timestamp and enclave's time (5 mins).
const HASHI_GUARDIAN_DELTA: Duration = Duration::from_secs(5 * 60);

pub async fn instant_withdraw(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<InstantWithdrawalRequest>,
) -> GuardianResult<Json<InstantWithdrawalResponse>> {
    // ------------------------ Validation ------------------------
    // Check cert
    validate_instant_withdraw(&request)?;

    // Check that the request was made recently
    validate_time(request.info.timestamp)?;

    // Validate all external addresses against the configured network
    let network = enclave.bitcoin_network();
    let verified_outputs = request
        .info
        .external_dest
        .iter()
        .map(|o| o.validate(network))
        .collect::<Result<Vec<_>, _>>()?;

    // TODO: Validate input UTXOs:
    //   - Verify script_pubkey is P2TR (taproot)
    //   - Verify amounts are non-zero
    //   - Verify other fields in the request

    // ------------------------ Check rate limits / enough delay ------------------------
    let mut enclave_state = enclave.state().await; // LOCK
    if request.delayed {
        // Check if we have seen this request before
        let (min_delay, _) = enclave.min_and_max_delay()?;
        approve_delayed_withdrawal(
            &request.info,
            enclave_state.pending_withdrawals(),
            min_delay,
        )?;
    } else {
        // Apply rate limits
        rate_limit(request.info.out_amount().to_sat(), enclave.rate_limiter()?)?;
    }

    // Check counter.log does not exist on S3 (dup enclave attack prevention)
    let counter: u64 = enclave_state.withdraw_state.counter;
    let log_key = format!("{}.log", counter);
    let s3_logger = enclave.s3_logger()?;
    s3_logger.is_exists(&log_key).await?;

    // ------------------------ Sign transaction ------------------------
    let signatures = sign(
        enclave.btc_key()?,
        &request.info,
        verified_outputs,
        enclave.change_address()?,
    )?;
    let response = InstantWithdrawalResponse {
        enclave_sign: signatures,
    };

    // Log to S3
    s3_logger
        .log(
            "instant_withdraw",
            &log_key,
            &format!("Request {:?}\nResponse {:?}", request, response),
        )
        .await?;

    // Update state
    enclave_state.withdraw_state.counter += 1;
    if request.delayed {
        // Delete relevant info
        enclave_state
            .pending_withdrawals_mut()
            .remove(&request.info.withdrawal_id)
            .ok_or(InternalError(
                "Could not find an earlier delayed withdrawal record".into(),
            ))?;
    }

    Ok(Json(response))
}

// TODO: Add tests
fn rate_limit(satoshis: u64, rate_limiter: &MyRateLimiter) -> GuardianResult<()> {
    // TODO: Discuss and align the rate limiting logic with others
    const UNIT_SIZE: u64 = 10_000;
    let cost = (satoshis / UNIT_SIZE).max(1);
    if cost > u32::MAX as u64 {
        // Rejects amounts greater than about 400k BTC
        return Err(InternalError("Amount too high".into()));
    }
    let x = NonZeroU32::new(cost as u32)
        .ok_or(InternalError("Zero amount? This shouldn't happen.".into()))?;
    rate_limiter
        .check_n(x)
        .map_err(|_| InternalError("Withdrawing more than the burst limit".into()))?
        .map_err(|_| InternalError("Withdraw after some time".into()))
    // TODO: Improve the second error message indicating when this call can be next made.
}

/// Sign a BTC tx. Errors out if there is no change amount.
/// TODO: Ensure change_amount is within expected range?
fn sign(
    sk: &SecretKey,
    request: &InstantWithdrawalInfo,
    verified_outputs: Vec<ValidatedWithdrawalOutput>,
    change_address: Address,
) -> GuardianResult<Vec<Signature>> {
    // Derive change amount
    let change_utxo = TxOut {
        value: request.change_amount()?,
        script_pubkey: change_address.script_pubkey(),
    };

    // Convert output WithdrawOutputs to TxOuts
    let output_txouts: Vec<TxOut> = verified_outputs.iter().map(|wo| wo.into()).collect();

    // Construct signing messages
    let messages = construct_signing_messages(&request.input_utxos, &output_txouts, &change_utxo)?;

    // Sign with the secret key
    sign_btc_tx(&messages, sk)
}

fn validate_instant_withdraw(_request: &InstantWithdrawalRequest) -> GuardianResult<()> {
    // TODO
    Ok(())
}

fn validate_time(request_time: SystemTime) -> GuardianResult<()> {
    let cur_time = SystemTime::now();
    let duration = cur_time
        .duration_since(request_time)
        .map_err(|_| InternalError("Time is earlier".into()))?;
    if duration > HASHI_GUARDIAN_DELTA {
        Err(InternalError("Request too old".into()))
    } else {
        Ok(())
    }
}

pub async fn delayed_withdraw(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<DelayedWithdrawalRequest>,
) -> GuardianResult<()> {
    // -------- Validation --------
    // Check cert
    validate_delayed_withdraw(&request)?;

    // Check if the request is sufficiently recent
    validate_time(request.info.timestamp)?;

    // Validate all external addresses against the configured network
    let network = enclave.bitcoin_network();
    for output in &request.info.external_dest {
        output.validate(network)?;
    }

    // -------- Record --------
    // Log to S3. Note that we need to log to S3 and then update internal state in that order
    //   as the enclave may die between the two steps.
    let log_key = &request.info.withdrawal_id;
    let s3_logger = enclave.s3_logger()?;
    s3_logger
        .log(
            "delayed_withdraw",
            log_key,
            &format!("Request {:?}", request),
        )
        .await?;

    // Store internally
    let mut enclave_state = enclave.state().await;
    if let Some(x) = enclave_state
        .withdraw_state
        .pending_delayed_withdrawals
        .insert(request.info.withdrawal_id.clone(), request.info)
    {
        return Err(InternalError(format!(
            "Withdraw ID already exists: {:?}",
            x
        )));
    }
    Ok(())
}

fn validate_delayed_withdraw(_request: &DelayedWithdrawalRequest) -> GuardianResult<()> {
    // TODO
    Ok(())
}

/// Approves withdrawal if a delayed_withdraw request was made sufficiently earlier
fn approve_delayed_withdrawal(
    withdrawal: &InstantWithdrawalInfo,
    pending_withdrawals: &HashMap<WithdrawalID, DelayedWithdrawalInfo>,
    min_delay: Duration,
) -> GuardianResult<()> {
    // Find the matching record
    let pending = match pending_withdrawals.get(&withdrawal.withdrawal_id) {
        Some(x) => x,
        None => {
            return Err(InternalError(
                "Could not find an earlier delayed withdrawal record".into(),
            ))
        }
    };

    // Check the dest (both address and amount)
    if pending.external_dest != withdrawal.external_dest {
        return Err(InternalError(format!(
            "WithdrawID matches but external destination \
                                         does not match {:?} {:?}",
            pending.external_dest, withdrawal.external_dest
        )));
    }

    // Check that the gap is sufficiently long
    let gap = withdrawal
        .timestamp
        .duration_since(pending.timestamp)
        .map_err(|_| InternalError("Time is earlier".into()))?;
    if gap < min_delay {
        Err(InternalError(format!(
            "Withdrawal timestamp {:?} is not sufficiently delayed ({:?} + {:?})",
            withdrawal.timestamp, pending.timestamp, min_delay
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Enclave;
    use axum::extract::State;
    use hashi_guardian_shared::test_utils::*;

    #[test]
    fn test_validate_time() {
        let recent_time = SystemTime::now();
        assert!(validate_time(recent_time).is_ok());

        let old_time = SystemTime::now() - Duration::from_secs(600); // 10 minutes ago
        assert!(validate_time(old_time).is_err());

        // Time in the future should error
        let future_time = SystemTime::now() + Duration::from_secs(100);
        assert!(validate_time(future_time).is_err());
    }

    #[tokio::test]
    async fn test_delayed_withdraw_e2e_flow() {
        // Create enclave with 10-second min delay
        let enclave = Enclave::create_for_test_with_min_delay(Some(Duration::from_secs(10))).await;

        let withdraw_id = "test_e2e_delayed".to_string();
        let output = create_test_withdraw_output(100_000);
        let initial_timestamp = SystemTime::now();

        // Step 1: Submit delayed withdrawal request
        let delayed_request = DelayedWithdrawalRequest {
            info: DelayedWithdrawalInfo {
                withdrawal_id: withdraw_id.clone(),
                external_dest: vec![output.clone()],
                timestamp: initial_timestamp,
            },
            cert: HashiCert {},
        };

        let result = delayed_withdraw(State(enclave.clone()), Json(delayed_request)).await;
        assert!(result.is_ok(), "Delayed withdrawal request should succeed");

        // Verify it was stored
        {
            let state = enclave.state().await;
            assert!(state
                .withdraw_state
                .pending_delayed_withdrawals
                .contains_key(&withdraw_id));
        }

        // Step 2: Try instant withdrawal immediately (before min_delay) - should FAIL
        // Wait 5 seconds to get past the initial timestamp but still within the 5-minute validation window
        tokio::time::sleep(Duration::from_secs(5)).await;

        let instant_request_early = InstantWithdrawalRequest {
            info: InstantWithdrawalInfo {
                withdrawal_id: withdraw_id.clone(),
                external_dest: vec![output.clone()],
                timestamp: SystemTime::now(), // Current time (5 seconds after initial)
                input_utxos: vec![create_test_utxo(110_000)],
                fee_sats: 1_000,
            },
            delayed: true,
            cert: HashiCert {},
        };

        let result_early =
            instant_withdraw(State(enclave.clone()), Json(instant_request_early)).await;
        assert!(
            result_early.is_err(),
            "Instant withdrawal before min_delay should fail"
        ); // TODO: Check error type after improving error handling

        // Verify pending withdrawal is still there
        {
            let state = enclave.state().await;
            assert!(
                state
                    .withdraw_state
                    .pending_delayed_withdrawals
                    .contains_key(&withdraw_id),
                "Pending withdrawal should still exist after failed instant withdrawal"
            );
        }

        // Step 3: Wait for remaining time to reach min_delay (5 more seconds)
        println!("⏳ Waiting 5 more seconds to reach min_delay...");
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Step 4: Try instant withdrawal after delay - should SUCCEED
        let instant_request_after = InstantWithdrawalRequest {
            info: InstantWithdrawalInfo {
                withdrawal_id: withdraw_id.clone(),
                external_dest: vec![output],
                timestamp: SystemTime::now(), // Now timestamp is well past min_delay
                input_utxos: vec![create_test_utxo(110_000)],
                fee_sats: 1_000,
            },
            delayed: true,
            cert: HashiCert {},
        };

        let result_after =
            instant_withdraw(State(enclave.clone()), Json(instant_request_after)).await;
        assert!(
            result_after.is_ok(),
            "Instant withdrawal after min_delay should succeed: {:?}",
            result_after
        );

        // Verify we got signatures back
        if let Ok(Json(response)) = result_after {
            assert_eq!(
                response.enclave_sign.len(),
                1,
                "Should have one signature for one input"
            );
        }

        // Verify pending withdrawal was removed
        {
            let state = enclave.state().await;
            assert!(
                !state
                    .withdraw_state
                    .pending_delayed_withdrawals
                    .contains_key(&withdraw_id),
                "Pending withdrawal should be removed after successful instant withdrawal"
            );
        }

        // Verify counter was incremented
        {
            let state = enclave.state().await;
            assert_eq!(
                state.withdraw_state.counter, 1,
                "Counter should be incremented after withdrawal"
            );
        }
    }

    // TODO: Add e2e tests for instant_withdraw to test rate limits

    mod rate_limit_tests {
        use super::*;
        use governor::Quota;
        use governor::RateLimiter;
        use nonzero_ext::nonzero;

        fn setup_rate_limiter() -> MyRateLimiter {
            // A bucket of max size 1 BTC with a continuous refill rate of 1 BTC per hour
            RateLimiter::direct(Quota::per_minute(nonzero!(100_000_000u32)))
        }

        #[test]
        fn test_basic() {
            {
                let r = setup_rate_limiter();
                let out = r.check_n(nonzero!(100_000_000u32));
                assert!(out.is_ok() && out.unwrap().is_ok());
            }

            {
                let r = setup_rate_limiter();
                let out = r.check_n(nonzero!(100_000_001u32));
                // Can never pass
                assert!(out.is_err());
            }

            {
                let r = setup_rate_limiter();
                let out = r.check_n(nonzero!(100_000_000u32));
                assert!(out.is_ok() && out.unwrap().is_ok());
                let out = r.check_n(nonzero!(100_000_000u32));
                println!("{:?}", out);
                assert!(out.is_ok() && out.unwrap().is_err());
            }
        }
    }
}
