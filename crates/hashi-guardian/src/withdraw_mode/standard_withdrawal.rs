// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::verify_hashi_cert;
use crate::Enclave;
use bitcoin::Txid;
use hashi_types::committee::certificate_threshold;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::EnclaveUninitialized;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::RateLimiter;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalRequestWire;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;
use tracing::error;
use tracing::info;

pub async fn standard_withdrawal(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<GuardianSigned<StandardWithdrawalResponse>> {
    info!("/standard_withdrawal - Received request.");

    let unsigned_request = StandardWithdrawalRequestWire::from(signed_request.message().clone()); // for logging
    let request_signature = signed_request.committee_signature().clone(); // for logging
    let wid = unsigned_request.wid;

    match normal_withdrawal_inner(enclave.clone(), signed_request).await {
        Ok((txid, response, limiter_guard)) => {
            info!("Withdrawal {} processed successfully. Logging to S3.", wid);
            let post_state = *limiter_guard.state();
            let msg = WithdrawalLogMessage::Success {
                txid,
                request_data: unsigned_request,
                request_sign: request_signature,
                response: response.clone(),
                post_state,
            };
            log_withdrawal_success(enclave.clone(), wid, msg, limiter_guard).await?;
            // <-- Limiter guard drops upon log_withdrawal_success return. Next withdrawal can begin.
            Ok(enclave.sign(response))
        }
        Err(withdraw_err) => {
            error!("Withdrawal {} failed: {:?}", wid, withdraw_err);
            let msg = WithdrawalLogMessage::Failure {
                request_data: unsigned_request,
                request_sign: request_signature,
                error: withdraw_err.clone(),
            };
            log_withdrawal_failure(enclave.as_ref(), wid, msg, &withdraw_err).await?;
            Err(withdraw_err)
        }
    }
}

async fn normal_withdrawal_inner(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<(
    Txid,
    StandardWithdrawalResponse,
    OwnedMutexGuard<RateLimiter>,
)> {
    // 0) Validation
    if !enclave.is_fully_initialized() {
        return Err(EnclaveUninitialized);
    }

    // 1) Verify certificate (before acquiring limiter lock)
    let committee = enclave.state.get_committee()?;
    let threshold = certificate_threshold(committee.total_weight());

    info!("Verifying request certificate.");
    verify_hashi_cert(committee, threshold, &signed_request)?;
    info!("Request certificate verified.");

    let (_, request) = signed_request.into_parts();

    // 2) Rate limits: acquire exclusive lock on limiter, consume tokens.
    //    The returned guard holds the mutex — no other withdrawal can proceed
    //    until this one is durably logged or the enclave aborts.
    //
    // Reject timestamps too far in the future (clock skew protection).
    // Old timestamps are safe — the limiter's monotonicity check prevents replay,
    // and old timestamps result in less refill (conservative).
    const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
    let guardian_now = now_timestamp_secs();
    if request.timestamp_secs() > guardian_now + MAX_CLOCK_SKEW_SECS {
        return Err(InvalidInputs(format!(
            "request timestamp {} is too far in the future (guardian clock: {})",
            request.timestamp_secs(),
            guardian_now
        )));
    }

    info!("Checking rate limits.");
    // Gross outflow (= inputs - change = external_out + miner_fee).
    // Miner fee leaves the pool too, so it must consume the limit;
    // change flows back, so it must not.
    let consumed_amount_sats = request.utxos().gross_outflow_amount().to_sat();
    let limiter_guard = enclave
        .state
        .consume_from_limiter(
            request.seq(),
            request.timestamp_secs(),
            consumed_amount_sats,
        )
        .await?;
    info!("Rate limit check passed.");

    // 3) Sign tx (while holding limiter lock)
    info!("Generating BTC signatures.");
    let (txid, signatures) = enclave
        .config
        .btc_sign(request.utxos())
        .expect("All BTC keys should be set");
    let response = StandardWithdrawalResponse {
        enclave_signatures: signatures,
    };
    info!("BTC signatures generated.");

    Ok((txid, response, limiter_guard))
}

async fn log_withdrawal_success(
    enclave: Arc<Enclave>,
    wid: WithdrawalID,
    msg: WithdrawalLogMessage,
    limiter_guard: OwnedMutexGuard<RateLimiter>,
) -> GuardianResult<()> {
    // The task owns the limiter guard and continues if the RPC future is cancelled.
    // In production, exhausting the write grace period panics and the process-wide
    // panic hook aborts the enclave.
    tokio::spawn(async move {
        enclave
            .log_withdraw(msg)
            .await
            .expect("withdrawal log write failed");
        info!("Withdrawal {} logged.", wid);
        drop(limiter_guard);
    })
    .await
    .expect("withdrawal log task failed");
    Ok(())
}

async fn log_withdrawal_failure(
    enclave: &Enclave,
    wid: WithdrawalID,
    msg: WithdrawalLogMessage,
    withdraw_err: &GuardianError,
) -> GuardianResult<()> {
    if let Err(log_err) = enclave.log_withdraw(msg).await {
        error!("Logging withdrawal {} to S3 failed: {:?}", wid, log_err);
        return Err(InternalError(format!(
            "Failed to log withdrawal {} error {} due to S3 logging error {}",
            wid, withdraw_err, log_err
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activate_enclave_for_testing;
    use crate::OperatorInitTestArgs;
    use bitcoin::Network;
    use hashi_types::bitcoin::create_btc_keypair_for_test;
    use hashi_types::bitcoin::hashi_master_g_from_btc_xonly_for_test;
    use hashi_types::guardian::HashiCommittee;
    use hashi_types::guardian::InitConfig;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::WithdrawStage;

    /// Sets up an enclave with a single committee and token bucket limiter.
    async fn setup_fully_initialized_enclave(
        network: Network,
        committee: HashiCommittee,
        max_bucket_capacity_sats: u64,
    ) -> Arc<Enclave> {
        let hashi_kp = create_btc_keypair_for_test(&[6u8; 32]);
        let hashi_btc_master_pubkey =
            hashi_master_g_from_btc_xonly_for_test(&hashi_kp.x_only_public_key().0);

        let refill_rate = 0; // no refill in tests unless specified
        let limiter_config = LimiterConfig {
            refill_rate,
            max_bucket_capacity: max_bucket_capacity_sats,
        };
        let limiter_state = LimiterState::genesis(&limiter_config);
        let config =
            InitConfig::from_parts_for_testing(limiter_config, hashi_btc_master_pubkey, network);

        // operator_init installs standby config; test activation installs the
        // committee and limiter before withdrawals.
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_config(config),
        )
        .await;

        // The reconstructed BTC keypair (set by provisioner_init in production).
        enclave
            .config
            .set_btc_keypair(create_btc_keypair_for_test(&[8u8; 32]))
            .unwrap();

        enclave
            .advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())
            .expect("test setup should advance provisioner init lifecycle");
        activate_enclave_for_testing(&enclave, committee, limiter_config, limiter_state)
            .expect("activate_enclave_for_testing should succeed on a fresh enclave");

        assert!(enclave.is_fully_initialized());
        enclave
    }

    #[tokio::test]
    async fn test_normal_withdrawal_inner_requires_full_init() {
        let enclave = Enclave::create_with_random_keys();
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let result = normal_withdrawal_inner(enclave, signed_request).await;
        assert!(matches!(result, Err(EnclaveUninitialized)));
    }

    #[tokio::test]
    async fn test_normal_withdrawal() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_for_testing(Network::Regtest);
        let amount_sats = signed_request
            .message()
            .utxos()
            .gross_outflow_amount()
            .to_sat();
        // Set request amount as the max bucket capacity
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        let result = normal_withdrawal_inner(enclave, signed_request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_standard_withdrawal_rate_limit_exceeded() {
        let (req1, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x01; 32]),
            100,
            0,
        );
        let amount_sats = req1.message().utxos().gross_outflow_amount().to_sat();
        // Bucket capacity == one withdrawal, so second will be rejected.
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        let first = standard_withdrawal(enclave.clone(), req1).await;
        assert!(first.is_ok());

        // Second withdrawal with seq=1 and later timestamp — bucket is empty, no refill (rate=0).
        let (req2, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x02; 32]),
            200,
            1,
        );
        let second = standard_withdrawal(enclave, req2).await;
        assert!(matches!(
            second.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));
    }
}
