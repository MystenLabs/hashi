// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::verify_hashi_cert;
use crate::Enclave;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalRequestWire;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalLogMessage;
use std::sync::Arc;
use tracing::info;

const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
// Requests are minted per attempt and should not remain usable indefinitely.
const MAX_REQUEST_AGE_SECS: u64 = 30 * 60;

pub async fn standard_withdrawal(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<GuardianSignedResponse<StandardWithdrawalResponse>> {
    info!("/standard_withdrawal - Received request.");

    let wid = *signed_request.message().wid();
    // 0) Validation
    enclave.require_fully_initialized()?;

    // 1) Verify certificate (before acquiring limiter lock)
    let committee = enclave.state.get_committee()?;

    info!("Verifying request certificate.");
    verify_hashi_cert(enclave.hashi_object_id()?, &committee, &signed_request)?;
    info!("Request certificate verified.");

    let (request_sign, request) = signed_request.into_parts();

    // 2) Rate limits: acquire exclusive lock on limiter, consume tokens.
    //    The returned guard holds the mutex — no other withdrawal can proceed
    //    until this one is durably logged or the enclave aborts.
    //
    validate_request_timestamp(request.timestamp_secs(), now_timestamp_secs())?;

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

    // 4) Log while holding the limiter lock, before returning signatures.
    info!("Withdrawal {} processed successfully. Logging to S3.", wid);
    let msg = WithdrawalLogMessage {
        txid,
        request_data: StandardWithdrawalRequestWire::from(request),
        request_sign,
        response: response.clone(),
        post_state: *limiter_guard.state(),
    };
    enclave
        .log_withdraw(msg)
        .await
        .expect("S3 logger must be initialized to log a withdrawal");
    info!("Withdrawal {} logged.", wid);
    // Publish the durable state and release the guard so the next withdrawal
    // may begin.
    enclave.state.set_limiter_snapshot(limiter_guard);
    Ok(enclave.sign(response))
}

fn validate_request_timestamp(
    request_timestamp_secs: u64,
    guardian_now: u64,
) -> GuardianResult<()> {
    if request_timestamp_secs > guardian_now + MAX_CLOCK_SKEW_SECS {
        return Err(InvalidInputs(format!(
            "request timestamp {} is too far in the future (guardian clock: {})",
            request_timestamp_secs, guardian_now
        )));
    }

    if guardian_now.saturating_sub(request_timestamp_secs) > MAX_REQUEST_AGE_SECS {
        return Err(InvalidInputs(format!(
            "request timestamp {} is too old (guardian clock: {}, maximum age: {} seconds)",
            request_timestamp_secs, guardian_now, MAX_REQUEST_AGE_SECS
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
    use hashi_types::guardian::EnclaveLifecycle;
    use hashi_types::guardian::GuardianError;
    use hashi_types::guardian::HashiCommittee;
    use hashi_types::guardian::InitConfig;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogMessageV1;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::VersionedLogMessage;
    use hashi_types::guardian::WithdrawStage;
    use hashi_types::guardian::WithdrawalID;

    /// Sets up an enclave with a single committee and token bucket limiter.
    async fn setup_fully_initialized_enclave(
        network: Network,
        committee: HashiCommittee,
        max_bucket_capacity_sats: u64,
    ) -> (Arc<Enclave>, crate::test_utils::CapturedPuts) {
        let hashi_kp = create_btc_keypair_for_test(&[6u8; 32]);
        let hashi_btc_master_pubkey =
            hashi_master_g_from_btc_xonly_for_test(&hashi_kp.x_only_public_key().0);

        let refill_rate = 0; // no refill in tests unless specified
        let limiter_config = LimiterConfig {
            refill_rate,
            max_bucket_capacity: max_bucket_capacity_sats,
        };
        let limiter_state = LimiterState::genesis(&limiter_config);
        let config = InitConfig::from_parts_for_testing(limiter_config, network);

        // operator_init installs standby config; test activation installs the
        // committee and limiter before withdrawals.
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default()
                .with_s3_logger(logger)
                .with_config(config)
                .with_genesis_bindings(
                    hashi_types::guardian::test_utils::TEST_HASHI_OBJECT_ID,
                    hashi_btc_master_pubkey,
                ),
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

        assert!(enclave.require_fully_initialized().is_ok());
        (enclave, captures)
    }

    #[tokio::test]
    async fn test_standard_withdrawal_requires_full_init() {
        let enclave = Enclave::create_with_random_keys();
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let result = standard_withdrawal(enclave, signed_request).await;
        assert!(matches!(
            result,
            Err(GuardianError::LifecycleMismatch {
                expected: EnclaveLifecycle::Withdraw(WithdrawStage::Activated),
                actual: EnclaveLifecycle::Withdraw(WithdrawStage::Uninitialized),
            })
        ));
    }

    #[tokio::test]
    async fn test_standard_withdrawal() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
                Network::Regtest,
                WithdrawalID::new([0xab; 32]),
                now_timestamp_secs(),
                0,
            );
        let amount_sats = signed_request
            .message()
            .utxos()
            .gross_outflow_amount()
            .to_sat();
        // Set request amount as the max bucket capacity
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        let result = standard_withdrawal(enclave, signed_request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn limiter_state_is_readable_while_a_withdrawal_holds_the_guard() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
                Network::Regtest,
                WithdrawalID::new([0xac; 32]),
                now_timestamp_secs(),
                0,
            );
        let amount_sats = signed_request
            .message()
            .utxos()
            .gross_outflow_amount()
            .to_sat();
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        // A withdrawal holds the limiter across its durable log write.
        let guard = enclave
            .state
            .consume_from_limiter(0, now_timestamp_secs(), amount_sats)
            .await
            .expect("limiter accepts the first withdrawal");

        // Readable rather than timing out into `None`, and still reporting the
        // durable state: this consumption is not logged yet.
        let state = enclave
            .state
            .limiter_snapshot()
            .expect("limiter state stays readable while the guard is held");
        assert_eq!(state.next_seq, 0);
        drop(guard);
    }

    #[tokio::test]
    async fn limiter_state_advances_once_the_withdrawal_is_logged() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
                Network::Regtest,
                WithdrawalID::new([0xad; 32]),
                now_timestamp_secs(),
                0,
            );
        let amount_sats = signed_request
            .message()
            .utxos()
            .gross_outflow_amount()
            .to_sat();
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;
        assert_eq!(
            enclave
                .state
                .limiter_snapshot()
                .expect("activated")
                .next_seq,
            0
        );

        standard_withdrawal(enclave.clone(), signed_request)
            .await
            .expect("withdrawal succeeds");

        assert_eq!(
            enclave
                .state
                .limiter_snapshot()
                .expect("activated")
                .next_seq,
            1
        );
    }

    #[tokio::test]
    async fn test_standard_withdrawal_rate_limit_exceeded() {
        let timestamp_secs = now_timestamp_secs();
        let (req1, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x01; 32]),
            timestamp_secs,
            0,
        );
        let amount_sats = req1.message().utxos().gross_outflow_amount().to_sat();
        // Bucket capacity == one withdrawal, so second will be rejected.
        let (enclave, captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        let first = standard_withdrawal(enclave.clone(), req1).await;
        assert!(first.is_ok());

        // Second withdrawal with seq=1 and later timestamp — bucket is empty, no refill (rate=0).
        let (req2, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x02; 32]),
            timestamp_secs + 1,
            1,
        );
        let second = standard_withdrawal(enclave, req2).await;
        assert!(matches!(
            second.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));

        let captured = captures.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "only successful withdrawals should be logged"
        );
        let success: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        assert_eq!(captured[0].0, success.object_key());
        let VersionedLogMessage::V1(LogMessageV1::Withdrawal(message)) = success.message() else {
            panic!("expected V1 withdrawal record");
        };
        let WithdrawalLogMessage {
            request_data,
            post_state,
            ..
        } = message.as_ref();
        assert_eq!(request_data.seq, 0);
        assert_eq!(post_state.next_seq, 1);
        assert_eq!(post_state.num_tokens_available, 0);
    }

    #[test]
    fn test_request_timestamp_bounds() {
        const GUARDIAN_NOW: u64 = 1_000_000;

        assert!(
            validate_request_timestamp(GUARDIAN_NOW - MAX_REQUEST_AGE_SECS, GUARDIAN_NOW).is_ok()
        );
        assert!(
            validate_request_timestamp(GUARDIAN_NOW + MAX_CLOCK_SKEW_SECS, GUARDIAN_NOW).is_ok()
        );

        let too_old =
            validate_request_timestamp(GUARDIAN_NOW - MAX_REQUEST_AGE_SECS - 1, GUARDIAN_NOW);
        assert!(matches!(too_old, Err(InvalidInputs(message)) if message.contains("too old")));

        let too_far_in_the_future =
            validate_request_timestamp(GUARDIAN_NOW + MAX_CLOCK_SKEW_SECS + 1, GUARDIAN_NOW);
        assert!(matches!(
            too_far_in_the_future,
            Err(InvalidInputs(message)) if message.contains("too far in the future")
        ));
    }
}
