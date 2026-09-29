// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::verify_hashi_cert;
use crate::Enclave;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::InvalidS3Log;
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

    // 2) Hold the limiter mutex from the S3 consistency check through signing
    // and durable logging, so local withdrawals cannot race with this read.
    info!("Checking persisted limiter state.");
    let mut limiter_guard = enclave.state.lock_limiter().await?;
    let mut reader = enclave.new_guardian_reader()?;
    let persisted_state =
        Box::pin(reader.recover_limiter_state(&enclave.limiter_config()?)).await?;
    if limiter_guard.state() != &persisted_state {
        return Err(InvalidS3Log(format!(
            "persisted limiter state differs from local state: persisted {persisted_state:?}, local {:?}",
            limiter_guard.state(),
        )));
    }
    // This catches already-visible divergence, not simultaneous withdrawals in
    // different enclaves: another session can write after our read completes.
    info!("Checking rate limits.");
    validate_request_timestamp(request.timestamp_secs(), now_timestamp_secs())?;
    // Gross outflow (= inputs - change = external_out + miner_fee).
    // Miner fees consume allowance too; change stays in the pool.
    let consumed_amount_sats = request.utxos().gross_outflow_amount().to_sat();
    limiter_guard.consume(
        request.seq(),
        request.timestamp_secs(),
        consumed_amount_sats,
    )?;
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
    use hashi_types::bitcoin::BitcoinKeypair;
    use hashi_types::bitcoin::HashiMasterG;
    use hashi_types::bitcoin::BTC_LIB;
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
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = setup_with_logger(network, committee, max_bucket_capacity_sats, logger).await;
        (enclave, captures)
    }

    async fn setup_with_logger(
        network: Network,
        committee: HashiCommittee,
        max_bucket_capacity_sats: u64,
        logger: crate::s3_client::GuardianS3Client,
    ) -> Arc<Enclave> {
        let hashi_kp =
            BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[6u8; 32]).expect("valid test secret key");
        let hashi_btc_master_pubkey =
            HashiMasterG::with_even_y_from_x_be_bytes(&hashi_kp.x_only_public_key().0.serialize())
                .expect("valid x-only public key");

        let refill_rate = 0; // no refill in tests unless specified
        let limiter_config = LimiterConfig {
            refill_rate,
            max_bucket_capacity: max_bucket_capacity_sats,
        };
        let limiter_state = LimiterState::genesis(&limiter_config);
        let config = InitConfig::from_parts_for_testing(limiter_config, network);

        // operator_init installs standby config; test activation installs the
        // committee and limiter before withdrawals.
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
            .set_btc_keypair(
                BitcoinKeypair::from_seckey_slice(&BTC_LIB, &[8u8; 32])
                    .expect("valid test secret key"),
            )
            .unwrap();

        enclave
            .advance_lifecycle_into(WithdrawStage::ProvisionerInitialized.into())
            .expect("test setup should advance provisioner init lifecycle");
        activate_enclave_for_testing(&enclave, committee, limiter_config, limiter_state)
            .expect("activate_enclave_for_testing should succeed on a fresh enclave");

        assert!(enclave.require_fully_initialized().is_ok());
        enclave
    }

    #[tokio::test]
    async fn test_standard_withdrawal_requires_full_init() {
        let enclave = Enclave::create_with_random_keys();
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let result = standard_withdrawal(enclave, signed_request).await;
        assert!(matches!(
            result,
            Err(GuardianError::LifecycleMismatch {
                expected: Some(EnclaveLifecycle::Withdraw(WithdrawStage::Activated)),
                actual: None,
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
        let mut guard = enclave.state.lock_limiter().await.unwrap();
        guard.consume(0, now_timestamp_secs(), amount_sats).unwrap();

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
        let (enclave, captures) =
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

        let state = enclave.state.limiter_snapshot().expect("activated");
        assert_eq!(state.next_seq, 1);
        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let log: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        let VersionedLogMessage::V1(LogMessageV1::Withdrawal(message)) = log.message() else {
            panic!("expected withdrawal record");
        };
        assert_eq!(message.post_state, state);
        assert_eq!(message.request_data.seq, 0);
        assert_eq!(state.num_tokens_available, 0);
    }

    #[tokio::test]
    async fn test_standard_withdrawal_rate_limit_exceeded() {
        let (request, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x01; 32]),
            now_timestamp_secs(),
            0,
        );
        let amount = request.message().utxos().gross_outflow_amount().to_sat();
        let (enclave, captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount - 1).await;
        let before = enclave.state.limiter_snapshot().unwrap();
        let result = standard_withdrawal(enclave.clone(), request).await;
        assert!(matches!(result, Err(GuardianError::RateLimitExceeded)));
        assert!(captures.lock().unwrap().is_empty());
        assert_eq!(*enclave.state.lock_limiter().await.unwrap().state(), before);
    }

    #[tokio::test]
    async fn failed_s3_read_does_not_consume_or_log() {
        use aws_sdk_s3::operation::list_object_versions::ListObjectVersionsError;
        use aws_sdk_s3::Client;
        use aws_smithy_mocks::mock;
        use aws_smithy_mocks::mock_client;
        use aws_smithy_mocks::RuleMode;
        use hashi_types::guardian::S3BucketInfo;
        use hashi_types::guardian::S3RetentionEnvironment;

        let failed_read = mock!(Client::list_object_versions).then_error(|| {
            ListObjectVersionsError::unhandled(std::io::Error::other("read failed"))
        });
        // No PutObject rule: any attempt to log a withdrawal would fail the test.
        let logger = crate::s3_client::GuardianS3Client::from_client(
            S3BucketInfo::mock_for_testing(),
            S3RetentionEnvironment::Testnet,
            mock_client!(aws_sdk_s3, RuleMode::MatchAny, &[&failed_read]),
        );
        let (request, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0x01; 32]),
            now_timestamp_secs(),
            0,
        );
        let amount = request.message().utxos().gross_outflow_amount().to_sat();
        let enclave = setup_with_logger(Network::Regtest, committee, amount, logger).await;
        let before = enclave.state.limiter_snapshot().unwrap();
        let result = standard_withdrawal(enclave.clone(), request).await;
        assert!(matches!(result, Err(GuardianError::S3Error(_))));
        assert_eq!(enclave.state.limiter_snapshot().unwrap(), before);
        assert_eq!(*enclave.state.lock_limiter().await.unwrap().state(), before);
    }

    #[tokio::test]
    async fn missing_history_after_a_withdrawal_is_rejected() {
        let (request, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0xab; 32]),
            now_timestamp_secs(),
            0,
        );
        let amount = request.message().utxos().gross_outflow_amount().to_sat();
        let (enclave, captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount * 2).await;
        standard_withdrawal(enclave.clone(), request).await.unwrap();
        let before = enclave.state.limiter_snapshot().unwrap();
        let (request, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            WithdrawalID::new([0xee; 32]),
            now_timestamp_secs(),
            1,
        );
        // The capturing mock lists an empty history, despite the successful write.
        let result = standard_withdrawal(enclave.clone(), request).await;
        assert!(matches!(result, Err(GuardianError::InvalidS3Log(_))));
        assert_eq!(captures.lock().unwrap().len(), 1);
        assert_eq!(*enclave.state.lock_limiter().await.unwrap().state(), before);
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
