// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::verify_hashi_cert;
use crate::enclave::WithdrawalState;
use crate::Enclave;
use bitcoin::Txid;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSignedResponse;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalRequestWire;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalID;
use hashi_types::guardian::WithdrawalLogMessage;
use std::sync::Arc;
use tokio::sync::OwnedMutexGuard;
use tracing::error;
use tracing::info;

const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
// Requests are minted per attempt and should not remain usable indefinitely.
const MAX_REQUEST_AGE_SECS: u64 = 30 * 60;

/// A verified request, resolved under the withdrawal lock.
enum Resolved {
    /// A repeat of a transaction this guardian has already debited.
    Replay(StandardWithdrawalResponse),
    /// A new transaction, debited and signed. The guard is held until its
    /// success log is durable.
    Signed(
        Txid,
        StandardWithdrawalResponse,
        OwnedMutexGuard<WithdrawalState>,
    ),
}

pub async fn standard_withdrawal(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<GuardianSignedResponse<StandardWithdrawalResponse>> {
    info!("/standard_withdrawal - Received request.");

    let unsigned_request = StandardWithdrawalRequestWire::from(signed_request.message().clone()); // for logging
    let request_signature = signed_request.committee_signature().clone(); // for logging
    let wid = unsigned_request.wid;

    match normal_withdrawal_inner(enclave.clone(), signed_request).await {
        Ok(Resolved::Replay(response)) => {
            info!(
                "Withdrawal {} was already signed; replaying its signatures for seq {}.",
                wid, unsigned_request.seq
            );
            Ok(enclave.sign(response))
        }
        Ok(Resolved::Signed(txid, response, withdrawals)) => {
            info!("Withdrawal {} processed successfully. Logging to S3.", wid);
            let msg = WithdrawalLogMessage::Success {
                txid,
                request_data: unsigned_request,
                request_sign: request_signature,
                response: response.clone(),
                post_state: *withdrawals.limiter.state(),
            };
            log_withdrawal_success(enclave.as_ref(), wid, msg, txid, withdrawals).await?;
            // The withdrawal lock is retained through the durable log and released
            // when `log_withdrawal_success` returns. The next withdrawal may now begin.
            Ok(enclave.sign(response))
        }
        Err(withdraw_err) => {
            error!("Withdrawal {} failed: {:?}", wid, withdraw_err);
            let msg = WithdrawalLogMessage::Failure {
                request_data: unsigned_request,
                request_sign: request_signature,
                error: withdraw_err.to_string(),
            };
            log_withdrawal_failure(enclave.as_ref(), wid, msg, &withdraw_err).await?;
            Err(withdraw_err)
        }
    }
}

async fn normal_withdrawal_inner(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<Resolved> {
    // 0) Validation
    enclave.require_fully_initialized()?;

    // 1) Verify certificate (before acquiring the withdrawal lock)
    let committee = enclave.state.get_committee()?;

    info!("Verifying request certificate.");
    verify_hashi_cert(enclave.hashi_object_id()?, &committee, &signed_request)?;
    info!("Request certificate verified.");

    let (_, request) = signed_request.into_parts();
    validate_request_timestamp(request.timestamp_secs(), now_timestamp_secs())?;

    // 2) Sign. Signing is deterministic and touches no shared state; the
    //    signatures leave the enclave only once this transaction is debited or
    //    matched to a debit already in the log.
    info!("Generating BTC signatures.");
    let (txid, signatures) = enclave
        .config
        .btc_sign(request.utxos())
        .expect("All BTC keys should be set");
    let response = StandardWithdrawalResponse {
        enclave_signatures: signatures,
    };
    info!("BTC signatures generated.");

    // 3) Acquire the withdrawal lock. The guard is held through durable
    //    logging — no other withdrawal can proceed until this one is durably
    //    logged or the enclave aborts.
    let mut withdrawals = enclave.state.lock_withdrawals().await?;

    // 4) A transaction this enclave has already debited is re-signed without a
    //    second debit: the txid fixes the same inputs and outputs, so it
    //    releases no new outflow. The seq is not part of the match, since a
    //    node retries at whatever seq its limiter mirror reconciled to.
    if withdrawals.signed_txids.contains(&txid) {
        return Ok(Resolved::Replay(response));
    }

    // 5) Rate limits
    info!("Checking rate limits.");
    // Gross outflow (= inputs - change = external_out + miner_fee).
    // Miner fee leaves the pool too, so it must consume the limit;
    // change flows back, so it must not.
    let consumed_amount_sats = request.utxos().gross_outflow_amount().to_sat();
    withdrawals.limiter.consume(
        request.seq(),
        request.timestamp_secs(),
        consumed_amount_sats,
    )?;
    info!("Rate limit check passed.");

    Ok(Resolved::Signed(txid, response, withdrawals))
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

async fn log_withdrawal_success(
    enclave: &Enclave,
    wid: WithdrawalID,
    msg: WithdrawalLogMessage,
    txid: Txid,
    withdrawals: OwnedMutexGuard<WithdrawalState>,
) -> GuardianResult<()> {
    enclave
        .log_withdraw(msg)
        .await
        .expect("S3 logger must be initialized to log a withdrawal");
    info!("Withdrawal {} logged.", wid);
    // Consumes the guard: the now-durable debit is recorded, and only then may
    // the next withdrawal enter.
    enclave.state.commit_withdrawal(withdrawals, txid);
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
    use crate::test_utils::CapturedPuts;
    use crate::OperatorInitTestArgs;
    use bitcoin::hashes::Hash;
    use bitcoin::Network;
    use bitcoin::Txid;
    use hashi_types::bitcoin::create_btc_keypair_for_test;
    use hashi_types::bitcoin::hashi_master_g_from_btc_xonly_for_test;
    use hashi_types::bitcoin::BitcoinSignature;
    use hashi_types::guardian::proto_conversions::signed_standard_withdrawal_request_to_pb;
    use hashi_types::guardian::AddressValidation;
    use hashi_types::guardian::EnclaveLifecycle;
    use hashi_types::guardian::HashiCommittee;
    use hashi_types::guardian::InitConfig;
    use hashi_types::guardian::LimiterConfig;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::LogMessageV2;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::RateLimiter;
    use hashi_types::guardian::SignedStandardWithdrawalRequestWire;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::VersionedLogMessage;
    use hashi_types::guardian::WithdrawStage;
    use std::collections::HashSet;

    /// An enclave through provisioner init, ready to activate with `limiter_config`.
    async fn provisioned_enclave(
        network: Network,
        limiter_config: LimiterConfig,
    ) -> (Arc<Enclave>, CapturedPuts) {
        let hashi_kp = create_btc_keypair_for_test(&[6u8; 32]);
        let hashi_btc_master_pubkey =
            hashi_master_g_from_btc_xonly_for_test(&hashi_kp.x_only_public_key().0);
        let config = InitConfig::from_parts_for_testing(
            limiter_config,
            hashi_btc_master_pubkey,
            network,
            hashi_types::guardian::test_utils::TEST_HASHI_OBJECT_ID,
        );

        // operator_init installs standby config; test activation installs the
        // committee and withdrawal state before withdrawals.
        let (logger, captures) = crate::test_utils::mock_logger_capturing();
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default()
                .with_s3_logger(logger)
                .with_config(config),
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
        (enclave, captures)
    }

    /// Sets up an enclave with a single committee and token bucket limiter.
    async fn setup_fully_initialized_enclave(
        network: Network,
        committee: HashiCommittee,
        max_bucket_capacity_sats: u64,
    ) -> (Arc<Enclave>, CapturedPuts) {
        let limiter_config = no_refill_limiter(max_bucket_capacity_sats);
        let (enclave, captures) = provisioned_enclave(network, limiter_config).await;
        activate_enclave_for_testing(
            &enclave,
            committee,
            limiter_config,
            LimiterState::genesis(&limiter_config),
        )
        .expect("activate_enclave_for_testing should succeed on a fresh enclave");

        assert!(enclave.require_fully_initialized().is_ok());
        (enclave, captures)
    }

    /// Activate the way operator_activate does after recovering the debited set.
    fn activate_with_signed_txids(
        enclave: &Enclave,
        committee: HashiCommittee,
        limiter_config: LimiterConfig,
        limiter_state: LimiterState,
        signed_txids: HashSet<Txid>,
    ) {
        let withdrawals = WithdrawalState {
            limiter: RateLimiter::new(limiter_config, limiter_state).unwrap(),
            signed_txids,
        };
        enclave.state.init(committee, withdrawals).unwrap();
        enclave.clear_temporary_init_state();
        enclave
            .advance_lifecycle_into(WithdrawStage::Activated.into())
            .unwrap();
    }

    fn no_refill_limiter(max_bucket_capacity: u64) -> LimiterConfig {
        LimiterConfig {
            refill_rate: 0,
            max_bucket_capacity,
        }
    }

    fn signed_request(
        wid: WithdrawalID,
        timestamp_secs: u64,
        seq: u64,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            wid,
            timestamp_secs,
            seq,
        )
    }

    fn amount_sats(request: &HashiSigned<StandardWithdrawalRequest>) -> u64 {
        request.message().utxos().gross_outflow_amount().to_sat()
    }

    fn signatures_of(
        enclave: &Enclave,
        response: GuardianSignedResponse<StandardWithdrawalResponse>,
    ) -> Vec<BitcoinSignature> {
        response
            .verify_into_data(&enclave.signing_pubkey())
            .expect("response is signed by this enclave")
            .response
            .enclave_signatures
    }

    #[tokio::test]
    async fn test_normal_withdrawal_inner_requires_full_init() {
        let enclave = Enclave::create_with_random_keys();
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let result = normal_withdrawal_inner(enclave, signed_request).await;
        assert!(matches!(
            result,
            Err(GuardianError::LifecycleMismatch {
                expected: EnclaveLifecycle::Withdraw(WithdrawStage::Activated),
                actual: EnclaveLifecycle::Withdraw(WithdrawStage::Uninitialized),
            })
        ));
    }

    #[tokio::test]
    async fn test_normal_withdrawal() {
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

        let result = normal_withdrawal_inner(enclave, signed_request).await;
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

        // A withdrawal holds the lock across its durable log write.
        let mut guard = enclave
            .state
            .lock_withdrawals()
            .await
            .expect("withdrawal lock is available");
        guard
            .limiter
            .consume(0, now_timestamp_secs(), amount_sats)
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
            2,
            "both withdrawal outcomes should be logged"
        );
        let success: LogRecord = serde_json::from_slice(&captured[0].1).unwrap();
        assert_eq!(captured[0].0, success.object_key());
        let VersionedLogMessage::V2(LogMessageV2::Withdrawal(message)) = success.message() else {
            panic!("expected V2 withdrawal record");
        };
        let WithdrawalLogMessage::Success {
            request_data,
            post_state,
            ..
        } = message.as_ref()
        else {
            panic!("expected successful withdrawal record");
        };
        assert_eq!(request_data.seq, 0);
        assert_eq!(post_state.next_seq, 1);
        assert_eq!(post_state.num_tokens_available, 0);

        let failure: LogRecord = serde_json::from_slice(&captured[1].1).unwrap();
        assert_eq!(captured[1].0, failure.object_key());
        let VersionedLogMessage::V2(LogMessageV2::Withdrawal(message)) = failure.message() else {
            panic!("expected V2 withdrawal record");
        };
        let WithdrawalLogMessage::Failure {
            request_data,
            error,
            ..
        } = message.as_ref()
        else {
            panic!("expected failed withdrawal record");
        };
        assert_eq!(request_data.seq, 1);
        assert_eq!(error, &GuardianError::RateLimitExceeded.to_string());
    }

    #[tokio::test]
    async fn retry_replays_at_any_seq() {
        let wid = WithdrawalID::new([0xb1; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        // Room for exactly one withdrawal, so a second debit would fail.
        let (enclave, captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats(&request))
                .await;

        let first = standard_withdrawal(enclave.clone(), request)
            .await
            .expect("withdrawal succeeds");
        let signatures = signatures_of(&enclave, first);
        let state = enclave.state.limiter_snapshot();

        for seq in [0, 1, 7] {
            let (retry, _) = signed_request(wid, now, seq);
            let replayed = standard_withdrawal(enclave.clone(), retry)
                .await
                .expect("retry replays");
            assert_eq!(signatures_of(&enclave, replayed), signatures);
        }
        assert_eq!(enclave.state.limiter_snapshot(), state);
        assert_eq!(captures.lock().unwrap().len(), 1, "a replay writes no log");
    }

    #[tokio::test]
    async fn replay_requires_a_valid_certificate() {
        let wid = WithdrawalID::new([0xb2; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats(&request))
                .await;
        standard_withdrawal(enclave.clone(), request)
            .await
            .expect("withdrawal succeeds");

        // Change the seq after signing so the certificate no longer covers the request.
        let (retry, _) = signed_request(wid, now, 1);
        let mut retry_pb = signed_standard_withdrawal_request_to_pb(&retry);
        retry_pb.data.as_mut().unwrap().seq = Some(2);
        let wire = SignedStandardWithdrawalRequestWire::try_from(retry_pb).unwrap();
        let forged =
            HashiSigned::<StandardWithdrawalRequest>::validate_addr(wire, Network::Regtest)
                .unwrap();

        let err = standard_withdrawal(enclave, forged).await.unwrap_err();
        assert!(matches!(err, GuardianError::Unauthenticated(_)));
    }

    #[tokio::test]
    async fn replay_requires_a_fresh_request() {
        let wid = WithdrawalID::new([0xb3; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats(&request))
                .await;
        standard_withdrawal(enclave.clone(), request)
            .await
            .expect("withdrawal succeeds");

        let (stale, _) = signed_request(wid, now - MAX_REQUEST_AGE_SECS - 1, 1);
        let err = standard_withdrawal(enclave, stale).await.unwrap_err();
        assert!(matches!(err, InvalidInputs(message) if message.contains("too old")));
    }

    #[tokio::test]
    async fn same_wid_for_a_different_transaction_is_a_new_withdrawal() {
        let wid = WithdrawalID::new([0xb4; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        let limiter_config = no_refill_limiter(amount_sats(&request));
        let limiter_state = LimiterState::genesis(&limiter_config);
        let (enclave, captures) = provisioned_enclave(Network::Regtest, limiter_config).await;
        // A debit for a different transaction must not cover this one, whatever
        // withdrawal id it carries: another txid moves different coins.
        activate_with_signed_txids(
            &enclave,
            committee,
            limiter_config,
            limiter_state,
            HashSet::from([Txid::all_zeros()]),
        );

        standard_withdrawal(enclave.clone(), request)
            .await
            .expect("a transaction with no debit of its own is signed as new");

        assert_eq!(
            enclave.state.limiter_snapshot().unwrap().next_seq,
            limiter_state.next_seq + 1
        );
        let captured = captures.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].0.contains("/success-"));
    }

    #[tokio::test]
    async fn an_earlier_withdrawal_still_replays() {
        let now = now_timestamp_secs();
        let earlier_wid = WithdrawalID::new([0xb5; 32]);
        let later_wid = WithdrawalID::new([0xb6; 32]);
        let (earlier, committee) = signed_request(earlier_wid, now, 0);
        // Room for the two withdrawals below and nothing more, so a re-debit of
        // either would fail loudly.
        let (enclave, captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, 2 * amount_sats(&earlier))
                .await;
        let first = standard_withdrawal(enclave.clone(), earlier)
            .await
            .expect("earlier withdrawal succeeds");
        let earlier_signatures = signatures_of(&enclave, first);

        let (later, _) = signed_request(later_wid, now, 1);
        standard_withdrawal(enclave.clone(), later)
            .await
            .expect("later withdrawal succeeds");
        let state = enclave.state.limiter_snapshot();

        // The earlier withdrawal is no longer the most recent one, and its retry
        // still replays: same signatures, no debit, no new log.
        let (earlier_retry, _) = signed_request(earlier_wid, now, 2);
        let replayed = standard_withdrawal(enclave.clone(), earlier_retry)
            .await
            .expect("the earlier withdrawal replays");
        assert_eq!(signatures_of(&enclave, replayed), earlier_signatures);
        assert_eq!(enclave.state.limiter_snapshot(), state);
        assert_eq!(captures.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn failed_withdrawal_keeps_the_debited_transactions() {
        let now = now_timestamp_secs();
        let signed_wid = WithdrawalID::new([0xb7; 32]);
        let (request, committee) = signed_request(signed_wid, now, 0);
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats(&request))
                .await;
        let first = standard_withdrawal(enclave.clone(), request)
            .await
            .expect("withdrawal succeeds");
        let signatures = signatures_of(&enclave, first);

        let (rate_limited, _) = signed_request(WithdrawalID::new([0xb8; 32]), now, 1);
        let err = standard_withdrawal(enclave.clone(), rate_limited)
            .await
            .unwrap_err();
        assert!(matches!(err, GuardianError::RateLimitExceeded));

        let (retry, _) = signed_request(signed_wid, now, 1);
        let replayed = standard_withdrawal(enclave.clone(), retry)
            .await
            .expect("retry replays");
        assert_eq!(signatures_of(&enclave, replayed), signatures);
    }

    #[tokio::test]
    async fn retry_waiting_on_the_lock_replays_once_the_withdrawal_commits() {
        let wid = WithdrawalID::new([0xb9; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        let amount = amount_sats(&request);
        let (enclave, _captures) =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount).await;

        // Stand in for the original request, holding the lock across its log write.
        let mut withdrawals = enclave.state.lock_withdrawals().await.unwrap();
        withdrawals.limiter.consume(0, now, amount).unwrap();
        let (txid, enclave_signatures) =
            enclave.config.btc_sign(request.message().utxos()).unwrap();

        let retry = tokio::spawn(standard_withdrawal(enclave.clone(), request));
        tokio::task::yield_now().await;
        assert!(
            !retry.is_finished(),
            "the retry waits for the withdrawal lock"
        );

        let response = StandardWithdrawalResponse { enclave_signatures };
        enclave.state.commit_withdrawal(withdrawals, txid);

        let replayed = retry.await.unwrap().expect("retry replays");
        assert_eq!(
            signatures_of(&enclave, replayed),
            response.enclave_signatures
        );
    }

    #[tokio::test]
    async fn recovered_withdrawal_replays_after_activation() {
        let wid = WithdrawalID::new([0xba; 32]);
        let now = now_timestamp_secs();
        let (request, committee) = signed_request(wid, now, 0);
        let limiter_config = no_refill_limiter(amount_sats(&request));
        let (enclave, captures) = provisioned_enclave(Network::Regtest, limiter_config).await;

        // What a previous session's success records left behind.
        let (txid, enclave_signatures) =
            enclave.config.btc_sign(request.message().utxos()).unwrap();
        let post_state = LimiterState {
            num_tokens_available: 0,
            last_updated_at: now,
            next_seq: 1,
        };
        activate_with_signed_txids(
            &enclave,
            committee,
            limiter_config,
            post_state,
            HashSet::from([txid]),
        );

        let (retry, _) = signed_request(wid, now, 1);
        let replayed = standard_withdrawal(enclave.clone(), retry)
            .await
            .expect("retry replays");
        assert_eq!(signatures_of(&enclave, replayed), enclave_signatures);
        assert_eq!(enclave.state.limiter_snapshot(), Some(post_state));
        assert!(captures.lock().unwrap().is_empty());
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
