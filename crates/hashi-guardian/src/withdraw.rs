// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::Enclave;
use bitcoin::Txid;
use hashi_types::guardian::now_timestamp_secs;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::EnclaveUninitialized;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;
use hashi_types::guardian::PendingReserve;
use hashi_types::guardian::RateLimiter;
use hashi_types::guardian::StandardWithdrawalRequest;
use hashi_types::guardian::StandardWithdrawalRequestWire;
use hashi_types::guardian::StandardWithdrawalResponse;
use hashi_types::guardian::WithdrawalLogMessage;
use serde::Serialize;
use std::sync::Arc;
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

    // Idempotency: retries (leader rotation, pod restart, lost response)
    // re-submit the same `wid`. Replay the cached signed response so the
    // limiter is debited at most once per unique withdrawal.
    if let Some(cached) = enclave.state.get_cached_response(wid) {
        info!("Withdrawal {} served from idempotency cache.", wid);
        return Ok(cached);
    }

    match normal_withdrawal_inner(enclave.clone(), signed_request).await {
        Ok((txid, response, limiter_guard)) => {
            info!("Withdrawal {} processed successfully. Logging to S3.", wid);
            // Snapshot the post-consume limiter state into the log so a
            // future session can rehydrate the rate limiter from S3 alone.
            // The LogRecord's signature attests to `response`, which is
            // what future sessions re-sign when rehydrating the wid cache.
            let limiter_state_post = limiter_guard.limiter_state();
            let msg = WithdrawalLogMessage::Success {
                txid,
                request_data: unsigned_request,
                request_sign: request_signature,
                response: response.clone(),
                limiter_state_post: Some(limiter_state_post),
            };
            log_withdrawal_success(enclave.as_ref(), wid, msg, limiter_guard).await?;
            let signed_response = enclave.sign(response);
            enclave.state.cache_response(wid, signed_response.clone());
            Ok(signed_response)
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

/// Light-touch pre-construction rate-limit probe.
///
/// Idempotent on `wid`: callers may re-submit the same wid from any node
/// at any time to learn whether capacity is available. A successful
/// reserve debits against future `soft_reserve` capacity checks but does
/// NOT advance `next_seq` or `last_updated_at`. The reservation is
/// dropped either by a matching `standard_withdrawal` commit or by the
/// TTL sweep.
///
/// Unlike `standard_withdrawal`, soft reserve does not require a
/// committee certificate — the 5-minute TTL bounds the DoS blast radius
/// of a rogue or buggy caller to at most one bucket's worth of headroom.
pub async fn soft_reserve_withdrawal(
    enclave: Arc<Enclave>,
    wid: u64,
    timestamp_secs: u64,
    amount_sats: u64,
) -> GuardianResult<PendingReserve> {
    info!(wid, amount_sats, "soft reserve");

    if !enclave.is_fully_initialized() {
        return Err(EnclaveUninitialized);
    }

    // A wid that has already been fully processed has no meaning in the
    // pending queue; short-circuit to avoid confusing callers.
    if let Some(_cached) = enclave.state.get_cached_response(wid) {
        // Already hard-reserved: nothing to pend. Return a sentinel
        // reservation pointing at "now" so callers can proceed to the
        // hard reserve (which will hit the idempotency cache).
        let now = now_timestamp_secs();
        return Ok(PendingReserve {
            amount_sats,
            timestamp_secs,
            expires_at_secs: now,
        });
    }

    // Reject timestamps too far in the future (clock skew protection).
    const MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;
    let guardian_now = now_timestamp_secs();
    if timestamp_secs > guardian_now + MAX_CLOCK_SKEW_SECS {
        return Err(InvalidInputs(format!(
            "soft reserve timestamp {timestamp_secs} is too far in the future \
             (guardian clock: {guardian_now})"
        )));
    }

    enclave
        .state
        .soft_reserve(wid, timestamp_secs, amount_sats, guardian_now)
        .await
}

// TODO: Support batched withdrawals (multiple wids per transaction).
async fn normal_withdrawal_inner(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<(Txid, StandardWithdrawalResponse, LimiterGuard)> {
    // 0) Validation
    if !enclave.is_fully_initialized() {
        return Err(EnclaveUninitialized);
    }

    // 1) Verify certificate (before acquiring limiter lock)
    let committee = enclave.state.get_committee()?;
    let threshold = enclave
        .config
        .committee_threshold()
        .expect("Committee threshold should be set");

    info!("Verifying request certificate.");
    verify_hashi_cert(committee, threshold, &signed_request)?;
    info!("Request certificate verified.");

    let (_, request) = signed_request.into_parts();

    // 2) Rate limits: acquire exclusive lock on limiter, consume tokens.
    //    The returned guard holds the mutex — no other withdrawal can proceed
    //    until this one is committed or reverted.
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
    let consumed_amount_sats = request.utxos().external_out_amount().to_sat();
    let wid = *request.wid();
    let limiter_guard = enclave
        .state
        .consume_from_limiter(
            wid,
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

/// RAII guard that holds the limiter mutex via an owned guard.
/// Reverts on drop unless committed.
pub struct LimiterGuard {
    guard: tokio::sync::OwnedMutexGuard<RateLimiter>,
    committed: bool,
}

impl LimiterGuard {
    pub(crate) fn new(guard: tokio::sync::OwnedMutexGuard<RateLimiter>) -> Self {
        Self {
            guard,
            committed: false,
        }
    }

    /// Snapshot of the limiter state AFTER the successful consume this guard
    /// wraps. Persisted into the withdrawal log so a subsequent session can
    /// rehydrate the bucket state on boot.
    pub fn limiter_state(&self) -> hashi_types::guardian::LimiterState {
        *self.guard.state()
    }

    /// Mark this withdrawal as successful. Prevents revert on drop.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for LimiterGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.guard.revert();
        }
    }
}

pub fn verify_hashi_cert<T: Serialize>(
    committee: Arc<HashiCommittee>,
    threshold: u64,
    signed_request: &HashiSigned<T>,
) -> GuardianResult<()> {
    committee
        .verify_signature_and_weight(signed_request, threshold)
        .map_err(|e| InvalidInputs(format!("signature verification failed {:?}", e)))
}

async fn log_withdrawal_success(
    enclave: &Enclave,
    wid: u64,
    msg: WithdrawalLogMessage,
    limiter_guard: LimiterGuard,
) -> GuardianResult<()> {
    match enclave.log_withdraw(msg).await {
        Ok(_) => {
            info!("Withdrawal {} logged.", wid);
            // Commit limiter consumption only after we've successfully logged.
            limiter_guard.commit();
            Ok(())
        }
        Err(e) => {
            // Logging failed => return Err (do not return signatures).
            // Note that LimiterGuard::Drop will revert the limiter
            error!("Logging withdrawal {} to S3 failed: {:?}", wid, e);
            Err(e)
        }
    }
}

async fn log_withdrawal_failure(
    enclave: &Enclave,
    wid: u64,
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
    use crate::OperatorInitTestArgs;
    use bitcoin::Network;
    use hashi_types::guardian::test_utils::create_btc_keypair;
    use hashi_types::guardian::LimiterState;
    use hashi_types::guardian::ProvisionerInitState;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::WithdrawalConfig;

    /// Sets up an enclave with a single committee and token bucket limiter.
    async fn setup_fully_initialized_enclave(
        network: Network,
        committee: HashiCommittee,
        max_bucket_capacity_sats: u64,
    ) -> Arc<Enclave> {
        let enclave = Enclave::create_operator_initialized_with(
            OperatorInitTestArgs::default().with_network(network),
        )
        .await;

        let enclave_kp = create_btc_keypair(&[8u8; 32]);
        let hashi_kp = create_btc_keypair(&[6u8; 32]);
        let hashi_btc_master_pubkey = hashi_kp.x_only_public_key().0;

        enclave.config.set_btc_keypair(enclave_kp).unwrap();
        enclave
            .config
            .set_hashi_btc_pk(hashi_btc_master_pubkey)
            .unwrap();

        let refill_rate = 0; // no refill in tests unless specified
        let withdrawal_config = WithdrawalConfig {
            committee_threshold: 1,
            refill_rate_sats_per_sec: refill_rate,
            max_bucket_capacity_sats,
        };
        enclave
            .config
            .set_withdrawal_config(withdrawal_config)
            .unwrap();

        let limiter_state = LimiterState {
            num_tokens_available: max_bucket_capacity_sats,
            last_updated_at: 0,
            next_seq: 0,
        };
        let init_state = ProvisionerInitState::new(
            committee,
            withdrawal_config,
            limiter_state,
            hashi_btc_master_pubkey,
        )
        .unwrap();
        enclave.state.init(init_state).unwrap();

        enclave
            .scratchpad
            .provisioner_init_logging_complete
            .set(())
            .expect("provisioner_init_logging_complete should only be set once");

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
            .external_out_amount()
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
            1,
            100,
            0,
        );
        let amount_sats = req1.message().utxos().external_out_amount().to_sat();
        // Bucket capacity == one withdrawal, so second will be rejected.
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, committee, amount_sats).await;

        let first = standard_withdrawal(enclave.clone(), req1).await;
        assert!(first.is_ok());

        // Second withdrawal with seq=1 and later timestamp — bucket is empty, no refill (rate=0).
        let (req2, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            2,
            200,
            1,
        );
        let second = standard_withdrawal(enclave, req2).await;
        assert!(matches!(
            second.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));
    }

    /// Retrying the same `wid` (e.g. after leader rotation or a lost
    /// response) returns the cached signed response and does NOT debit the
    /// bucket a second time. Bucket capacity is sized to exactly one
    /// withdrawal so a second debit would tip it over the rate limit.
    #[tokio::test]
    async fn test_standard_withdrawal_wid_cache_is_idempotent() {
        let wid = 42;
        let (req1, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            wid,
            100,
            0,
        );
        let amount_sats = req1.message().utxos().external_out_amount().to_sat();
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, committee.clone(), amount_sats).await;

        let first = standard_withdrawal(enclave.clone(), req1)
            .await
            .expect("first withdrawal succeeds");

        // Same wid, fresh timestamp + seq. Without the cache this would
        // fail with a seq mismatch (or debit the bucket a second time); the
        // cache short-circuits before any of that.
        let (req2, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            wid,
            200,
            1,
        );
        let second = standard_withdrawal(enclave.clone(), req2)
            .await
            .expect("retry serves cached response");
        assert_eq!(first, second, "cache must return identical signed response");

        // Bucket should still reflect exactly one debit.
        let limiter_state = enclave.state.limiter_state().await.unwrap();
        assert_eq!(limiter_state.next_seq, 1);
        assert_eq!(limiter_state.num_tokens_available, 0);
    }

    /// A failed withdrawal must NOT be cached — otherwise retries would
    /// permanently receive the same error even if the underlying cause
    /// (e.g. a corrupted one-off request) is gone on the next attempt.
    #[tokio::test]
    async fn test_standard_withdrawal_failures_not_cached() {
        // Bucket capacity = 0 so the first request fails with RateLimitExceeded.
        let (req1, committee) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            42,
            100,
            0,
        );
        let enclave = setup_fully_initialized_enclave(Network::Regtest, committee, 0).await;

        let first = standard_withdrawal(enclave.clone(), req1).await;
        assert!(matches!(
            first.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));

        // Retry with the same wid should NOT hit the cache — it gets
        // another attempt. It will still fail here (bucket still 0) but
        // via the live path, not a cached replay.
        let (req2, _) = StandardWithdrawalRequest::mock_signed_and_committee_with_seq(
            Network::Regtest,
            42,
            200,
            0,
        );
        let second = standard_withdrawal(enclave.clone(), req2).await;
        assert!(matches!(
            second.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));
        // Nothing was committed in either attempt.
        let limiter_state = enclave.state.limiter_state().await.unwrap();
        assert_eq!(limiter_state.next_seq, 0);
    }
}
