use crate::Enclave;
use bitcoin::Amount;
use hashi_types::guardian::GuardianError;
use hashi_types::guardian::GuardianError::EnclaveUninitialized;
use hashi_types::guardian::GuardianError::InternalError;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::GuardianSigned;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::HashiSigned;
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

    match normal_withdrawal_inner(enclave.clone(), signed_request) {
        Ok((response, limiter_guard)) => {
            info!("Withdrawal {} processed successfully. Logging to S3.", wid);
            let msg = WithdrawalLogMessage::Success {
                request_data: unsigned_request,
                request_sign: request_signature,
                response: response.clone(),
            };
            log_withdrawal_success(enclave.as_ref(), wid, msg, limiter_guard).await?;
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

/// RAII guard to ensure limiter consumption is reverted on any error path.
struct LimiterGuard {
    enclave: Arc<Enclave>,
    epoch: u64,
    amount: Amount,
    committed: bool,
}

fn normal_withdrawal_inner(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<StandardWithdrawalRequest>,
) -> GuardianResult<(StandardWithdrawalResponse, LimiterGuard)> {
    // 0) Validation
    if !enclave.is_fully_initialized() {
        return Err(EnclaveUninitialized);
    }

    let epoch = signed_request.epoch();
    let committee = enclave.state.get_committee(epoch)?;
    let threshold = enclave
        .config
        .committee_threshold()
        .expect("Committee threshold should be set");

    info!("Verifying request certificate.");
    verify_hashi_cert(committee, threshold, &signed_request)?;
    info!("Request certificate verified.");

    let (_, request) = signed_request.into_parts();

    // 1) Rate limits: reserve from the available limit (automatically reverted on failure)
    info!("Checking rate limits.");
    let consumed_amount = request.utxos().external_out_amount();
    let limiter_guard = LimiterGuard::new(enclave.clone(), epoch, consumed_amount)?;
    info!("Rate limit check passed.");

    // 2) Sign tx
    info!("Generating BTC signatures.");
    let signatures = enclave
        .config
        .btc_sign(request.utxos())
        .expect("All BTC keys should be set");
    let response = StandardWithdrawalResponse {
        enclave_signatures: signatures,
    };
    info!("BTC signatures generated.");

    Ok((response, limiter_guard))
}

impl LimiterGuard {
    fn new(enclave: Arc<Enclave>, epoch: u64, amount: Amount) -> GuardianResult<Self> {
        enclave.state.consume_from_limiter(epoch, amount)?;
        Ok(Self {
            enclave,
            epoch,
            amount,
            committed: false,
        })
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for LimiterGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // Note: The only downside with the current RAII approach is that we are unable to propagate
        // errors in revert_limiter. But that function should not fail normally, so this should be rare.
        if let Err(e) = self.enclave.state.revert_limiter(self.epoch, self.amount) {
            // Never panic in Drop; best-effort revert and local error log.
            error!(
                epoch = self.epoch,
                ?e,
                "failed to revert limiter during drop"
            );
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
    use bitcoin::Amount;
    use bitcoin::Network;
    use hashi_types::guardian::epoch_store::EpochWindow;
    use hashi_types::guardian::test_utils::create_btc_keypair;
    use hashi_types::guardian::CommitteeStore;
    use hashi_types::guardian::ProvisionerInitState;
    use hashi_types::guardian::RateLimiter;
    use hashi_types::guardian::StandardWithdrawalRequest;
    use hashi_types::guardian::WithdrawalConfig;
    use hashi_types::guardian::WithdrawalState;
    use std::num::NonZeroU16;
    use std::time::Duration;

    /// Sets up an enclave with a one-epoch window and provided committee, rate limits.
    async fn setup_fully_initialized_enclave(
        network: Network,
        epoch: u64,
        committee: HashiCommittee,
        max_withdrawable_per_epoch: Amount,
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

        let withdrawal_config = WithdrawalConfig {
            committee_threshold: 1,
            delayed_withdrawals_min_delay: Duration::from_secs(1),
            delayed_withdrawals_timeout: Duration::from_secs(60),
        };
        enclave
            .config
            .set_withdrawal_config(withdrawal_config.clone())
            .unwrap();

        let epoch_window = EpochWindow::new(epoch, NonZeroU16::new(1).unwrap());
        let limiter = RateLimiter::new(
            epoch_window,
            vec![Amount::from_sat(0)],
            max_withdrawable_per_epoch,
        )
        .unwrap();
        let withdrawal_state = WithdrawalState::new(limiter);
        let committee_store = CommitteeStore::new(epoch_window, vec![committee]).unwrap();
        let init_state = ProvisionerInitState::new(
            committee_store,
            withdrawal_config,
            withdrawal_state,
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

    #[test]
    fn test_normal_withdrawal_inner_requires_full_init() {
        let enclave = Enclave::create_with_random_keys();
        let signed_request = StandardWithdrawalRequest::mock_signed_for_testing(Network::Regtest);
        let result = normal_withdrawal_inner(enclave, signed_request);
        assert!(matches!(result, Err(EnclaveUninitialized)));
    }

    #[tokio::test]
    async fn test_normal_withdrawal() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_for_testing(Network::Regtest);
        let epoch = signed_request.epoch();
        let amount = signed_request.message().utxos().external_out_amount();
        // Set request amount as the max withdrawable
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, epoch, committee, amount).await;

        let result = normal_withdrawal_inner(enclave, signed_request);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_standard_withdrawal_rate_limit_exceeded() {
        let (signed_request, committee) =
            StandardWithdrawalRequest::mock_signed_and_committee_for_testing(Network::Regtest);
        let epoch = signed_request.epoch();
        let amount = signed_request.message().utxos().external_out_amount();
        // Set request amount as the max withdrawable
        let enclave =
            setup_fully_initialized_enclave(Network::Regtest, epoch, committee, amount).await;

        let first = standard_withdrawal(enclave.clone(), signed_request.clone()).await;
        assert!(first.is_ok());

        let second = standard_withdrawal(enclave, signed_request).await;
        assert!(matches!(
            second.unwrap_err(),
            GuardianError::RateLimitExceeded
        ));
    }
}
