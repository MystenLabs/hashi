use crate::Enclave;
use bitcoin::Amount;
use bitcoin::Network;
use hashi_guardian_shared::bitcoin_utils::construct_signing_messages;
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::bitcoin_utils::TxUTXOs;
use hashi_guardian_shared::BitcoinKeypair;
use hashi_guardian_shared::BitcoinPubkey;
use hashi_guardian_shared::BitcoinSignature;
use hashi_guardian_shared::GuardianError;
use hashi_guardian_shared::GuardianError::InternalError;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::GuardianResult;
use hashi_guardian_shared::GuardianSigned;
use hashi_guardian_shared::HashiCommittee;
use hashi_guardian_shared::HashiSigned;
use hashi_guardian_shared::LogMessage;
use hashi_guardian_shared::NormalWithdrawalRequest;
use hashi_guardian_shared::NormalWithdrawalResponse;
use serde::Serialize;
use std::sync::Arc;
use tracing::error;
use tracing::info;

/// RAII guard to ensure limiter consumption is reverted on any error path.
struct LimiterGuard {
    enclave: Arc<Enclave>,
    epoch: u64,
    amount: Amount,
    committed: bool,
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

#[allow(dead_code)]
pub fn verify_hashi_cert<T: Serialize>(
    committee: Arc<HashiCommittee>,
    threshold: u64,
    signed_request: &HashiSigned<T>,
) -> GuardianResult<()> {
    committee
        .verify_signature_and_weight(signed_request, threshold)
        .map_err(|e| InvalidInputs(format!("signature verification failed {:?}", e)))
}

#[allow(dead_code)]
pub async fn normal_withdrawal(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<NormalWithdrawalRequest>,
) -> GuardianResult<GuardianSigned<NormalWithdrawalResponse>> {
    info!("/normal_withdrawal - Received request.");

    let unsigned_request = signed_request.message().clone(); // for logging
    let wid = *unsigned_request.wid();
    let request_signature = signed_request.committee_signature().clone(); // for logging

    match normal_withdrawal_inner(enclave.clone(), signed_request) {
        Ok((response, limiter_guard)) => {
            info!("Withdrawal {} processed successfully. Logging to S3.", wid);
            let msg = LogMessage::NormalWithdrawalSuccess {
                response: response.clone(),
                request_signature,
            };
            log_withdrawal_success(enclave.as_ref(), wid, msg, limiter_guard).await?;
            Ok(enclave.sign(response))
        }
        Err(withdraw_err) => {
            error!("Withdrawal {} failed: {:?}", wid, withdraw_err);
            let msg = LogMessage::NormalWithdrawalFailure {
                unsigned_request,
                request_signature,
                error: withdraw_err.clone(),
            };
            log_withdrawal_failure(enclave.as_ref(), wid, msg, &withdraw_err).await?;
            Err(withdraw_err)
        }
    }
}

fn normal_withdrawal_inner(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<NormalWithdrawalRequest>,
) -> GuardianResult<(NormalWithdrawalResponse, LimiterGuard)> {
    // 0) Validation
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("Enclave is not fully initialized".into()));
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
    let enclave_btc_keypair = enclave
        .config
        .btc_keypair()
        .expect("BTC keypair should be set");
    let hashi_btc_pk = enclave
        .config
        .hashi_btc_pk()
        .expect("Hashi BTC public key should be set");
    let network = enclave
        .config
        .bitcoin_network()
        .expect("Bitcoin network should be set");
    let signatures = sign(enclave_btc_keypair, hashi_btc_pk, request.utxos(), network);
    let response = NormalWithdrawalResponse {
        request,
        enclave_signatures: signatures,
    };
    info!("BTC signatures generated.");

    Ok((response, limiter_guard))
}

#[allow(dead_code)]
fn sign(
    enclave_keypair: &BitcoinKeypair,
    hashi_pubkey: &BitcoinPubkey,
    tx_utxos: &TxUTXOs,
    network: Network,
) -> Vec<BitcoinSignature> {
    let messages = construct_signing_messages(
        tx_utxos,
        &enclave_keypair.x_only_public_key().0,
        hashi_pubkey,
        network,
    );
    sign_btc_tx(&messages, enclave_keypair)
}

async fn log_withdrawal_success(
    enclave: &Enclave,
    wid: u64,
    msg: LogMessage,
    limiter_guard: LimiterGuard,
) -> GuardianResult<()> {
    match enclave.sign_and_log(msg).await {
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
            Err(InternalError("S3 logging failed".into()))
        }
    }
}

async fn log_withdrawal_failure(
    enclave: &Enclave,
    wid: u64,
    msg: LogMessage,
    withdraw_err: &GuardianError,
) -> GuardianResult<()> {
    if let Err(log_err) = enclave.sign_and_log(msg).await {
        error!("Logging withdrawal {} to S3 failed: {:?}", wid, log_err);
        return Err(InternalError(format!(
            "Failed to log withdrawal error {} due to S3 logging error {}",
            withdraw_err, log_err
        )));
    }

    Ok(())
}
