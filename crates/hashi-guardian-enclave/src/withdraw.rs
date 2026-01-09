//! Guardian withdraw utilities
//!
//! A successful withdrawal means a (i) successful S3 write, and (ii) an error-free response.
//! S3 logs are used when restarting the enclave. Since S3 writes are prone to higher failures,
//! the pattern employed in this file is: log to s3 and then update state. This ensures that all the
//! state updates are committed to S3.
//!
//! Relatedly, the code in this file follows the following invariant: Killing the enclave at any point
//! after a S3 write & restarting it with the recon script should lead to an enclave with the same
//! state as another enclave that didn't die in the first place.

use crate::Enclave;
use bitcoin::Network;
use bitcoin::XOnlyPublicKey;
use hashi_guardian_shared::bitcoin_utils::construct_signing_messages;
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::bitcoin_utils::TxUTXOs;
use hashi_guardian_shared::BitcoinKeypair;
use hashi_guardian_shared::BitcoinSignature;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::GuardianResult;
use hashi_guardian_shared::GuardianSigned;
use hashi_guardian_shared::HashiSigned;
use hashi_guardian_shared::LogMessage;
use hashi_guardian_shared::NormalWithdrawalRequest;
use hashi_guardian_shared::NormalWithdrawalResponse;
use serde::Serialize;
use std::sync::Arc;
use tracing::info;

pub fn verify_hashi_cert<T: Serialize>(
    enclave: Arc<Enclave>,
    signed_request: HashiSigned<T>,
) -> GuardianResult<T> {
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("meant to be called only post init".into()));
    }

    let committee = enclave.get_committee();
    let threshold = enclave
        .committee_threshold()
        .expect("committee threshold not found in enclave");

    committee
        .verify_signature_and_weight(&signed_request, threshold)
        .map_err(|e| InvalidInputs(format!("signature verification failed {:?}", e)))?;

    Ok(signed_request.into_message())
}

fn sign(
    enclave_keypair: &BitcoinKeypair,
    hashi_pubkey: &XOnlyPublicKey,
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

pub async fn normal_withdrawal(
    enclave: Arc<Enclave>,
    request: HashiSigned<NormalWithdrawalRequest>,
) -> GuardianResult<GuardianSigned<NormalWithdrawalResponse>> {
    info!("/normal_withdrawal - Received request.");

    // ------------------------ Validation ------------------------
    // verify enclave is in right state
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("enclave is not fully initialized".into()));
    }

    // verify request cert
    let request = verify_hashi_cert(enclave.clone(), request)?; // clone is cheap
    info!("Request cert verified.");

    // validate request data
    let network = enclave
        .bitcoin_network()
        .expect("network should be initialized in operator_init");
    // TODO: validate request utxo's match network
    // request.validate(network)?;

    // ------------------------ Setup ------------------------

    let enclave_btc_keypair = enclave.btc_keypair().expect("btc key pair should be set");
    let hashi_btc_pk = enclave
        .hashi_btc_pk()
        .expect("hashi btc pub key should be set");

    // ------------------------ Rate limits ------------------------

    // Check and apply rate limits
    info!("Checking rate limits.");
    apply_rate_limits(request.all_utxos().external_out_amount().to_sat())?;
    info!("Rate limit check passed.");

    let signatures = sign(
        enclave_btc_keypair,
        hashi_btc_pk,
        request.all_utxos(),
        network,
    );
    let response = NormalWithdrawalResponse {
        enclave_signatures: signatures,
    };
    info!("Enclave btc signature generated.");

    // ------------------------ S3 logging & state updates ------------------------
    // Notes:
    // 1. Operation order: See text at the top of this file for why B comes before C.
    // 2. If enclave dies after B finishes but before C completes, then the next call to this fn will panic (in A).
    //    Ideally, we would like to execute B & C atomically (together or neither). Doing C right after B is the next best thing.
    // 3. Lock is currently held from A through to C to simplify internal logic.

    // A) Check counter.log does not exist on S3 (dup enclave attack prevention)
    let mut enclave_state = enclave.acquire_withdrawal_state_lock().await; // LOCK acquired
    let num_withdrawals = enclave_state.num_withdrawals;
    if enclave.iwlog_exists(num_withdrawals).await? {
        panic!("duplicate enclave attack detected");
        // TODO: If sign_and_log does not fail if a log key exists, then check again post S3 write.
    }

    // B) Log to S3
    info!(
        "Logging immediate withdrawal to S3. WithdrawalID: {}, WithdrawCount: {}.",
        request.wid(),
        num_withdrawals
    );
    enclave
        .sign_and_log(LogMessage::NormalWithdrawalSuccess {
            request: request.clone(),
            response: response.clone(),
            withdraw_count: num_withdrawals,
        })
        .await?;
    info!("Withdrawal logged to S3.");

    // C) Increment withdraw counter
    enclave_state.num_withdrawals += 1;

    info!(
        "Withdrawal processed successfully. WithdrawalID: {}",
        request.wid()
    );

    Ok(enclave.sign(response))
}

fn apply_rate_limits(_satoshis: u64) -> GuardianResult<()> {
    todo!("waiting for clarity over rate limiter")
}
