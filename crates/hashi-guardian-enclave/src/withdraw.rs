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
use axum::extract::State;
use axum::Json;
use bitcoin::key::Keypair;
use bitcoin::taproot::Signature;
use bitcoin::{Network, XOnlyPublicKey};
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::bitcoin_utils::{construct_signing_messages, TxUTXOs};
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Delayed withdrawal
///
/// Throws an error if:
///     1. Validation issue: invalid cert or request contents
///     2. S3 logging issue: Unable to log to S3
pub async fn delayed_withdraw(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<HashiNodeSigned<DelayedWithdrawalRequest>>,
) -> GuardianResult<()> {
    info!("/delayed_withdraw - Received request.");

    // ------------------------ Validation ------------------------

    // verify enclave is in right state
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("enclave is not fully initialized".into()));
    }

    // verify request cert
    let committee = enclave.get_committee();
    let request = request.verify_cert(&committee)?;
    info!("Request cert verified.");

    // validate request data
    let network = enclave
        .bitcoin_network()
        .expect("network should be initialized in operator_init");
    request.validate(network, true)?;
    info!("Request validated. WithdrawalID: {}.", request.wid());

    // ------------------------ Record ------------------------

    // What should the order be between updating pending_delayed_withdrawals and writing to S3?
    // 1) update pending_delayed_withdrawals -> write to S3: If writing to S3 fails, what to do?
    //    should the caller retry? if so, should we not error out upon seeing a duplicate request & instead allow S3 log write?
    // 2) write to S3 -> update pending_delayed_withdrawals: in this direction, S3 logging failures
    //    implicitly imply that caller should retry. so we choose this option.

    {
        // Pre S3 write detection of duplicates to keep the logs clean
        let withdraw_state = enclave.get_withdraw_state().await; // LOCK acquired
        if withdraw_state
            .pending_delayed_withdrawals
            .contains_key(&request.wid())
        {
            warn!(
                "Duplicate delayed_withdraw request. WithdrawalID: {}.",
                request.wid()
            );
            return Err(InvalidInputs("duplicate withdrawal ID".into()));
        }
    } // LOCK released

    // Log to S3. Notes:
    // 1. If enclave dies after writing to S3, then we have a S3 log without a corresponding
    //    entry in pending_delayed_withdrawals. Recon script will then be triggered which repopulates
    //    the new enclave with the right value of pending_delayed_withdrawals.
    // 2: It is possible that we have a duplicate S3 log for a single withdrawal.
    //    For example, a race between two requests with the exact same contents could cause it.
    //    Recon script can pick the timestamp corresponding to the first occurrence in that case.
    info!("Logging delayed withdrawal to S3.");
    enclave
        .sign_and_log(LogMessage::DelayedWithdrawal(request.clone()))
        .await?;

    let mut withdraw_state = enclave.get_withdraw_state().await; // LOCK acquired
    match withdraw_state
        .pending_delayed_withdrawals
        .entry(request.wid())
    {
        Entry::Vacant(v) => {
            v.insert(request.clone());
            info!(
                "Delayed withdrawal recorded. WithdrawalID: {}.",
                request.wid()
            );
            Ok(())
        }
        // if there is an entry already, we just error. happens only in race conditions.
        Entry::Occupied(_) => {
            warn!(
                "Race condition: duplicate withdrawal ID after S3 write. WithdrawalID: {}.",
                request.wid()
            );
            Err(InvalidInputs("duplicate withdrawal ID".into()))
        }
    }
}

/// Immediate withdrawal. Two types of requests:
///     Type 1: a request expected to be below the rate limits
///     Type 2: a previously seen delayed_withdraw() request
///
/// Throws an error if:
///     1. Validation issue: invalid cert or request contents
///     2. S3 logging issue: Unable to log to S3
///     3. Type 1 request gets rate limited
///     4. Type 2 request uses insufficient delay
pub async fn immediate_withdraw(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<HashiNodeSigned<ImmediateWithdrawalRequest>>,
) -> GuardianResult<Json<GuardianSigned<ImmediateWithdrawalResponse>>> {
    info!("/immediate_withdraw - Received request.");

    // ------------------------ Validation ------------------------

    // verify enclave is in right state
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("enclave is not fully initialized".into()));
    }

    // verify request cert
    let committee = enclave.get_committee();
    let request = request.verify_cert(&committee)?;
    info!("Request cert verified.");

    // validate request data
    let network = enclave
        .bitcoin_network()
        .expect("network should be initialized in operator_init");
    request.validate(network)?;
    info!(
        "Request validated. WithdrawalID: {}, Delayed: {}.",
        request.wid(),
        request.is_delayed()
    );

    // fetch all config we'd need later on
    let enclave_btc_keypair = enclave.btc_keypair().expect("btc key pair should be set");
    let hashi_btc_pk = enclave
        .hashi_btc_pk()
        .expect("hashi btc pub key should be set");

    // ------------------------ Apply rate limits / check delay ------------------------

    if request.is_delayed() {
        info!("Checking delayed withdrawal eligibility.");
        let min_delay = enclave
            .delayed_withdrawals_delay()
            .expect("withdrawal config should be set");

        // Acquire lock
        let ws = enclave.get_withdraw_state().await;

        // Check if we have seen this request before
        approve_delayed_withdrawal(&request, &ws.pending_delayed_withdrawals, min_delay)?;
        // Release lock

        info!("Delayed withdrawal approved.");
    } else {
        // Check and apply rate limits
        info!("Checking rate limits.");
        apply_rate_limits(request.all_utxos().external_out_amount().to_sat())?;
        info!("Rate limit check passed.");
    }

    // ------------------------ Sign transaction ------------------------

    let signatures = sign(
        enclave_btc_keypair,
        hashi_btc_pk,
        request.all_utxos(),
        network,
    );
    let response = ImmediateWithdrawalResponse {
        enclave_signatures: signatures,
    };

    // ------------------------ S3 logging & state updates ------------------------

    // Notes re operation order:
    // 1. We grab the lock from the moment we know the withdrawal number until the moment it gets updated
    //    so that no other thread sees the same value (i.e., A, B & C should be covered by the lock).
    // 2. Operations B and C must happen atomically in a live enclave (we're okay with enclave dying between).
    //    This is because: if B succeeds and enclave error returns before C, then the next call to enclave
    //    will panic during A. This is why we do C immediately after B.
    // 3. C & D must happen after B for reasons outlined at the start of this file.

    // A) Check counter.log does not exist on S3 (dup enclave attack prevention)
    let mut enclave_state = enclave.get_withdraw_state().await; // LOCK acquired
    let num_withdrawals = enclave_state.num_withdrawals;
    if enclave.iwlog_exists(num_withdrawals).await? {
        panic!("duplicate enclave attack detected");
        // TODO: If sign_and_log does not fail if a log key exists, then check again post S3 write.
    }

    // Error handling portion of D: Early fail to avoid unnecessary S3 logs
    if request.is_delayed()
        && !enclave_state
            .pending_delayed_withdrawals
            .contains_key(&request.wid())
    {
        warn!(
            "Race condition: delayed withdrawal already processed. WithdrawalID: {}.",
            request.wid()
        );
        return Err(InvalidInputs("duplicate call".into()));
        // this error can be thrown if there is a race between two exact same requests
    }

    // B) Log to S3
    info!(
        "Logging immediate withdrawal to S3. WithdrawalID: {}, WithdrawCount: {}.",
        request.wid(),
        num_withdrawals
    );
    enclave
        .sign_and_log(LogMessage::ImmediateWithdrawal {
            request: request.clone(),
            response: response.clone(),
            withdraw_count: num_withdrawals,
        })
        .await?;
    info!("Withdrawal logged to S3.");

    // C) Increment withdraw counter
    enclave_state.num_withdrawals += 1;

    // D) Update pending withdrawals list for delayed reqs
    if request.is_delayed() {
        enclave_state
            .pending_delayed_withdrawals
            .remove(&request.wid())
            .expect("entry existence confirmed before");
    }

    info!(
        "Withdrawal processed successfully. WithdrawalID: {}",
        request.wid()
    );

    Ok(Json(enclave.sign(response)))
}

/// Throws an error if:
///     1. an earlier delayed withdrawal record is not found with matching wid or external_outs
///     2. not enough time has elapsed
fn approve_delayed_withdrawal(
    cur_withdrawal: &ImmediateWithdrawalRequest,
    pending_withdrawals: &HashMap<WithdrawalID, DelayedWithdrawalRequest>,
    delayed_withdrawals_delay: Duration,
) -> GuardianResult<()> {
    // Find the matching record
    let pending_withdrawal = match pending_withdrawals.get(&cur_withdrawal.wid()) {
        Some(x) => x,
        None => {
            return Err(InvalidInputs(
                "Could not find an earlier delayed withdrawal record".into(),
            ))
        }
    };

    // Check the dest (both address and amount)
    if !pending_withdrawal
        .external_outs()
        .iter()
        .eq(cur_withdrawal.all_utxos().external_outs())
    {
        return Err(InvalidInputs(format!(
            "WithdrawID matches but external destination \
                                         does not match {:?} {:?}",
            pending_withdrawal.external_outs(),
            cur_withdrawal.all_utxos().external_outs()
        )));
    }

    // Check that the gap is sufficiently long
    // TODO: confirm below impl after confirming HashiTime type
    let required_timestamp = delayed_withdrawals_delay.as_secs() + pending_withdrawal.timestamp();
    if cur_withdrawal.timestamp() < required_timestamp {
        return Err(InvalidInputs(format!(
            "Request too early. Required time: {:?}, Actual time: {:?}",
            required_timestamp,
            cur_withdrawal.timestamp()
        )));
    }

    Ok(())
}

fn apply_rate_limits(_satoshis: u64) -> GuardianResult<()> {
    todo!()
}

fn sign(
    enclave_keypair: &Keypair,
    hashi_pubkey: &XOnlyPublicKey,
    tx_utxos: &TxUTXOs,
    network: Network,
) -> Vec<Signature> {
    let messages = construct_signing_messages(
        tx_utxos,
        &enclave_keypair.x_only_public_key().0,
        hashi_pubkey,
        network,
    );
    sign_btc_tx(&messages, enclave_keypair)
}
