use crate::Enclave;
use bitcoin::Network;
use hashi_guardian_shared::bitcoin_utils::construct_signing_messages;
use hashi_guardian_shared::bitcoin_utils::sign_btc_tx;
use hashi_guardian_shared::bitcoin_utils::TxUTXOs;
use hashi_guardian_shared::BitcoinKeypair;
use hashi_guardian_shared::BitcoinPubkey;
use hashi_guardian_shared::BitcoinSignature;
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
use tracing::info;

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
    request: HashiSigned<NormalWithdrawalRequest>,
) -> GuardianResult<GuardianSigned<NormalWithdrawalResponse>> {
    info!("/normal_withdrawal - Received request.");

    // 0) Validation
    if !enclave.is_fully_initialized() {
        return Err(InvalidInputs("Enclave is not fully initialized".into()));
    }

    let epoch = request.epoch();
    let signers = request.signers_bitmap_bytes().to_vec(); // for logging
    let committee = enclave.state.get_committee(epoch)?;
    let threshold = enclave
        .config
        .committee_threshold()
        .expect("Committee threshold should be set");

    info!("Verifying request certificate.");
    verify_hashi_cert(committee, threshold, &request)?;
    info!("Request certificate verified.");

    let request = request.into_message();

    // 1) Rate limits: grab the available limit
    info!("Checking rate limits.");
    enclave
        .state
        .consume_from_limiter(epoch, request.utxos().external_out_amount())?;
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
        enclave_signatures: signatures,
    };
    info!("BTC signatures generated.");

    // 3) Log to S3
    let request_wid = *request.wid();
    info!("Logging withdrawal. WithdrawalID: {}.", request_wid);
    // Note: Signing here is not needed for security, but we do it as good practice.
    enclave
        .sign_and_log(LogMessage::NormalWithdrawalSuccess {
            request,
            response: response.clone(),
            signers,
        })
        .await?;
    // TODO: Reset the limiter before returning an Err?

    info!("Withdrawal logged. WithdrawalID: {}.", request_wid);

    // Note: Signing here is not needed for security, but we do it as good practice.
    Ok(enclave.sign(response))
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
