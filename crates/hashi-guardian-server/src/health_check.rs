use crate::s3_logger::test_s3_connectivity;
use crate::Enclave;
use axum::extract::State;
use axum::Json;
use hashi_guardian_shared::{HealthCheckResponse, SECRET_SHARING_T};
use hpke::Serializable;
use std::sync::Arc;
use tracing::info;

/// Health check endpoint that returns server status and encryption public key
/// PubKey is useful for test environments where enclave attestation doesn't work
pub async fn health_check(State(enclave): State<Arc<Enclave>>) -> Json<HealthCheckResponse> {
    info!("🏥 /health_check - Received request");

    let btc_key_configured = enclave.config.bitcoin_key.get().is_some();

    let s3_configured = {
        match enclave.config.s3_logger.get() {
            Some(logger) => match test_s3_connectivity(&logger).await {
                Ok(_) => true,
                Err(_) => false,
            },
            None => false,
        }
    };

    let shares_received = enclave
        .scratchpad
        .decrypted_shares
        .lock()
        .map(|shares| shares.len())
        .unwrap_or(0);

    // Include public key for non-enclave environments
    let enc_public_key = {
        let pk = enclave.config.eph_keys.encryption_keys.public();
        Some(pk.to_bytes().to_vec())
    };

    info!("   S3 configured: {}", s3_configured);
    info!("   BTC key configured: {}", btc_key_configured);
    info!(
        "   Shares received: {}/{}",
        shares_received, SECRET_SHARING_T
    );
    info!(
        "   Encryption public key: {} bytes",
        enc_public_key.as_ref().map(|k| k.len()).unwrap_or(0)
    );

    Json(HealthCheckResponse {
        s3_configured,
        btc_key_configured,
        shares_received,
        enc_public_key,
    })
}
