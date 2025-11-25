use crate::s3_logger::test_s3_connectivity;
use crate::Enclave;
use axum::extract::State;
use axum::Json;
use hashi_guardian_shared::*;
use hpke::Serializable;
use std::sync::Arc;
use tracing::info;

/// Health check endpoint that returns server status and encryption public key
/// PubKey is useful for test environments where enclave attestation doesn't work
pub async fn health_check(State(enclave): State<Arc<Enclave>>) -> Json<HealthCheckResponse> {
    info!("🏥 /health_check - Received request");

    let btc_key_configured = enclave.btc_key().is_ok();

    let s3_configured = {
        match enclave.s3_logger() {
            Ok(logger) => match test_s3_connectivity(&logger).await {
                Ok(_) => true,
                Err(_) => false,
            },
            Err(_) => false,
        }
    };

    let shares_received = enclave.decrypted_shares().lock().await.len();

    // Include public key for non-enclave environments
    let enc_public_key = {
        let pk = enclave.encryption_public_key();
        Some(pk.to_bytes().to_vec())
    };

    info!("   S3 configured: {}", s3_configured);
    info!("   BTC key configured: {}", btc_key_configured);
    info!("   Shares received: {}/{}", shares_received, THRESHOLD);
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
