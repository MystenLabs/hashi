use crate::GuardianError::GenericError;
use crate::GuardianResult;
use axum::Json;
use fastcrypto::hash::{Blake2b256, HashFunction}; // kept only for fingerprint logging
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::encrypt_share;
use hashi_guardian_shared::crypto::k256_secret_key_to_shares;
use hashi_guardian_shared::*;
use k256::SecretKey;
use tracing::error;
use tracing::info;

// Stateless request
pub async fn setup_new_key(
    Json(request): Json<SetupNewKeyRequest>,
) -> GuardianResult<Json<SetupNewKeyResponse>> {
    info!("📥 /setup_new_key - Received request");

    info!("🔍 Validating key provisioner public keys...");
    let key_provisioner_pks: Vec<EncPubKey> = request
        .try_into()
        .map_err(|e| GenericError(format!("Failed to deserialize public key: {}", e)))?;
    if key_provisioner_pks.len() != LIMIT {
        error!(
            "❌ Wrong number of public keys: {} (expected {})",
            key_provisioner_pks.len(),
            LIMIT
        );
        return Err(GenericError(format!(
            "Only {} public keys provided",
            key_provisioner_pks.len()
        )));
    }
    info!("✅ Received {} public keys", LIMIT);

    info!("🔑 Generating new Bitcoin private key...");
    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    // Note: Outputting a fingerprint for testing purposes. We can remove it
    let sk_hash = Blake2b256::digest(&sk.to_bytes());
    info!("✅ Bitcoin key generated with fingerprint {}", sk_hash);

    info!(
        "🔪 Splitting secret into {} shares (threshold: {})...",
        LIMIT, THRESHOLD
    );
    let shares = k256_secret_key_to_shares(sk)?;

    info!("🔐 Encrypting shares for key provisioners...");
    let mut encrypted_shares = vec![];
    let mut share_commitments = vec![];
    for i in 0..LIMIT {
        let share = &shares[i];
        let pk = &key_provisioner_pks[i];
        let encrypted = encrypt_share(share, pk, None)?;
        let commitment = commit_share(share)?;
        encrypted_shares.push(encrypted);
        share_commitments.push(commitment);
    }
    info!("✅ All {} shares encrypted", LIMIT);
    info!("📤 Sending encrypted shares and commitments to client");

    Ok(Json(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    }))
}
