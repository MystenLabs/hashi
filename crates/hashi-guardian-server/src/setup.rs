use crate::GuardianError::GenericError;
use crate::GuardianResult;
use axum::Json;
use fastcrypto::hash::{Blake2b256, HashFunction};
use hashi_guardian_shared::{
    encrypt, EncPubKey, MyShare, SetupNewKeyRequest, SetupNewKeyResponse, SECRET_SHARING_N,
    SECRET_SHARING_T,
};
use k256::SecretKey;
use tracing::{error, info};
use vsss_rs::{shamir, IdentifierPrimeField};

// Stateless request
pub async fn setup_new_key(
    Json(request): Json<SetupNewKeyRequest>,
) -> GuardianResult<Json<SetupNewKeyResponse>> {
    info!("📥 /setup_new_key - Received request");
    const THRESHOLD: usize = SECRET_SHARING_T as usize;
    const LIMIT: usize = SECRET_SHARING_N as usize;

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
    info!("✅ Bitcoin key generated");
    info!(
        "🔪 Splitting secret into {} shares (threshold: {})...",
        LIMIT, THRESHOLD
    );
    let nzs = sk.to_nonzero_scalar();
    let shared_secret = IdentifierPrimeField(*nzs.as_ref());
    let shares = shamir::split_secret::<MyShare>(THRESHOLD, LIMIT, &shared_secret, &mut rng)
        .map_err(|e| GenericError(format!("Failed to split secret: {}", e)))?;
    info!("✅ Secret split into {} shares", LIMIT);

    info!("🔐 Encrypting shares for key provisioners...");
    let mut encrypted_shares = vec![];
    let mut share_commitments = vec![];
    for i in 0..LIMIT {
        let share = &shares[i];
        let share_id = share.identifier;
        let share_value = share.value;
        let bytes = bincode::serialize(&share_value)
            .map_err(|e| GenericError(format!("Failed to serialize share: {}", e)))?;
        let pk = &key_provisioner_pks[i];
        encrypted_shares.push((share_id, encrypt(&bytes, pk, None)?).into());
        share_commitments.push((share_id, Blake2b256::digest(&bytes)).into());
    }
    info!("✅ All {} shares encrypted", LIMIT);
    info!("📤 Sending encrypted shares and commitments to client");

    Ok(Json(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    }))
}
