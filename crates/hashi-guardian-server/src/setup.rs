use crate::GuardianResult;
use axum::Json;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest}; // kept only for fingerprint logging
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::encrypt_share;
use hashi_guardian_shared::crypto::split_secret;
use hashi_guardian_shared::crypto::NUM_OF_SHARES;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use hpke::Deserializable;
use k256::SecretKey;
use tracing::error;
use tracing::info;

// Stateless request
pub async fn setup_new_key(
    Json(request): Json<Vec<Vec<u8>>>,
) -> GuardianResult<Json<(Vec<EncryptedShare>, Vec<ShareCommitment>)>> {
    info!("/setup_new_key - Received request");

    info!("Validating key provisioner public keys...");
    let key_provisioner_pks: Vec<EncPubKey> = request
        .into_iter()
        .map(|bytes| EncPubKey::from_bytes(&bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| InvalidInputs(format!("Failed to deserialize public key: {}", e)))?;
    if key_provisioner_pks.len() != NUM_OF_SHARES {
        error!(
            "Wrong number of public keys: {} (expected {})",
            key_provisioner_pks.len(),
            NUM_OF_SHARES
        );
        return Err(InvalidInputs(format!(
            "Only {} public keys provided",
            key_provisioner_pks.len()
        )));
    }
    info!("Received {} public keys", NUM_OF_SHARES);

    info!("Generating new Bitcoin private key...");
    let mut rng = rand::thread_rng();
    let sk = SecretKey::random(&mut rng);
    // Note: Outputting a fingerprint for testing purposes. We can remove it
    let sk_hash = Blake2b::<U32>::digest(sk.to_bytes().as_slice());
    info!("Bitcoin key generated with fingerprint {:x}", sk_hash);

    info!(
        "🔪 Splitting secret into {} shares (threshold: {})...",
        NUM_OF_SHARES, THRESHOLD
    );
    let shares = split_secret(&sk, &mut rng);

    info!("Encrypting shares for key provisioners...");
    let mut encrypted_shares = vec![];
    let mut share_commitments = vec![];
    for i in 0..NUM_OF_SHARES {
        let share = &shares[i];
        let pk = &key_provisioner_pks[i];
        let encrypted = encrypt_share(share, pk, None, &mut rng)?;
        let commitment = commit_share(share);
        encrypted_shares.push(encrypted);
        share_commitments.push(commitment);
    }
    info!("All {} shares encrypted", NUM_OF_SHARES);
    info!("Sending encrypted shares and commitments to client");

    Ok(Json((encrypted_shares, share_commitments)))
}
