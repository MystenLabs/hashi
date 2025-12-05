use std::sync::Arc;
use axum::extract::State;
use crate::{Enclave, GuardianResult};
use axum::Json;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest}; // kept only for fingerprint logging
use hashi_guardian_shared::crypto::commit_share;
use hashi_guardian_shared::crypto::encrypt_share;
use hashi_guardian_shared::crypto::split_secret;
use hashi_guardian_shared::crypto::NUM_OF_SHARES;
use hashi_guardian_shared::GuardianError::InvalidInputs;
use hashi_guardian_shared::*;
use k256::SecretKey;
use tracing::error;
use tracing::info;

// Stateless request
pub async fn setup_new_key(
    State(enclave): State<Arc<Enclave>>,
    Json(request): Json<SetupNewKeyRequest>,
) -> GuardianResult<Json<Signed<SetupNewKeyResponse>>> {
    info!("/setup_new_key - Received request");

    info!("Validating key provisioner public keys...");
    let key_provisioner_pks = request.public_keys()?;
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
    // Note: Outputting a fingerprint for testing purposes (no security purpose to it, so it can be removed)
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

    Ok(Json(enclave.sign(SetupNewKeyResponse {
        encrypted_shares,
        share_commitments,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use hashi_guardian_shared::{commit_share, decrypt_share, NUM_OF_SHARES};

    #[tokio::test]
    async fn test_setup_new_key() {
        let enclave = Enclave::create_with_random_keys();
        let verification_key = &enclave.signing_keypair().verification_key();
        let (request, kp_private_keys) = SetupNewKeyRequest::mock_for_testing();
        let Json(resp) = setup_new_key(State(enclave), Json(request)).await.unwrap();
        let validated_resp = validate_signed_response(verification_key, resp).unwrap();
        assert_eq!(validated_resp.encrypted_shares.len(), NUM_OF_SHARES);

        for (i, (enc_share, sk)) in validated_resp
            .encrypted_shares
            .iter()
            .zip(kp_private_keys.iter())
            .enumerate()
            .take(NUM_OF_SHARES)
        {
            let share = decrypt_share(enc_share, sk, None).unwrap();
            let commitment = &validated_resp.share_commitments[i];
            assert_eq!(enc_share.id, commitment.id);
            assert_eq!(commit_share(&share), *commitment);
            println!("Received share: (id) {:?}", enc_share.id);
        }
    }
}