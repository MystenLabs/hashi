use crate::GuardianError::GenericError;
use crate::GuardianResult;
use axum::Json;
use fastcrypto::hash::{Blake2b256, HashFunction};
use k256::elliptic_curve::PrimeField;
use hashi_guardian_shared::{
    encrypt, EncPubKey, MyShare, SetupNewKeyRequest, SetupNewKeyResponse, SECRET_SHARING_N,
    SECRET_SHARING_T,
};
use k256::SecretKey;
use tracing::{error, info};
use vsss_rs::{shamir, IdentifierPrimeField, ReadableShareSet};

const THRESHOLD: usize = SECRET_SHARING_T as usize;
const LIMIT: usize = SECRET_SHARING_N as usize;

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
    info!("✅ Bitcoin key generated");

    info!(
        "🔪 Splitting secret into {} shares (threshold: {})...",
        LIMIT, THRESHOLD
    );
    let shares = k256_secret_key_to_shares(sk)?;
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

pub fn k256_secret_key_to_shares(sk: SecretKey) -> GuardianResult<Vec<MyShare>> {
    let nzs = sk.to_nonzero_scalar();
    let shared_secret = IdentifierPrimeField(*nzs.as_ref());
    let shares = shamir::split_secret::<MyShare>(
        THRESHOLD, LIMIT, &shared_secret, &mut rand::thread_rng()
    ).map_err(|e| GenericError(format!("Failed to split secret: {}", e)))?;
    Ok(shares)
}


pub fn k256shares_to_secp_secret_key(
    shares: &[MyShare],
) -> GuardianResult<bitcoin::secp256k1::SecretKey> {
    let result = shares
        .combine()
        .map_err(|e| GenericError(format!("Failed to combine share: {}", e)))?;
    info!("✅ Shares combined successfully");

    let sk = result.0.to_repr();
    let secp_sk = bitcoin::secp256k1::SecretKey::from_slice(&sk)
        .map_err(|e| GenericError(format!("Failed to cast combined secret key: {}", e)))?;
    Ok(secp_sk)
}

mod secret_sharing_tests {
    use super::*;
    use elliptic_curve::ff::PrimeField;
    use k256::{NonZeroScalar, SecretKey};
    use vsss_rs::{shamir, *};
    use bitcoin::secp256k1::{Message, Secp256k1};

    #[test]
    fn basic_secret_sharing() {
        let mut osrng = rand_core::OsRng::default();
        let sk = SecretKey::random(&mut osrng);
        let nzs = sk.to_nonzero_scalar();
        let shared_secret = IdentifierPrimeField(*nzs.as_ref());
        let res = shamir::split_secret::<MyShare>(2, 3, &shared_secret, &mut osrng);
        assert!(res.is_ok());
        let shares = res.unwrap();
        println!("{:?}", shares);
        let res = shares.combine();
        assert!(res.is_ok());
        let scalar = res.unwrap();
        let nzs_dup = NonZeroScalar::from_repr(scalar.0.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        assert_eq!(sk_dup.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn test_libs_compat() {
        let msg = [7u8; 32];
        let mut osrng = rand_core::OsRng::default();
        let sk1 = k256::SecretKey::random(&mut osrng);
        let sk1_bytes = sk1.to_bytes();

        let secp = Secp256k1::new();
        let sk2 = bitcoin::secp256k1::SecretKey::from_slice(&sk1_bytes).unwrap();
        let sk2_bytes = sk2.secret_bytes();

        let sk1_dup = k256::SecretKey::from_slice(&sk2_bytes).unwrap();
        assert_eq!(sk1_dup, sk1);

        let sk1_shares = k256_secret_key_to_shares(sk1).unwrap();
        let sk2_dup = k256shares_to_secp_secret_key(&sk1_shares).unwrap();
        assert_eq!(sk2_dup, sk2);

        // secp signing
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk2);
        let bytes = [2u8; 32];
        let msg_dup = Message::from_digest(msg);
        let signature = secp.sign_schnorr_with_aux_rand(&msg_dup, &keypair, &bytes);
        let xonly_pubkey = bitcoin::XOnlyPublicKey::from_keypair(&keypair).0;
        secp.verify_schnorr(&signature, &msg_dup, &xonly_pubkey)
            .unwrap();

        // k256 Schnorr signing
        let k256_schnorr_key = k256::schnorr::SigningKey::from_bytes(&sk1_bytes).unwrap();
        let k256_schnorr_sig = k256_schnorr_key.sign_raw(&msg, &bytes).unwrap();
        assert_eq!(signature.serialize(), k256_schnorr_sig.to_bytes());

        // Verify with k256 Schnorr
        let k256_schnorr_vkey = k256_schnorr_key.verifying_key();
        k256_schnorr_vkey
            .verify_raw(&msg, &k256_schnorr_sig)
            .unwrap();
    }
}