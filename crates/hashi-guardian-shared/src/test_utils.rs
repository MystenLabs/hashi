use crate::crypto::{commit_share, k256_secret_key_to_shares, LIMIT};
use crate::errors::GuardianResult;
use crate::{
    EncPubKey, EncSecKey, GuardianError, HashiCommittee, InitExternalRequestState, MyShare,
    SetupNewKeyRequest, ShareCommitment, WithdrawConfig, WithdrawalState,
};
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use k256::SecretKey;
use std::time::Duration;

/// Test enclave secret key
pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32]; // Fingerprint: 9Azq+G5XdpIzMrjY/TvvhJytsZxplrwnKvH2SNlWakw=

/// Generate LIMIT key provisioner keypairs for testing
/// Returns (private_keys, public_keys)
pub fn generate_kp_keypairs() -> (Vec<EncSecKey>, Vec<EncPubKey>) {
    let mut private_keys = vec![];
    let mut public_keys = vec![];
    for _i in 0..LIMIT {
        let mut rng = rand::thread_rng();
        let (sk, pk) = X25519HkdfSha256::gen_keypair(&mut rng);
        private_keys.push(sk);
        public_keys.push(pk);
    }
    (private_keys, public_keys)
}

/// Create a mock SetupNewKeyRequest with generated keypairs
/// Returns (request, private_keys)
pub fn mock_setup_new_key_request() -> (SetupNewKeyRequest, Vec<EncSecKey>) {
    let (private_keys, public_keys) = generate_kp_keypairs();
    (public_keys.into(), private_keys)
}

/// Create a mock InitExternalRequestState for testing
pub fn mock_init_external_state() -> InitExternalRequestState {
    InitExternalRequestState {
        hashi_committee_info: HashiCommittee::default(),
        withdraw_config: WithdrawConfig {
            min_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(3600),
        },
        withdraw_state: WithdrawalState::default(),
        cached_bytes: std::sync::OnceLock::new(),
    }
}

/// Generate dummy test shares from TEST_ENCLAVE_SK
/// Returns (shares, commitments)
pub fn gen_dummy_share_data() -> GuardianResult<(Vec<MyShare>, Vec<ShareCommitment>)> {
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&TEST_ENCLAVE_SK)
        .map_err(|e| GuardianError::GenericError(format!("Failed to create test key: {}", e)))?;
    // Convert to k256 for splitting
    let k256_sk = SecretKey::from_bytes(&sk.secret_bytes().into())
        .map_err(|e| GuardianError::GenericError(format!("Failed to convert key: {}", e)))?;
    let shares = k256_secret_key_to_shares(k256_sk)?;
    let share_commitments: Result<Vec<_>, _> =
        shares.iter().map(|share| commit_share(share)).collect();
    Ok((shares, share_commitments?))
}
