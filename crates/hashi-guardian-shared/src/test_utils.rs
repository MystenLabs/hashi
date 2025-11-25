use crate::crypto::commit_share;
use crate::crypto::k256_secret_key_to_shares;
use crate::crypto::LIMIT;
use crate::errors::GuardianResult;
use crate::EncPubKey;
use crate::EncSecKey;
use crate::GuardianError;
use crate::HashiCommittee;
use crate::InitExternalRequestState;
use crate::MyShare;
use crate::SetupNewKeyRequest;
use crate::ShareCommitment;
use crate::WithdrawConfig;
use crate::WithdrawalState;
use bitcoin::Address;
use bitcoin::Network;
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use k256::SecretKey;
use std::time::Duration;

/// Test enclave secret key
pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32]; // Fingerprint: 9Azq+G5XdpIzMrjY/TvvhJytsZxplrwnKvH2SNlWakw=
pub const TEST_HASHI_SK: [u8; 32] = [2u8; 32];
pub const DUMMY_REGTEST_ADDRESS: &str = "bcrt1q6zpf4gefu4ckuud3pjch563nm7x27u4ruahz3y";

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
        change_address: DUMMY_REGTEST_ADDRESS.to_string(),
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

/// Helper to create a test TaprootUTXO
pub fn create_test_utxo(amount_sats: u64) -> crate::bitcoin_utils::TaprootUTXO {
    use bitcoin::hashes::Hash;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::Txid;

    crate::bitcoin_utils::TaprootUTXO {
        txid: Txid::from_byte_array([1u8; 32]),
        vout: 0,
        amount: Amount::from_sat(amount_sats),
        script_pubkey: ScriptBuf::new(),
        leaf_script: ScriptBuf::new(),
    }
}

/// Helper to create a test WithdrawOutput with a regtest address
pub fn create_test_withdraw_output(amount_sats: u64) -> crate::WithdrawOutput {
    use bitcoin::Address;
    use bitcoin::Amount;

    let address: Address<_> = DUMMY_REGTEST_ADDRESS.parse().unwrap();
    crate::WithdrawOutput {
        address: address.as_unchecked().clone(),
        amount: Amount::from_sat(amount_sats),
    }
}

pub fn create_dummy_regtest_address() -> Address {
    DUMMY_REGTEST_ADDRESS
        .parse::<Address<_>>()
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap()
}
