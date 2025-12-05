use crate::crypto::commit_share;
use crate::crypto::split_secret;
use crate::crypto::Share;
use crate::crypto::NUM_OF_SHARES;
use crate::EncSecKey;
use crate::HashiCommitteeInfo;
use crate::ProvisionerInitRequestState;
use crate::ShareCommitment;
use crate::WithdrawalConfig;
use crate::WithdrawalState;
use crate::{EncPubKey, SetupNewKeyRequest};
use bitcoin::{Address, Amount};
use bitcoin::Network;
use hpke::kem::X25519HkdfSha256;
use hpke::Kem;
use k256::SecretKey;
use std::num::NonZeroU32;
use std::time::Duration;

/// Test enclave secret key
pub const TEST_ENCLAVE_SK: [u8; 32] = [1u8; 32]; // Fingerprint: 9Azq+G5XdpIzMrjY/TvvhJytsZxplrwnKvH2SNlWakw=
pub const TEST_HASHI_SK: [u8; 32] = [2u8; 32];
pub const DUMMY_REGTEST_ADDRESS: &str = "bcrt1q6zpf4gefu4ckuud3pjch563nm7x27u4ruahz3y";

/// Generate dummy test shares from TEST_ENCLAVE_SK
/// Returns (shares, commitments)
pub fn gen_dummy_share_data() -> (Vec<Share>, Vec<ShareCommitment>) {
    // Convert to k256 for splitting
    let k256_sk = SecretKey::from_slice(&TEST_ENCLAVE_SK).expect("valid test key");
    let shares = split_secret(&k256_sk, &mut rand::thread_rng());
    let share_commitments: Vec<_> = shares.iter().map(commit_share).collect();
    (shares, share_commitments)
}

/// Helper to create a test TaprootUTXO
pub fn create_test_utxo(amount_sats: u64) -> crate::bitcoin_utils::TaprootUTXO {
    use bitcoin::hashes::Hash;
    use bitcoin::opcodes::all::OP_PUSHNUM_2;
    use bitcoin::script::Builder;
    use bitcoin::Amount;
    use bitcoin::ScriptBuf;
    use bitcoin::Txid;

    // Create a minimal valid P2TR script and leaf script
    let internal_key = bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).expect("valid pubkey");
    let script_pubkey =
        ScriptBuf::new_p2tr(&bitcoin::secp256k1::Secp256k1::new(), internal_key, None);
    let leaf_script = Builder::new().push_opcode(OP_PUSHNUM_2).into_script();

    crate::bitcoin_utils::TaprootUTXO::new(
        Txid::from_byte_array([1u8; 32]),
        0,
        Amount::from_sat(amount_sats),
        script_pubkey,
        leaf_script,
    )
    .expect("valid test UTXO")
}

/// Helper to create a test WithdrawOutput with a regtest address
pub fn create_test_withdraw_output(amount_sats: u64) -> crate::WithdrawalOutput {
    let address: Address<_> = DUMMY_REGTEST_ADDRESS.parse().unwrap();
    crate::WithdrawalOutput {
        address: address.as_unchecked().clone(),
        amount: Amount::from_sat(amount_sats),
    }
}
