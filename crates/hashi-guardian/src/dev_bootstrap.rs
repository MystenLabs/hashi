// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Helpers shared between the dev-cluster bootstrap example and in-process
//! test harnesses. Not for production: generates fresh BTC keys + shares
//! purely from local randomness.

use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey as BtcSecretKey;
use hashi_types::committee::Bls12381PrivateKey;
use hashi_types::committee::CommitteeMember as HashiCommitteeMember;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::committee::EncryptionPublicKey;
use hashi_types::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
use hashi_types::committee::DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS;
use hashi_types::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;
use hashi_types::guardian::crypto::commit_share;
use hashi_types::guardian::crypto::split_secret;
use hashi_types::guardian::BitcoinPubkey;
use hashi_types::guardian::HashiCommittee;
use hashi_types::guardian::LimiterState;
use hashi_types::guardian::Share;
use hashi_types::guardian::ShareCommitment;
use hashi_types::guardian::ShareCommitments;
use hashi_types::guardian::WithdrawalConfig;
use rand::CryptoRng;
use rand::RngCore;
use sui_sdk_types::Address as SuiAddress;

/// All material needed to drive a fresh OperatorInit + ProvisionerInit
/// in dev. Produced together so commitments and shares are guaranteed
/// to match.
pub struct DevShareMaterial {
    pub shares: Vec<Share>,
    pub commitments: ShareCommitments,
    pub master_pubkey: BitcoinPubkey,
}

/// Generate a fresh BTC master secret, split into Shamir shares, and
/// compute the matching commitments. The returned master_pubkey is the
/// x-only public key that the guardian will reconstruct from any
/// THRESHOLD shares.
pub fn generate_dev_share_material<R: CryptoRng + RngCore>(rng: &mut R) -> DevShareMaterial {
    let k256_sk = k256::SecretKey::random(&mut *rng);

    let shares = split_secret(&k256_sk, rng);
    let commitments_vec: Vec<ShareCommitment> = shares.iter().map(commit_share).collect();
    let commitments =
        ShareCommitments::new(commitments_vec).expect("split_secret produces NUM_OF_SHARES shares");

    let secp = Secp256k1::new();
    let btc_sk = BtcSecretKey::from_slice(&k256_sk.to_bytes())
        .expect("k256 secret key bytes are a valid secp256k1 secret");
    let keypair = Keypair::from_secret_key(&secp, &btc_sk);
    let (master_pubkey, _parity) = keypair.x_only_public_key();

    DevShareMaterial {
        shares,
        commitments,
        master_pubkey,
    }
}

/// Build a WithdrawalConfig from the three policy values.
pub fn build_withdrawal_config(
    committee_threshold: u64,
    refill_rate_sats_per_sec: u64,
    max_bucket_capacity_sats: u64,
) -> WithdrawalConfig {
    WithdrawalConfig {
        committee_threshold,
        refill_rate_sats_per_sec,
        max_bucket_capacity_sats,
    }
}

/// Initial limiter state with a full bucket.
pub fn full_bucket_state(config: &WithdrawalConfig) -> LimiterState {
    LimiterState {
        num_tokens_available: config.max_bucket_capacity_sats,
        last_updated_at: 0,
        next_seq: 0,
    }
}

/// Single-member mock committee for dev. Lets the guardian reach fully-
/// initialized state so hashi-server can seed its local limiter. Signature
/// verification against on-chain withdrawals will fail until this is
/// replaced with a real committee (separate problem).
pub fn mock_dev_committee(epoch: u64) -> HashiCommittee {
    let bls_sk =
        Bls12381PrivateKey::from_bytes([9u8; Bls12381PrivateKey::LENGTH]).expect("valid bls sk");
    let enc_sk = EncryptionPrivateKey::new(&mut rand::thread_rng());
    let member = HashiCommitteeMember::new(
        SuiAddress::new([1u8; 32]),
        bls_sk.public_key(),
        EncryptionPublicKey::from_private_key(&enc_sk),
        10,
    );
    HashiCommittee::new(
        vec![member],
        epoch,
        DEFAULT_MPC_THRESHOLD_IN_BASIS_POINTS,
        DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
        DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::guardian::crypto::combine_shares;
    use hashi_types::guardian::crypto::NUM_OF_SHARES;
    use hashi_types::guardian::crypto::THRESHOLD;

    #[test]
    fn generated_shares_reconstruct_to_master_pubkey() {
        let mut rng = rand::thread_rng();
        let material = generate_dev_share_material(&mut rng);

        assert_eq!(material.shares.len(), NUM_OF_SHARES);

        // Any THRESHOLD shares must reconstruct to a key whose x-only pubkey
        // matches the master_pubkey we exported.
        let subset = &material.shares[..THRESHOLD];
        let reconstructed = combine_shares(subset).expect("threshold shares combine");
        let (reconstructed_xonly, _) = reconstructed.x_only_public_key();
        assert_eq!(reconstructed_xonly, material.master_pubkey);
    }

    #[test]
    fn full_bucket_state_matches_capacity() {
        let cfg = build_withdrawal_config(3, 1_000, 100_000_000);
        let state = full_bucket_state(&cfg);
        assert_eq!(state.num_tokens_available, cfg.max_bucket_capacity_sats);
    }
}
