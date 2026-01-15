use crate::bitcoin_utils::BTC_LIB;
use crate::Ciphertext;
use crate::CommitteeStore;
use crate::EncPubKey;
use crate::EncryptedShare;
use crate::GuardianSigned;
use crate::HashiCommittee;
use crate::HashiCommitteeMember;
use crate::OperatorInitRequest;
use crate::ProvisionerInitRequest;
use crate::ProvisionerInitRequestState;
use crate::RateLimiter;
use crate::SetupNewKeyRequest;
use crate::SetupNewKeyResponse;
use crate::ShareCommitment;
use crate::WithdrawalConfig;
use crate::WithdrawalState;
use crate::NUM_OF_SHARES;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::SecretKey;
use bitcoin::Amount;
use ed25519_consensus::SigningKey;
use fastcrypto::bls12381::min_pk::BLS12381KeyPair;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::ToFromBytes;
use hashi_types::committee::EncryptionPrivateKey;
use hashi_types::committee::EncryptionPublicKey;
use hpke::Deserializable;
use std::num::NonZeroU16;
use std::time::Duration;
use std::time::UNIX_EPOCH;
use sui_sdk_types::bcs::FromBcs;
use sui_sdk_types::Address as SuiAddress;

pub fn create_btc_keypair(sk: &[u8; 32]) -> Keypair {
    let secret_key = SecretKey::from_slice(sk).expect("valid secret key");
    Keypair::from_secret_key(&BTC_LIB, &secret_key)
}

impl SetupNewKeyRequest {
    pub fn mock_for_testing() -> Self {
        let pk = EncPubKey::from_bytes(&[0u8; 32]).unwrap();
        SetupNewKeyRequest::new(vec![pk; NUM_OF_SHARES]).unwrap()
    }
}

impl GuardianSigned<SetupNewKeyResponse> {
    pub fn mock_for_testing() -> Self {
        let mut share_commitments = vec![];
        let mut encrypted_shares = vec![];
        for i in 0..NUM_OF_SHARES {
            share_commitments.push(ShareCommitment {
                id: NonZeroU16::new((i + 1) as u16).unwrap(),
                digest: vec![0u8; 32],
            });

            encrypted_shares.push(EncryptedShare {
                id: NonZeroU16::new((i + 1) as u16).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![0u8; 32],
                    aes_ciphertext: vec![0u8; 32],
                },
            });
        }

        let resp = SetupNewKeyResponse {
            encrypted_shares,
            share_commitments,
        };

        let signing_kp = SigningKey::from([1u8; 32]);
        GuardianSigned::new(resp, &signing_kp, UNIX_EPOCH)
    }
}

impl OperatorInitRequest {
    pub fn mock_for_testing() -> Self {
        let s3_config = crate::S3Config {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            bucket_name: "bucket".into(),
        };

        let mut share_commitments = vec![];
        for i in 0..NUM_OF_SHARES {
            share_commitments.push(ShareCommitment {
                id: NonZeroU16::new((i + 1) as u16).unwrap(),
                digest: vec![0u8; 32],
            })
        }

        OperatorInitRequest {
            s3_config,
            share_commitments,
            network: crate::Network::Regtest,
        }
    }
}

impl ProvisionerInitRequest {
    // NOTE: Incorrect encryption is used. Fix later if needed.
    pub fn mock_for_testing() -> Self {
        ProvisionerInitRequest {
            encrypted_share: EncryptedShare {
                id: NonZeroU16::new(1).unwrap(),
                ciphertext: Ciphertext {
                    encapsulated_key: vec![0u8; 32],
                    aes_ciphertext: vec![0u8; 32],
                },
            },
            state: ProvisionerInitRequestState::mock_for_testing(None),
        }
    }
}

pub(crate) fn mock_committee_member() -> HashiCommitteeMember {
    HashiCommitteeMember::new(
        SuiAddress::new([0u8; 32]),
        BLS12381KeyPair::from_bytes(&[1u8; 32])
            .unwrap()
            .public()
            .clone(),
        EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::from_bcs(&[1u8; 32]).unwrap()),
        10,
    )
}

pub fn mock_committee_with_one_member() -> HashiCommittee {
    HashiCommittee::new(vec![mock_committee_member()], 0)
}

impl ProvisionerInitRequestState {
    pub fn mock_for_testing(kp: Option<Keypair>) -> Self {
        let kp = kp.unwrap_or(create_btc_keypair(&[1u8; 32]));
        let num_epochs_to_track = NonZeroU16::new(2).unwrap();
        let epoch_window = crate::epoch_store::EpochWindow::new(0, num_epochs_to_track);
        let max_withdrawable_per_epoch = Amount::from_sat(1000);

        ProvisionerInitRequestState {
            withdrawal_config: WithdrawalConfig {
                committee_threshold: 0,
                delayed_withdrawals_min_delay: Duration::from_secs(10),
                delayed_withdrawals_timeout: Duration::from_secs(60),
            },
            withdrawal_state: WithdrawalState::new(
                RateLimiter::new(
                    epoch_window,
                    vec![Amount::from_sat(0)],
                    max_withdrawable_per_epoch,
                )
                .unwrap(),
            ),
            hashi_committees: CommitteeStore::new(
                epoch_window,
                vec![mock_committee_with_one_member()],
            )
            .unwrap(),
            hashi_btc_master_pubkey: kp.x_only_public_key().0,
        }
    }
}
