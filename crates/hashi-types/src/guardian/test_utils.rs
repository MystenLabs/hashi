use super::Ciphertext;
use super::CommitteeStore;
use super::EncPubKey;
use super::EncryptedShare;
use super::GetGuardianInfoResponse;
use super::GuardianInfo;
use super::GuardianSigned;
use super::HashiCommittee;
use super::HashiCommitteeMember;
use super::HashiSigned;
use super::NUM_OF_SHARES;
use super::OperatorInitRequest;
use super::ProvisionerInitRequest;
use super::ProvisionerInitState;
use super::RateLimiter;
use super::S3BucketInfo;
use super::S3Config;
use super::SetupNewKeyRequest;
use super::SetupNewKeyResponse;
use super::ShareCommitment;
use super::StandardWithdrawalRequest;
use super::StandardWithdrawalResponse;
use super::WithdrawalConfig;
use super::WithdrawalState;
use super::bitcoin_utils::BTC_LIB;
use super::bitcoin_utils::InputUTXO;
use super::bitcoin_utils::OutputUTXO;
use super::bitcoin_utils::TxUTXOs;
use super::bitcoin_utils::sign_btc_tx;
use crate::committee::Bls12381PrivateKey;
use crate::committee::BlsSignatureAggregator;
use crate::committee::EncryptionPrivateKey;
use crate::committee::EncryptionPublicKey;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::hashes::Hash as _;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::TapLeafHash;
use ed25519_consensus::SigningKey;
use hpke::Deserializable;
use std::num::NonZeroU16;
use std::time::Duration;
use sui_sdk_types::Address as SuiAddress;
use sui_sdk_types::bcs::FromBcs;

// -------------------------------
// Shared deterministic test values
// -------------------------------

/// Deterministic Sui address used across signing-related mocks.
const TEST_SIGNER_ADDRESS: SuiAddress = SuiAddress::new([1u8; 32]);

/// Deterministic committee signing key material used across tests.
const TEST_HASHI_BLS_SK_BYTES: [u8; Bls12381PrivateKey::LENGTH] = [9u8; Bls12381PrivateKey::LENGTH];

pub fn create_btc_keypair(sk: &[u8; 32]) -> Keypair {
    let secret_key = SecretKey::from_slice(sk).expect("valid secret key");
    Keypair::from_secret_key(&BTC_LIB, &secret_key)
}

impl GetGuardianInfoResponse {
    pub fn mock_for_testing() -> Self {
        let signing_key = ed25519_consensus::SigningKey::from([1u8; 32]);
        let signing_pub_key = signing_key.verification_key();

        let info = GuardianInfo {
            share_commitments: None,
            bucket_info: Some(super::S3BucketInfo {
                bucket: "bucket".to_string(),
                region: "us-east-1".to_string(),
            }),
            encryption_pubkey: vec![0u8; 32],
            server_version: "v1".to_string(),
        };

        GetGuardianInfoResponse {
            attestation: "abcd".as_bytes().to_vec(),
            signing_pub_key,
            signed_info: GuardianSigned::new(info, &signing_key, 1234),
        }
    }
}

impl SetupNewKeyRequest {
    pub fn mock_for_testing() -> Self {
        let pk = EncPubKey::from_bytes(&[0u8; 32]).unwrap();
        SetupNewKeyRequest::new(vec![pk; NUM_OF_SHARES]).unwrap()
    }
}

fn dummy_commitments() -> Vec<ShareCommitment> {
    (0..NUM_OF_SHARES)
        .map(|i| ShareCommitment {
            id: NonZeroU16::new((i + 1) as u16).unwrap(),
            digest: vec![0u8; 32],
        })
        .collect()
}

fn dummy_encrypted_shares() -> Vec<EncryptedShare> {
    (0..NUM_OF_SHARES)
        .map(|i| EncryptedShare {
            id: NonZeroU16::new((i + 1) as u16).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![0u8; 32],
                aes_ciphertext: vec![0u8; 32],
            },
        })
        .collect()
}

impl GuardianSigned<SetupNewKeyResponse> {
    pub fn mock_for_testing() -> Self {
        let resp = SetupNewKeyResponse {
            encrypted_shares: dummy_encrypted_shares(),
            share_commitments: dummy_commitments(),
        };

        let signing_kp = SigningKey::from([1u8; 32]);
        GuardianSigned::new(resp, &signing_kp, 0)
    }
}

impl OperatorInitRequest {
    pub fn mock_for_testing() -> Self {
        let s3_config = super::S3Config {
            access_key: "ak".into(),
            secret_key: "sk".into(),
            bucket_info: super::S3BucketInfo {
                bucket: "bucket".into(),
                region: "us-east-1".into(),
            },
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
            network: super::Network::Regtest,
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
            state: ProvisionerInitState::mock_for_testing(None),
        }
    }
}

fn mock_hashi_bls_sk() -> Bls12381PrivateKey {
    Bls12381PrivateKey::from_bytes(TEST_HASHI_BLS_SK_BYTES).expect("valid bls sk bytes")
}

fn mock_committee_member() -> HashiCommitteeMember {
    let pk = mock_hashi_bls_sk().public_key();

    HashiCommitteeMember::new(
        // This address must match the one used in signing-related mocks.
        TEST_SIGNER_ADDRESS,
        pk,
        EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::from_bcs(&[1u8; 32]).unwrap()),
        10,
    )
}

fn mock_committee_with_one_member(epoch: u64) -> HashiCommittee {
    HashiCommittee::new(vec![mock_committee_member()], epoch)
}

impl ProvisionerInitState {
    pub fn from_parts_for_testing(
        withdrawal_config: WithdrawalConfig,
        withdrawal_state: WithdrawalState,
        hashi_committees: CommitteeStore,
        hashi_btc_master_pubkey: super::BitcoinPubkey,
    ) -> Self {
        ProvisionerInitState::new(
            hashi_committees,
            withdrawal_config,
            withdrawal_state,
            hashi_btc_master_pubkey,
        )
        .expect("valid ProvisionerInitState")
    }

    pub fn mock_for_testing(kp: Option<Keypair>) -> Self {
        let kp = kp.unwrap_or(create_btc_keypair(&[1u8; 32]));
        let num_epochs_to_track = NonZeroU16::new(2).unwrap();
        let epoch_window = super::epoch_store::EpochWindow::new(0, num_epochs_to_track);
        let max_withdrawable_per_epoch = Amount::from_sat(1000);

        ProvisionerInitState {
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
                vec![mock_committee_with_one_member(epoch_window.first_epoch)],
            )
            .unwrap(),
            hashi_btc_master_pubkey: kp.x_only_public_key().0,
        }
    }
}

impl StandardWithdrawalRequest {
    fn mock_for_testing(network: Network, wid: u64) -> Self {
        let kp = create_btc_keypair(&[2u8; 32]);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&kp);
        let addr_unchecked =
            bitcoin::Address::p2tr(&BTC_LIB, internal_key, None, network).into_unchecked();

        let txid = bitcoin::Txid::from_slice(&[9u8; 32]).expect("valid txid bytes");
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };
        let leaf_hash = TapLeafHash::from_slice(&[7u8; 32]).expect("valid leaf hash bytes");

        let input = InputUTXO::new(
            outpoint,
            Amount::from_sat(10_000),
            addr_unchecked.clone(),
            leaf_hash,
            network,
        )
        .expect("valid InputUTXO");

        let output_external =
            OutputUTXO::new_external(addr_unchecked, Amount::from_sat(9_000), network)
                .expect("valid external output");

        let output_internal = OutputUTXO::new_internal([42u8; 32], Amount::from_sat(500));

        let utxos = TxUTXOs::new(vec![input], vec![output_external, output_internal])
            .expect("valid TxUTXOs");

        StandardWithdrawalRequest::new(wid, utxos)
    }

    fn sign_for_request(
        req: StandardWithdrawalRequest,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        let epoch = 0u64;
        let committee = mock_committee_with_one_member(epoch);

        let sk = mock_hashi_bls_sk();
        let address = TEST_SIGNER_ADDRESS;
        let mut agg = BlsSignatureAggregator::new(&committee, req.clone());
        agg.add_signature(sk.sign(epoch, address, &req))
            .expect("member signature should verify");

        (agg.finish().expect("finish aggregator"), committee)
    }

    fn sign_for_wid(
        network: Network,
        wid: u64,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        Self::sign_for_request(Self::mock_for_testing(network, wid))
    }

    /// Returns a signed request and the committee used to produce the signature
    pub fn mock_signed_and_committee_for_testing(
        network: Network,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        Self::sign_for_wid(network, 123)
    }

    pub fn mock_signed_for_testing(network: Network) -> HashiSigned<StandardWithdrawalRequest> {
        Self::mock_signed_and_committee_for_testing(network).0
    }

    pub fn mock_signed_for_testing_with_wid(
        network: Network,
        wid: u64,
    ) -> HashiSigned<StandardWithdrawalRequest> {
        Self::sign_for_wid(network, wid).0
    }
}

impl GuardianSigned<StandardWithdrawalResponse> {
    pub fn mock_for_testing() -> Self {
        let kp = create_btc_keypair(&[3u8; 32]);
        let msg = Message::from_digest([5u8; 32]);
        let enclave_signatures = sign_btc_tx(&[msg], &kp);

        let resp = StandardWithdrawalResponse { enclave_signatures };

        let signing_kp = SigningKey::from([4u8; 32]);
        GuardianSigned::new(resp, &signing_kp, 0)
    }
}

impl S3BucketInfo {
    /// Convenience helper for tests.
    pub fn mock_for_testing() -> Self {
        Self {
            bucket: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
        }
    }
}

impl S3Config {
    /// Convenience helper for tests.
    pub fn mock_for_testing() -> Self {
        Self {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
            bucket_info: S3BucketInfo::mock_for_testing(),
        }
    }
}
