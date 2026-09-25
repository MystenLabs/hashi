// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(any(test, feature = "test-utils"))]
pub use super::crypto::encryption::attested_test_utils::dev_kp_attestations;
#[cfg(any(test, feature = "test-utils"))]
pub use super::crypto::encryption::attested_test_utils::mock_attested_kp_certs;
#[cfg(any(test, feature = "test-utils"))]
pub use super::crypto::encryption::attested_test_utils::mock_attested_kp_keypair;

use super::AttestedKpCert;
#[cfg(any(test, feature = "test-utils"))]
use super::BatchProvisionerInitRequest;
#[cfg(any(test, feature = "test-utils"))]
use super::BatchProvisionerRotateKpSetRequest;
use super::BuildPcrs;
use super::Ciphertext;
use super::GenesisState;
use super::GetGuardianInfoResponse;
use super::GuardianEncryptedShare;
use super::GuardianInfo;
use super::GuardianResponse;
use super::GuardianSigned;
use super::GuardianSignedResponse;
use super::HashiCommittee;
use super::HashiCommitteeMember;
use super::HashiSigned;
use super::InitConfig;
#[cfg(any(test, feature = "test-utils"))]
use super::KpCertRoster;
use super::KpEncryptedShare;
use super::KpEncryptedShareRoster;
#[cfg(any(test, feature = "test-utils"))]
use super::KpSigned;
use super::LimiterConfig;
use super::NitroAttestation;
use super::OperatorInitRequest;
use super::PcrAllowlist;
use super::ProvisionerInitRequest;
use super::ProvisionerRotateCertRequest;
use super::ProvisionerRotateCertResponse;
#[cfg(any(test, feature = "test-utils"))]
use super::ProvisionerRotateKpSetRequest;
use super::RotateKpSetResponse;
use super::S3BucketInfo;
use super::S3Credentials;
use super::SecretSharingInstance;
use super::SessionID;
#[cfg(any(test, feature = "test-utils"))]
use super::SetupNewKeyRequest;
use super::SetupNewKeyResponse;
use super::ShareCommitment;
use super::ShareCommitments;
use super::StandardWithdrawalRequest;
use super::StandardWithdrawalResponse;
use super::WithdrawStage;
use super::WithdrawalID;

use crate::bitcoin::BTC_LIB;
use crate::bitcoin::BitcoinAddress;
use crate::bitcoin::InputUTXO;
use crate::bitcoin::OutputUTXOWire;
use crate::bitcoin::TxUTXOs;
use crate::bitcoin::create_btc_keypair_for_test;
use crate::bitcoin::hashi_master_g_from_btc_xonly_for_test;
use crate::bitcoin::sign_btc_tx;
use crate::committee::Bls12381PrivateKey;
use crate::committee::BlsSignatureAggregator;
use crate::committee::EncryptionPrivateKey;
use bitcoin::Amount;
use bitcoin::Network;
use bitcoin::hashes::Hash as _;
use bitcoin::key::UntweakedPublicKey;
use bitcoin::secp256k1::Message;
use ed25519_consensus::SigningKey;
use std::num::NonZeroU16;
use sui_sdk_types::Address as SuiAddress;
use sui_sdk_types::bcs::FromBcs;

use crate::committee::DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS;
use crate::committee::DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA;

// Default secret-sharing params used by mock_for_testing helpers.
const TEST_N: usize = 5;
const TEST_T: usize = 3;

// -------------------------------
// Shared deterministic test values
// -------------------------------

/// Deterministic Sui address used across signing-related mocks.
const TEST_SIGNER_ADDRESS: SuiAddress = SuiAddress::new([1u8; 32]);

/// Deterministic Hashi object id bound into mock certificate preimages.
/// Guardian tests that verify these certificates must pin the same id.
pub const TEST_HASHI_OBJECT_ID: SuiAddress = SuiAddress::new([0xAA; 32]);

/// Deterministic committee signing key material used across tests.
const TEST_HASHI_BLS_SK_BYTES: [u8; Bls12381PrivateKey::LENGTH] = [9u8; Bls12381PrivateKey::LENGTH];

impl GuardianInfo {
    pub fn mock_for_testing() -> Self {
        Self {
            lifecycle: WithdrawStage::OperatorInitialized.into(),
            secret_sharing_instance: None,
            deployment_info: Some(
                super::DeploymentConfig {
                    bucket_info: S3BucketInfo {
                        name: "bucket".into(),
                        region: "us-east-1".into(),
                    },
                    ..super::DeploymentConfig::mock_for_testing()
                }
                .summary(),
            ),
            encryption_pubkey: vec![0u8; 32],
            config_hash: None,
            genesis_state_hash: None,
            enclave_btc_pubkey: None,
            limiter_state: None,
            limiter_config: None,
            current_committee_epoch: None,
            mpc_master_g: None,
            hashi_object_id: None,
        }
    }
}

impl super::OperatorInitInfo {
    pub fn mock_for_testing() -> Self {
        let config = InitConfig::mock_for_testing();
        let (_, hashi_object_id, mpc_master_g) = GenesisState::mock_for_testing().into_parts();
        Self {
            deployment_info: config.deployment().summary(),
            encryption_pubkey: vec![0u8; 32],
            initialization: super::OperatorInitMode::Withdraw(Box::new(
                super::WithdrawOperatorInitInfo {
                    secret_sharing_instance: SetupNewKeyResponse::mock_for_testing()
                        .secret_sharing_instance,
                    config_hash: [2; 32],
                    limiter_config: *config.limiter_config(),
                    hashi_object_id,
                    mpc_master_g,
                    genesis_state_hash: None,
                },
            )),
        }
    }
}

impl GetGuardianInfoResponse {
    pub fn mock_for_testing() -> Self {
        let signing_key = ed25519_consensus::SigningKey::from([1u8; 32]);
        let signing_pub_key = signing_key.verification_key();

        GetGuardianInfoResponse::new(
            NitroAttestation::new("abcd".as_bytes().to_vec()),
            signing_pub_key,
            GuardianSigned::sign(
                GuardianResponse::new(GuardianInfo::mock_for_testing(), 1234),
                &signing_key,
            ),
        )
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl SetupNewKeyRequest {
    pub fn mock_for_testing() -> Self {
        SetupNewKeyRequest::new(mock_kp_certs_roster(TEST_N), TEST_N, TEST_T).unwrap()
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub fn mock_kp_certs_roster(n: usize) -> KpCertRoster {
    KpCertRoster::new(mock_attested_kp_certs(n)).unwrap()
}

fn dummy_commitments() -> ShareCommitments {
    let commitments = (0..TEST_N)
        .map(|i| ShareCommitment {
            id: NonZeroU16::new((i + 1) as u16).unwrap(),
            digest: vec![0u8; 32],
        })
        .collect();
    ShareCommitments::new(commitments).unwrap()
}

fn dummy_encrypted_shares() -> KpEncryptedShareRoster {
    KpEncryptedShareRoster::new(
        (0..TEST_N)
            .map(|i| KpEncryptedShare {
                id: NonZeroU16::new((i + 1) as u16).unwrap(),
                recipient_fingerprint: format!("DUMMY FINGERPRINT {i}"),
                armored_ciphertext: "-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----"
                    .into(),
            })
            .collect(),
    )
    .unwrap()
}

impl SetupNewKeyResponse {
    pub fn mock_for_testing() -> Self {
        Self {
            encrypted_shares: dummy_encrypted_shares(),
            secret_sharing_instance: dummy_secret_sharing_instance(),
            btc_master_pubkey: crate::guardian::crypto::k256_sk_to_btc_xonly_pubkey(
                &k256::SecretKey::from_slice(&[7u8; 32]).expect("valid k256 sk"),
            ),
        }
    }
}

impl GuardianSignedResponse<SetupNewKeyResponse> {
    pub fn mock_for_testing() -> Self {
        let signing_kp = SigningKey::from([1u8; 32]);
        GuardianSigned::sign(
            GuardianResponse::new(SetupNewKeyResponse::mock_for_testing(), 0),
            &signing_kp,
        )
    }
}

impl RotateKpSetResponse {
    pub fn mock_for_testing() -> Self {
        Self {
            encrypted_shares: dummy_encrypted_shares(),
            new_instance: dummy_secret_sharing_instance(),
        }
    }
}

impl GuardianSignedResponse<RotateKpSetResponse> {
    pub fn mock_for_testing() -> Self {
        let signing_kp = SigningKey::from([1u8; 32]);
        GuardianSigned::sign(
            GuardianResponse::new(RotateKpSetResponse::mock_for_testing(), 0),
            &signing_kp,
        )
    }
}

impl ProvisionerRotateCertResponse {
    pub fn mock_for_testing() -> Self {
        Self {
            cert_seq: 7,
            encrypted_share: dummy_encrypted_shares()
                .into_vec()
                .into_iter()
                .next()
                .expect("dummy shares should be non-empty"),
        }
    }
}

impl GuardianSignedResponse<ProvisionerRotateCertResponse> {
    pub fn mock_for_testing() -> Self {
        let signing_key = SigningKey::from([1u8; 32]);
        GuardianSigned::sign(
            GuardianResponse::new(ProvisionerRotateCertResponse::mock_for_testing(), 0),
            &signing_key,
        )
    }
}

impl OperatorInitRequest {
    pub fn mock_for_testing() -> Self {
        let config = InitConfig::mock_for_testing();
        OperatorInitRequest::new_withdraw_mode(
            S3Credentials::mock_for_testing(),
            config,
            Some(GenesisState::mock_for_testing()),
        )
    }
}

impl GenesisState {
    pub fn mock_for_testing() -> Self {
        let kp = create_btc_keypair_for_test(&[1u8; 32]);
        Self::new(
            mock_committee_with_one_member(0),
            TEST_HASHI_OBJECT_ID,
            hashi_master_g_from_btc_xonly_for_test(&kp.x_only_public_key().0),
        )
    }
}

impl ProvisionerInitRequest {
    pub fn mock_for_testing() -> Self {
        let encrypted_share = GuardianEncryptedShare {
            id: NonZeroU16::new(1).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![0u8; 32],
                aes_ciphertext: vec![0u8; 32],
            },
        };
        Self::new("mock-session".into(), [7u8; 32], None, encrypted_share)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl BatchProvisionerInitRequest {
    // NOTE: Incorrect encryption is used. Fix later if needed.
    pub fn mock_for_testing() -> Self {
        let (cert, _) = mock_attested_kp_keypair();
        BatchProvisionerInitRequest(vec![KpSigned::from_parts(
            ProvisionerInitRequest::mock_for_testing(),
            cert,
            "mock-signature".into(),
        )])
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl BatchProvisionerRotateKpSetRequest {
    // NOTE: Incorrect encryption and signature are used. This is only for wire round trips.
    pub fn mock_for_testing() -> Self {
        let encrypted_old_share = GuardianEncryptedShare {
            id: NonZeroU16::new(1).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![0u8; 32],
                aes_ciphertext: vec![0u8; 32],
            },
        };
        let request = ProvisionerRotateKpSetRequest::new(
            "mock-session".into(),
            super::DeploymentConfig::mock_for_testing().digest(),
            encrypted_old_share,
            mock_kp_certs_roster(TEST_N),
            TEST_N,
            TEST_T,
        )
        .unwrap();
        let (cert, _) = mock_attested_kp_keypair();
        Self::new(vec![
            KpSigned::from_parts(
                request,
                cert,
                "mock-signature".into(),
            );
            TEST_T
        ])
        .unwrap()
    }
}

impl ProvisionerRotateCertRequest {
    pub fn from_encrypted_share_for_testing(
        expected_session_id: SessionID,
        expected_cert_seq: u64,
        new_kp_pgp_cert: AttestedKpCert,
        encrypted_share: GuardianEncryptedShare,
    ) -> Self {
        Self::from_encrypted_share(
            expected_session_id,
            expected_cert_seq,
            new_kp_pgp_cert,
            encrypted_share,
        )
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
        EncryptionPrivateKey::from_bcs(&[1u8; 32])
            .unwrap()
            .public_key(),
        10,
    )
}

fn mock_committee_with_one_member(epoch: u64) -> HashiCommittee {
    HashiCommittee::new(
        vec![mock_committee_member()],
        epoch,
        DEFAULT_MPC_WEIGHT_REDUCTION_ALLOWED_DELTA,
        DEFAULT_MPC_MAX_FAULTY_IN_BASIS_POINTS,
    )
}

impl InitConfig {
    pub fn from_parts_for_testing(limiter_config: LimiterConfig, network: super::Network) -> Self {
        InitConfig::new(
            limiter_config,
            crate::guardian::DeploymentConfig {
                pcr_allowlist: mock_pcr_allowlist(),
                bucket_info: S3BucketInfo::mock_for_testing(),
                retention_environment: super::S3RetentionEnvironment::Testnet,
                bitcoin_network: network,
            },
        )
    }

    pub fn mock_for_testing() -> Self {
        Self::from_parts_for_testing(
            LimiterConfig {
                refill_rate: 10,
                max_bucket_capacity: 1000,
            },
            super::Network::Regtest,
        )
    }
}

fn mock_pcr_allowlist() -> PcrAllowlist {
    PcrAllowlist::new(BuildPcrs::new("unknown", vec![0]), []).expect("valid PCR allowlist")
}

/// A throwaway secret-sharing instance for tests that don't exercise share verification.
fn dummy_secret_sharing_instance() -> SecretSharingInstance {
    SecretSharingInstance::new(dummy_commitments(), TEST_N, TEST_T, 0).unwrap()
}

impl StandardWithdrawalRequest {
    fn mock_for_testing(network: Network, wid: WithdrawalID) -> Self {
        let kp = create_btc_keypair_for_test(&[2u8; 32]);
        let (internal_key, _) = UntweakedPublicKey::from_keypair(&kp);
        let addr_unchecked =
            BitcoinAddress::p2tr(&BTC_LIB, internal_key, None, network).into_unchecked();

        let txid = bitcoin::Txid::from_slice(&[9u8; 32]).expect("valid txid bytes");
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };

        let input = InputUTXO::new(outpoint, Amount::from_sat(10_000), [7u8; 32].into());

        let output_external = OutputUTXOWire::external(addr_unchecked, Amount::from_sat(9_000));
        let output_internal = OutputUTXOWire::internal([42u8; 32].into(), Amount::from_sat(500));

        let utxos = TxUTXOs::new(vec![input], vec![output_external, output_internal], network)
            .expect("valid TxUTXOs");

        StandardWithdrawalRequest::new(wid, utxos, 1_000_000, 0)
    }

    fn mock_for_testing_with_seq(
        network: Network,
        wid: WithdrawalID,
        timestamp_secs: u64,
        seq: u64,
    ) -> Self {
        let mut req = Self::mock_for_testing(network, wid);
        req.timestamp_secs = timestamp_secs;
        req.seq = seq;
        req
    }

    fn sign_for_request(
        req: StandardWithdrawalRequest,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        let epoch = 0u64;
        let committee = mock_committee_with_one_member(epoch);

        let sk = mock_hashi_bls_sk();
        let address = TEST_SIGNER_ADDRESS;
        let mut agg = BlsSignatureAggregator::new(TEST_HASHI_OBJECT_ID, &committee, req.clone());
        agg.add_signature(sk.sign(TEST_HASHI_OBJECT_ID, epoch, address, &req))
            .expect("member signature should verify");

        (agg.finish().expect("finish aggregator"), committee)
    }

    fn sign_for_wid(
        network: Network,
        wid: WithdrawalID,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        Self::sign_for_request(Self::mock_for_testing(network, wid))
    }

    /// Returns a signed request and the committee used to produce the signature
    pub fn mock_signed_and_committee_for_testing(
        network: Network,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        Self::sign_for_wid(network, WithdrawalID::new([0xab; 32]))
    }

    pub fn mock_signed_for_testing(network: Network) -> HashiSigned<StandardWithdrawalRequest> {
        Self::mock_signed_and_committee_for_testing(network).0
    }

    pub fn mock_signed_for_testing_with_wid(
        network: Network,
        wid: WithdrawalID,
    ) -> HashiSigned<StandardWithdrawalRequest> {
        Self::sign_for_wid(network, wid).0
    }

    pub fn mock_signed_and_committee_with_seq(
        network: Network,
        wid: WithdrawalID,
        timestamp_secs: u64,
        seq: u64,
    ) -> (HashiSigned<StandardWithdrawalRequest>, HashiCommittee) {
        Self::sign_for_request(Self::mock_for_testing_with_seq(
            network,
            wid,
            timestamp_secs,
            seq,
        ))
    }
}

impl StandardWithdrawalResponse {
    pub fn mock_for_testing() -> Self {
        let kp = create_btc_keypair_for_test(&[3u8; 32]);
        let msg = Message::from_digest([5u8; 32]);
        let enclave_signatures = sign_btc_tx(&[msg], &kp);
        Self { enclave_signatures }
    }
}

impl GuardianSignedResponse<StandardWithdrawalResponse> {
    pub fn mock_for_testing() -> Self {
        let signing_kp = SigningKey::from([4u8; 32]);
        GuardianSigned::sign(
            GuardianResponse::new(StandardWithdrawalResponse::mock_for_testing(), 0),
            &signing_kp,
        )
    }
}

impl S3BucketInfo {
    /// Convenience helper for tests.
    pub fn mock_for_testing() -> Self {
        Self {
            name: "test-bucket".to_string(),
            region: "us-east-1".to_string(),
        }
    }
}

impl S3Credentials {
    pub fn mock_for_testing() -> Self {
        Self {
            access_key: "test-access-key".to_string(),
            secret_key: "test-secret-key".to_string(),
            session_token: None,
        }
    }
}

impl super::DeploymentConfig {
    pub fn mock_for_testing() -> Self {
        Self {
            bucket_info: S3BucketInfo::mock_for_testing(),
            retention_environment: super::S3RetentionEnvironment::Testnet,
            bitcoin_network: super::Network::Regtest,
            pcr_allowlist: mock_pcr_allowlist(),
        }
    }
}
