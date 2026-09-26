// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

mod ceremony_state;
pub mod crypto;
mod deployment;
pub mod errors;
pub mod lifecycle;
pub mod proto_conversions;
pub mod s3;
pub(crate) mod serde;
mod session;
pub mod test_utils;
pub mod time;

pub mod limiter;

pub use ceremony_state::*;
pub use crypto::attestation;
pub use crypto::encryption as kp_certs_roster;
pub use crypto::signing;
pub use crypto::*;
pub use deployment::*;
pub use lifecycle::*;
pub use limiter::LimiterConfig;
pub use limiter::LimiterState;
pub use limiter::RateLimiter;
pub use s3::DEVNET_S3_OBJECT_LOCK_POLICY;
pub use s3::MAINNET_S3_OBJECT_LOCK_POLICY;
pub use s3::S3BucketInfo;
pub use s3::S3Credentials;
pub use s3::S3ObjectLockPolicy;
pub use s3::S3RetentionEnvironment;
pub use s3::TESTNET_S3_OBJECT_LOCK_POLICY;
pub use s3::log;
pub use s3::log::*;
pub use session::*;
pub use time::UnixMillis;
pub use time::now_timestamp_ms;
pub use time::now_timestamp_secs;
pub use time::unix_millis_to_seconds;

use self::errors::GuardianError::*;
use crate::bitcoin::BitcoinPubkey;
use crate::bitcoin::BitcoinSignature;
use crate::bitcoin::HashiMasterG;
use crate::bitcoin::TxUTXOs;
use crate::bitcoin::TxUTXOsWire;
pub use crate::committee::Committee as HashiCommittee;
pub use crate::committee::CommitteeMember as HashiCommitteeMember;
pub use crate::committee::SignedMessage as HashiSigned;
use ::serde::Deserialize;
use ::serde::Serialize;
use bitcoin::Network;
use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
pub use ed25519_consensus::Signature as GuardianSignature;
pub use ed25519_consensus::SigningKey as GuardianSignKeyPair;
pub use ed25519_consensus::VerificationKey as GuardianPubKey;
pub use errors::*;
use rand_core::CryptoRng;
use rand_core::RngCore;

// ---------------------------------
//    Common requests and responses
// ---------------------------------

/// Mode-specific operator bootstrap accepted by the shared `OperatorInit` RPC.
#[derive(Debug, Clone, PartialEq)]
pub enum OperatorInitRequest {
    Ceremony(CeremonyOperatorInitRequest),
    Withdraw(Box<WithdrawOperatorInitRequest>),
}

#[derive(Debug, PartialEq, Clone)]
pub struct GetGuardianInfoResponse {
    /// AWS Nitro attestation
    attestation: NitroAttestation,
    /// Signing pub key of the guardian
    signing_pub_key: GuardianPubKey,
    /// Signed guardian info
    signed_info: GuardianSignedResponse<GuardianInfo>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct VerifiedGuardianInfo {
    pub info: GuardianInfo,
    pub signing_pub_key: GuardianPubKey,
    pub session_id: SessionID,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    /// Signed enclave mode and stage; absent until operator initialization commits.
    pub lifecycle: Option<EnclaveLifecycle>,
    /// Secret-sharing instance (if set). Used by KPs to check that the right key will be used.
    pub secret_sharing_instance: Option<SecretSharingInstance>,
    /// Public summary of the installed deployment configuration, absent before OI.
    pub deployment_info: Option<DeploymentConfigSummary>,
    /// Encryption key. Used by KPs to encrypt their shares.
    #[serde(with = "hex::serde")]
    pub encryption_pubkey: EncPubKeyBytes,
    /// Digest of the operator-supplied `InitConfig` (set after operator_init).
    /// KPs recompute it from their verified sources and match to confirm config.
    #[serde(with = "crate::guardian::serde::option_hex_32")]
    pub config_hash: Option<[u8; 32]>,
    /// Enclave BTC signing pubkey (x-only). Absent before `provisioner_init`.
    pub enclave_btc_pubkey: Option<BitcoinPubkey>,
    /// Current rate limiter state (set after operator_activate).
    pub limiter_state: Option<LimiterState>,
    /// Immutable limiter configuration (set after operator_init).
    pub limiter_config: Option<LimiterConfig>,
    /// Current committee epoch (set after operator_activate). Drives
    /// `UpdateCommittee` catch-up.
    pub current_committee_epoch: Option<u64>,
    /// The Hashi shared-object id this guardian serves (set after
    /// operator_init). Certificates verified by this enclave must be bound
    /// to it. Loaded from verified genesis, or pinned for KP authorization
    /// during first-deployment bootstrap.
    pub hashi_object_id: Option<sui_sdk_types::Address>,
    /// MPC committee verifying key `G` (the derivation master, NOT the guardian's
    /// own BTC key). Set after operator_init from the same genesis source.
    #[serde(with = "crate::guardian::serde::option_mpc_master_g")]
    pub mpc_master_g: Option<HashiMasterG>,
    /// Digest of the optional genesis state pinned during operator init. KPs
    /// independently derive and bind it into their signed PI submissions.
    #[serde(with = "crate::guardian::serde::option_hex_32")]
    pub genesis_state_hash: Option<[u8; 32]>,
}

// ---------------------------------------
//    Withdraw mode requests and responses
// ---------------------------------------

/// Withdraw-mode bootstrap carrying the stable configuration KPs authenticate
/// during provisioner initialization.
#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawOperatorInitRequest {
    pub s3_credentials: S3Credentials,
    pub init_config: InitConfig,
    pub genesis_state: Option<GenesisState>,
}

/// Stable operator-supplied config for arming a withdraw-mode standby. Its
/// `digest()` is the `config_hash` that KPs authenticate in their PI submissions,
/// and that the enclave exposes via `GuardianInfo`. Immutable deployment bindings
/// come from genesis rather than this config.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InitConfig {
    /// Limiter config.
    limiter_config: LimiterConfig,
    /// Deployment settings shared with ceremony mode.
    deployment: DeploymentConfig,
}

/// Optional first-deploy state pinned by the operator during OI and authorized
/// by KPs as part of their signed PI submissions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenesisState {
    committee: crate::move_types::Committee,
    hashi_object_id: sui_sdk_types::Address,
    mpc_master_g: HashiMasterG,
}

/// Live serving state derived during operator activation. Its `digest()` is the
/// `state_hash` checked against the operator's activation pin.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationState {
    /// Binds the live activation state to the stable arming config.
    config_hash: [u8; 32],
    /// Secret-sharing instance pinned during OI and retained through activation.
    secret_sharing_instance: SecretSharingInstance,
    /// Current Hashi committee
    committee: HashiCommittee,
    /// Limiter state (tokens available, timestamp, seq)
    limiter_state: LimiterState,
}

/// The current KPs' signed share submissions, assembled by the relay once it has
/// collected enough. The enclave verifies every KP signature, session pin, and
/// config hash before decrypting the shares.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchProvisionerInitRequest(pub Vec<KpSigned<ProvisionerInitRequest>>);

/// Relay-facing request carrying one KP's signed contribution toward
/// `ProvisionerInit` for a specific guardian session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvisionerInitRequest {
    expected_session_id: SessionID,
    #[serde(with = "hex::serde")]
    expected_config_hash: [u8; 32],
    #[serde(with = "crate::guardian::serde::option_hex_32")]
    expected_genesis_state_hash: Option<[u8; 32]>,
    encrypted_share: GuardianEncryptedShare,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorActivateRequest {
    expected_state_hash: [u8; 32],
}

/// A withdrawal request. `HashiSigned<T>.`
/// Note: Deserialize is not implemented because UTXOs contain validated addresses.
/// StandardWithdrawalRequestWire mocks this type with unverified addresses and Deserialize trait.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StandardWithdrawalRequest {
    /// Unique withdrawal ID assigned by Hashi
    wid: WithdrawalID,
    /// BTC transaction input and output utxos
    utxos: TxUTXOs,
    /// Timestamp in unix seconds (used for rate limiting)
    timestamp_secs: u64,
    /// Monotonic sequence number for ordering
    seq: u64,
}

impl crate::intent::IntentMessage for StandardWithdrawalRequest {
    const INTENT: crate::intent::Intent = crate::intent::Intent::GuardianWithdrawalRequest;
}

/// `GuardianSignedResponse<StandardWithdrawalResponse>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StandardWithdrawalResponse {
    pub enclave_signatures: Vec<BitcoinSignature>,
}

/// Committee handoff payload signed by the outgoing committee as
/// `HashiSigned<CommitteeTransitionRequest>`. `new_committee` is the Move BCS
/// shape so on-chain and guardian signatures match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitteeTransitionRequest {
    pub new_committee: crate::move_types::Committee,
}

impl crate::intent::IntentMessage for CommitteeTransitionRequest {
    const INTENT: crate::intent::Intent = crate::intent::Intent::CommitteeTransition;
}

/// `KpSigned<ProvisionerRotateCertRequest>`.
/// Replaces the signing KP's sole certificate.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProvisionerRotateCertRequest {
    expected_session_id: SessionID,
    expected_cert_seq: u64,
    new_kp_pgp_cert: AttestedKpCert,
    encrypted_share: GuardianEncryptedShare,
}

/// `GuardianSignedResponse<ProvisionerRotateCertResponse>`. Returned after the
/// guardian appends the next `kp-shares/` certificate-state snapshot.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProvisionerRotateCertResponse {
    pub cert_seq: u64,
    pub encrypted_share: KpEncryptedShare,
}

// ---------------------------------------
//    Ceremony mode requests and responses
// ---------------------------------------

/// Ceremony-mode bootstrap carrying the shared deployment policy and separate credentials.
#[derive(Debug, Clone, PartialEq)]
pub struct CeremonyOperatorInitRequest {
    pub deployment: DeploymentConfig,
    pub s3_credentials: S3Credentials,
}

/// New KPs authorize the session, roster, and sharing parameters by confirming
/// the live proposal digest before completed ceremony state is published.
/// The confirmation also commits to the full deployment configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct SetupNewKeyRequest {
    /// One ordered KP certificate per secret share.
    key_provisioner_certs_roster: KpCertRoster,
    /// The secret-sharing params (n, t).
    params: SecretSharingParams,
}

/// `GuardianSignedResponse<SetupNewKeyResponse>`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetupNewKeyResponse {
    /// One encrypted share per KP certificate.
    pub encrypted_shares: KpEncryptedShareRoster,
    /// Params + share commitments.
    pub secret_sharing_instance: SecretSharingInstance,
    /// The Guardian BTC pubkey.
    pub btc_master_pubkey: BitcoinPubkey,
}
/// One KP's signed confirmation that it independently verified the complete
/// [`CeremonyArtifacts`] for a specific guardian session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CeremonyConfirmationRequest {
    expected_session_id: SessionID,
    /// Digest of the deployment configuration and ceremony state in `CeremonyArtifacts`.
    #[serde(with = "hex::serde")]
    ceremony_artifacts_digest: [u8; 32],
}

/// Progress returned after accepting one ceremony confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyConfirmationResponse {
    pub have: u32,
    pub need: u32,
    pub completed: bool,
}

/// A batch of current-KP-authorized requests to rotate the KP set.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchProvisionerRotateKpSetRequest {
    submissions: Vec<KpSigned<ProvisionerRotateKpSetRequest>>,
}

/// One current KP's signed contribution toward rotating the KP set.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProvisionerRotateKpSetRequest {
    expected_session_id: SessionID,
    expected_deployment_config_hash: [u8; 32],
    encrypted_old_share: GuardianEncryptedShare,
    /// Ordered OpenPGP certificate roster for the new KPs. Its length equals
    /// `new_params.num_shares()`.
    new_kp_certs_roster: KpCertRoster,
    /// The new secret-sharing params (n, t).
    new_params: SecretSharingParams,
}

/// `GuardianSignedResponse<RotateKpSetResponse>`. The new KP set's encrypted
/// shares, returned by `rotate_kp_set`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RotateKpSetResponse {
    /// One encrypted share per new KP certificate.
    pub encrypted_shares: KpEncryptedShareRoster,
    /// The new secret-sharing params and commitments.
    pub new_instance: SecretSharingInstance,
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

/// 32-byte UID of the on-chain `WithdrawalTransaction` Sui object.
/// Used to correlate events across Sui, hashi nodes, and the guardian.
pub type WithdrawalID = sui_sdk_types::Address;

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl OperatorInitRequest {
    pub fn new_ceremony_mode(deployment: DeploymentConfig, s3_credentials: S3Credentials) -> Self {
        Self::Ceremony(CeremonyOperatorInitRequest {
            deployment,
            s3_credentials,
        })
    }

    pub fn new_withdraw_mode(
        s3_credentials: S3Credentials,
        init_config: InitConfig,
        genesis_state: Option<GenesisState>,
    ) -> Self {
        Self::Withdraw(Box::new(WithdrawOperatorInitRequest {
            s3_credentials,
            init_config,
            genesis_state,
        }))
    }
}

impl SetupNewKeyRequest {
    pub fn new(
        kp_certs_roster: KpCertRoster,
        num_shares: usize,
        threshold: usize,
    ) -> GuardianResult<Self> {
        let params = SecretSharingParams::new(num_shares, threshold)?;
        if kp_certs_roster.num_kps() != params.num_shares() {
            return Err(InvalidInputs(format!(
                "expected {} KP OpenPGP cert roster entries, got {}",
                params.num_shares(),
                kp_certs_roster.num_kps()
            )));
        }
        Ok(Self {
            key_provisioner_certs_roster: kp_certs_roster,
            params,
        })
    }

    pub fn kp_certs_roster(&self) -> &KpCertRoster {
        &self.key_provisioner_certs_roster
    }

    pub fn params(&self) -> &SecretSharingParams {
        &self.params
    }

    pub fn num_shares(&self) -> usize {
        self.params.num_shares()
    }

    pub fn threshold(&self) -> usize {
        self.params.threshold()
    }
}

impl CeremonyConfirmationRequest {
    pub fn new(expected_session_id: SessionID, ceremony_artifacts_digest: [u8; 32]) -> Self {
        Self {
            expected_session_id,
            ceremony_artifacts_digest,
        }
    }

    pub fn expected_session_id(&self) -> &SessionID {
        &self.expected_session_id
    }

    pub fn ceremony_artifacts_digest(&self) -> &[u8; 32] {
        &self.ceremony_artifacts_digest
    }

    pub fn into_parts(self) -> (SessionID, [u8; 32]) {
        (self.expected_session_id, self.ceremony_artifacts_digest)
    }
}

impl SessionBoundRequest for CeremonyConfirmationRequest {
    const REQUEST_CONTEXT: &'static str = "ceremony confirmation";

    fn expected_session(&self) -> &SessionID {
        &self.expected_session_id
    }
}

impl CeremonyConfirmationResponse {
    pub fn new(have: usize, need: usize) -> GuardianResult<Self> {
        let have = u32::try_from(have)
            .map_err(|_| InvalidInputs(format!("confirmation count {have} exceeds u32::MAX")))?;
        let need = u32::try_from(need).map_err(|_| {
            InvalidInputs(format!(
                "required confirmation count {need} exceeds u32::MAX"
            ))
        })?;
        Ok(Self {
            have,
            need,
            completed: have == need,
        })
    }
}

impl GenesisState {
    pub fn new(
        committee: HashiCommittee,
        hashi_object_id: sui_sdk_types::Address,
        mpc_master_g: HashiMasterG,
    ) -> Self {
        Self {
            committee: (&committee).into(),
            hashi_object_id,
            mpc_master_g,
        }
    }

    pub fn from_parts(
        committee: crate::move_types::Committee,
        hashi_object_id: sui_sdk_types::Address,
        mpc_master_g: HashiMasterG,
    ) -> Self {
        Self {
            committee,
            hashi_object_id,
            mpc_master_g,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        crate::move_types::Committee,
        sui_sdk_types::Address,
        HashiMasterG,
    ) {
        (self.committee, self.hashi_object_id, self.mpc_master_g)
    }

    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(self).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl OperatorActivateRequest {
    pub fn new(expected_state_hash: [u8; 32]) -> Self {
        Self {
            expected_state_hash,
        }
    }

    pub fn expected_state_hash(&self) -> &[u8; 32] {
        &self.expected_state_hash
    }
}

impl ActivationState {
    pub fn new(
        config_hash: [u8; 32],
        secret_sharing_instance: SecretSharingInstance,
        committee: HashiCommittee,
        limiter_state: LimiterState,
    ) -> Self {
        Self {
            config_hash,
            secret_sharing_instance,
            committee,
            limiter_state,
        }
    }

    pub fn into_parts(
        self,
    ) -> (
        [u8; 32],
        SecretSharingInstance,
        HashiCommittee,
        LimiterState,
    ) {
        (
            self.config_hash,
            self.secret_sharing_instance,
            self.committee,
            self.limiter_state,
        )
    }

    pub fn committee(&self) -> &HashiCommittee {
        &self.committee
    }

    pub fn limiter_state(&self) -> &LimiterState {
        &self.limiter_state
    }

    /// The `state_hash`: the digest the operator pins at activation.
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            bcs::to_bytes(&ActivationStateRepr::from(self)).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl InitConfig {
    pub fn new(limiter_config: LimiterConfig, deployment: DeploymentConfig) -> Self {
        Self {
            limiter_config,
            deployment,
        }
    }

    pub fn into_parts(self) -> (LimiterConfig, DeploymentConfig) {
        (self.limiter_config, self.deployment)
    }

    pub fn deployment(&self) -> &DeploymentConfig {
        &self.deployment
    }

    pub fn limiter_config(&self) -> &LimiterConfig {
        &self.limiter_config
    }

    /// The config hash KPs authenticate, including the entire deployment policy.
    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(self).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl ProvisionerInitRequest {
    /// Build one KP's PI contribution, encrypting `share` to the enclave's
    /// session key. Agreement on the stable config is authenticated by the KP
    /// signature over this request, not by HPKE AAD.
    pub fn build_from_share<R: CryptoRng + RngCore>(
        expected_session_id: SessionID,
        expected_config_hash: [u8; 32],
        expected_genesis_state_hash: Option<[u8; 32]>,
        share: &Share,
        enclave_pub_key: &EncPubKey,
        rng: &mut R,
    ) -> Self {
        Self::new(
            expected_session_id,
            expected_config_hash,
            expected_genesis_state_hash,
            encrypt_share(share, enclave_pub_key, None, rng),
        )
    }

    pub fn new(
        expected_session_id: SessionID,
        expected_config_hash: [u8; 32],
        expected_genesis_state_hash: Option<[u8; 32]>,
        encrypted_share: GuardianEncryptedShare,
    ) -> Self {
        Self {
            expected_session_id,
            expected_config_hash,
            expected_genesis_state_hash,
            encrypted_share,
        }
    }

    pub fn expected_session_id(&self) -> &str {
        self.expected_session_id.as_str()
    }

    pub fn encrypted_share(&self) -> &GuardianEncryptedShare {
        &self.encrypted_share
    }

    pub fn expected_config_hash(&self) -> &[u8; 32] {
        &self.expected_config_hash
    }

    pub fn expected_genesis_state_hash(&self) -> Option<[u8; 32]> {
        self.expected_genesis_state_hash
    }

    pub fn into_parts(
        self,
    ) -> (
        SessionID,
        [u8; 32],
        Option<[u8; 32]>,
        GuardianEncryptedShare,
    ) {
        (
            self.expected_session_id,
            self.expected_config_hash,
            self.expected_genesis_state_hash,
            self.encrypted_share,
        )
    }
}

impl SessionBoundRequest for ProvisionerInitRequest {
    const REQUEST_CONTEXT: &'static str = "PI submission";

    fn expected_session(&self) -> &SessionID {
        &self.expected_session_id
    }
}

impl BatchProvisionerRotateKpSetRequest {
    pub fn new(submissions: Vec<KpSigned<ProvisionerRotateKpSetRequest>>) -> GuardianResult<Self> {
        if submissions.is_empty() {
            return Err(InvalidInputs(
                "KP-set rotation requires at least one signed submission".into(),
            ));
        }
        Ok(Self { submissions })
    }

    pub fn submissions(&self) -> &[KpSigned<ProvisionerRotateKpSetRequest>] {
        &self.submissions
    }

    pub fn into_submissions(self) -> Vec<KpSigned<ProvisionerRotateKpSetRequest>> {
        self.submissions
    }
}

impl ProvisionerRotateKpSetRequest {
    pub fn new(
        expected_session_id: SessionID,
        expected_deployment_config_hash: [u8; 32],
        encrypted_old_share: GuardianEncryptedShare,
        new_kp_certs_roster: KpCertRoster,
        new_num_shares: usize,
        new_threshold: usize,
    ) -> GuardianResult<Self> {
        let new_params = SecretSharingParams::new(new_num_shares, new_threshold)?;
        if new_kp_certs_roster.num_kps() != new_params.num_shares() {
            return Err(InvalidInputs(format!(
                "expected {} new KP cert roster entries, got {}",
                new_params.num_shares(),
                new_kp_certs_roster.num_kps()
            )));
        }
        Ok(Self {
            expected_session_id,
            expected_deployment_config_hash,
            encrypted_old_share,
            new_kp_certs_roster,
            new_params,
        })
    }

    /// Build one current KP's rotation request. The KP signature directly binds
    /// the deployment config hash, new roster, and sharing parameters to its encrypted old share.
    pub fn build_from_share<R: CryptoRng + RngCore>(
        expected_session_id: SessionID,
        expected_deployment_config_hash: [u8; 32],
        share: &Share,
        enclave_pub_key: &EncPubKey,
        new_kp_certs_roster: KpCertRoster,
        new_params: SecretSharingParams,
        rng: &mut R,
    ) -> GuardianResult<Self> {
        Self::new(
            expected_session_id,
            expected_deployment_config_hash,
            encrypt_share(share, enclave_pub_key, None, rng),
            new_kp_certs_roster,
            new_params.num_shares(),
            new_params.threshold(),
        )
    }

    pub fn expected_session_id(&self) -> &SessionID {
        &self.expected_session_id
    }

    pub fn expected_deployment_config_hash(&self) -> &[u8; 32] {
        &self.expected_deployment_config_hash
    }

    pub fn encrypted_old_share(&self) -> &GuardianEncryptedShare {
        &self.encrypted_old_share
    }

    pub fn new_kp_certs_roster(&self) -> &KpCertRoster {
        &self.new_kp_certs_roster
    }

    pub fn new_params(&self) -> &SecretSharingParams {
        &self.new_params
    }

    pub fn into_parts(
        self,
    ) -> (
        SessionID,
        [u8; 32],
        GuardianEncryptedShare,
        KpCertRoster,
        SecretSharingParams,
    ) {
        (
            self.expected_session_id,
            self.expected_deployment_config_hash,
            self.encrypted_old_share,
            self.new_kp_certs_roster,
            self.new_params,
        )
    }
}

impl SessionBoundRequest for ProvisionerRotateKpSetRequest {
    const REQUEST_CONTEXT: &'static str = "KP rotation submission";

    fn expected_session(&self) -> &SessionID {
        &self.expected_session_id
    }
}

impl ProvisionerRotateCertRequest {
    pub fn new<R: CryptoRng + RngCore>(
        expected_session_id: SessionID,
        expected_cert_seq: u64,
        new_kp_pgp_cert: AttestedKpCert,
        share: &Share,
        enclave_pub_key: &EncPubKey,
        rng: &mut R,
    ) -> Self {
        let encrypted_share = encrypt_share(share, enclave_pub_key, None, rng);
        Self {
            expected_session_id,
            expected_cert_seq,
            new_kp_pgp_cert,
            encrypted_share,
        }
    }

    pub(crate) fn from_encrypted_share(
        expected_session_id: SessionID,
        expected_cert_seq: u64,
        new_kp_pgp_cert: AttestedKpCert,
        encrypted_share: GuardianEncryptedShare,
    ) -> Self {
        Self {
            expected_session_id,
            expected_cert_seq,
            new_kp_pgp_cert,
            encrypted_share,
        }
    }

    pub fn share_id(&self) -> ShareID {
        self.encrypted_share.id
    }

    pub fn new_kp_pgp_cert(&self) -> &AttestedKpCert {
        &self.new_kp_pgp_cert
    }

    pub fn new_recipient_fingerprint(&self) -> KPFingerprint {
        self.new_kp_pgp_cert.fingerprint().to_hex()
    }

    pub fn encrypted_share(&self) -> &GuardianEncryptedShare {
        &self.encrypted_share
    }

    pub fn expected_session_id(&self) -> &SessionID {
        &self.expected_session_id
    }

    pub fn expected_cert_seq(&self) -> u64 {
        self.expected_cert_seq
    }

    pub fn into_parts(self) -> (SessionID, u64, AttestedKpCert, GuardianEncryptedShare) {
        (
            self.expected_session_id,
            self.expected_cert_seq,
            self.new_kp_pgp_cert,
            self.encrypted_share,
        )
    }
}

impl SessionBoundRequest for ProvisionerRotateCertRequest {
    const REQUEST_CONTEXT: &'static str = "provisioner_rotate_cert request";

    fn expected_session(&self) -> &SessionID {
        &self.expected_session_id
    }
}

impl StandardWithdrawalRequest {
    pub fn new(wid: WithdrawalID, utxos: TxUTXOs, timestamp_secs: u64, seq: u64) -> Self {
        Self {
            wid,
            utxos,
            timestamp_secs,
            seq,
        }
    }

    pub fn wid(&self) -> &WithdrawalID {
        &self.wid
    }

    pub fn utxos(&self) -> &TxUTXOs {
        &self.utxos
    }

    pub fn timestamp_secs(&self) -> u64 {
        self.timestamp_secs
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

impl GetGuardianInfoResponse {
    pub fn new(
        attestation: NitroAttestation,
        signing_pub_key: GuardianPubKey,
        signed_info: GuardianSignedResponse<GuardianInfo>,
    ) -> Self {
        Self {
            attestation,
            signing_pub_key,
            signed_info,
        }
    }

    /// Verify a live guardian response against an independently approved build.
    ///
    /// Checks:
    /// - `signed_info` is signed by `signing_pub_key`;
    /// - initialized sessions report the expected deployment revision;
    /// - the Nitro attestation has a valid signature;
    /// - the certificate chain is valid now;
    /// - the attested public key and PCR0 match `signing_pub_key` and `expected_build`.
    ///
    /// Callers check whether the verified lifecycle is appropriate for their operation.
    pub fn verify_live(
        &self,
        expected_build: &BuildPcrs,
    ) -> CryptoVerificationResult<VerifiedGuardianInfo> {
        let info = self
            .signed_info
            .verify_signature(&self.signing_pub_key)?
            .response
            .clone();
        if info.lifecycle.is_some() {
            if info
                .deployment_info
                .as_ref()
                .map(|d| d.git_revision.as_str())
                != Some(expected_build.git_revision())
            {
                return Err(CryptoVerificationError::new(format!(
                    "guardian reports build '{:?}', expected '{}'",
                    info.deployment_info.as_ref().map(|d| &d.git_revision),
                    expected_build.git_revision()
                )));
            }
        } else if info.deployment_info.is_some() {
            return Err(CryptoVerificationError::new(
                "expected an uninitialized guardian without deployment configuration",
            ));
        }
        self.attestation
            .verify_live(&self.signing_pub_key, expected_build)?;
        Ok(VerifiedGuardianInfo {
            info,
            signing_pub_key: self.signing_pub_key,
            session_id: SessionID::from_signing_pubkey(&self.signing_pub_key),
        })
    }

    /// Extract the guardian's self-reported info and signing key WITHOUT verifying
    /// the signature or attestation.
    pub fn into_info_unchecked(self) -> (GuardianInfo, GuardianPubKey) {
        (
            self.signed_info.into_data_unchecked().response,
            self.signing_pub_key,
        )
    }
}

// ---------------------------------
//    Serialize / Deserialize
// ---------------------------------

/// Mock of StandardWithdrawalRequest with unchecked addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardWithdrawalRequestWire {
    pub wid: WithdrawalID,
    pub utxos: TxUTXOsWire,
    pub timestamp_secs: u64,
    pub seq: u64,
}

#[derive(Debug, Clone)]
pub struct SignedStandardWithdrawalRequestWire {
    pub data: StandardWithdrawalRequestWire,
    pub signature: crate::move_types::CommitteeSignature,
}

/// Serializable representation of ActivationState. Used for computing its digest.
#[derive(Serialize)]
struct ActivationStateRepr {
    pub config_hash: [u8; 32],
    pub secret_sharing_instance: SecretSharingInstance,
    pub committee: crate::move_types::Committee,
    pub limiter_state: LimiterState,
}

/// Converter from T -> Self that internally validates addresses
pub trait AddressValidation<T>: Sized {
    fn validate_addr(value: T, network: Network) -> GuardianResult<Self>;
}

impl AddressValidation<SignedStandardWithdrawalRequestWire>
    for HashiSigned<StandardWithdrawalRequest>
{
    fn validate_addr(
        wire_value: SignedStandardWithdrawalRequestWire,
        network: Network,
    ) -> GuardianResult<Self> {
        HashiSigned::<StandardWithdrawalRequest>::new(
            wire_value.signature.epoch,
            StandardWithdrawalRequest::validate_addr(wire_value.data, network)?,
            &wire_value.signature.signature,
            &wire_value.signature.signers_bitmap,
        )
        .map_err(|e| InvalidInputs(format!("{:?}", e)))
    }
}

impl AddressValidation<StandardWithdrawalRequestWire> for StandardWithdrawalRequest {
    fn validate_addr(
        value: StandardWithdrawalRequestWire,
        network: Network,
    ) -> GuardianResult<Self> {
        Ok(Self {
            wid: value.wid,
            utxos: TxUTXOs::new(value.utxos.inputs, value.utxos.outputs, network)
                .map_err(|e| InvalidInputs(e.to_string()))?,
            timestamp_secs: value.timestamp_secs,
            seq: value.seq,
        })
    }
}

impl From<StandardWithdrawalRequest> for StandardWithdrawalRequestWire {
    fn from(m: StandardWithdrawalRequest) -> Self {
        Self {
            wid: m.wid,
            utxos: m.utxos.into(),
            timestamp_secs: m.timestamp_secs,
            seq: m.seq,
        }
    }
}

impl From<&ActivationState> for ActivationStateRepr {
    fn from(state: &ActivationState) -> Self {
        let (config_hash, secret_sharing_instance, committee, limiter_state) =
            state.clone().into_parts();
        Self {
            config_hash,
            secret_sharing_instance,
            committee: (&committee).into(),
            limiter_state,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardian::test_utils::mock_attested_kp_certs;

    #[test]
    fn guardian_info_json_encodes_binary_fields_as_strings() {
        let mut info = GuardianInfo::mock_for_testing();
        info.config_hash = Some([0xab; 32]);
        let btc_pubkey = crate::bitcoin::create_btc_keypair_for_test(&[3u8; 32])
            .x_only_public_key()
            .0;
        info.mpc_master_g = Some(crate::bitcoin::hashi_master_g_from_btc_xonly_for_test(
            &btc_pubkey,
        ));

        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["lifecycle"]["withdraw"], "operator_initialized");
        assert_eq!(json["encryption_pubkey"], hex::encode([0u8; 32]));
        assert_eq!(json["config_hash"], hex::encode([0xab; 32]));
        let mpc_master_g = json["mpc_master_g"].as_str().unwrap();
        assert_eq!(mpc_master_g.len(), 66);
        assert!(
            mpc_master_g
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );

        let from_json: GuardianInfo = serde_json::from_value(json).unwrap();
        assert_eq!(from_json, info);
    }

    #[test]
    fn get_guardian_info_into_info_unchecked_returns_info_and_signing_key() {
        let resp = GetGuardianInfoResponse::mock_for_testing();
        let expected_info = GuardianInfo::mock_for_testing();
        let expected_signing_pub_key = resp.signing_pub_key;
        let (info, signing_pub_key) = resp.into_info_unchecked();

        assert_eq!(info, expected_info);
        assert_eq!(signing_pub_key, expected_signing_pub_key);
    }

    #[test]
    fn get_guardian_info_verify_live_uses_signed_info_verification() {
        let mut resp = GetGuardianInfoResponse::mock_for_testing();
        let mut sig_bytes: [u8; 64] = resp.signed_info.signature.to_bytes();
        sig_bytes[0] ^= 0xff;
        resp.signed_info.signature = GuardianSignature::from(sig_bytes);

        assert_eq!(
            resp.verify_live(&BuildPcrs::new("test-revision", vec![0]))
                .unwrap_err()
                .to_string(),
            "signature invalid"
        );
    }

    #[test]
    fn guardian_info_verification_distinguishes_boot_from_initialized_sessions() {
        let key = GuardianSignKeyPair::from([7; 32]);
        let build = BuildPcrs::new("approved", vec![1]);
        let response = |info| {
            GetGuardianInfoResponse::new(
                NitroAttestation::new(vec![]),
                key.verification_key(),
                GuardianSigned::sign(GuardianResponse::new(info, 1234), &key),
            )
        };
        let mut info = GuardianInfo::mock_for_testing();
        info.lifecycle = None;
        info.deployment_info = None;
        assert!(response(info.clone()).verify_live(&build).is_ok());
        let mut deployment = DeploymentConfig::mock_for_testing().summary();
        deployment.git_revision = "approved".into();
        info.deployment_info = Some(deployment);
        assert!(response(info.clone()).verify_live(&build).is_err());
        info.lifecycle = CeremonyStage::OperatorInitialized.into();
        assert!(response(info.clone()).verify_live(&build).is_ok());
        info.deployment_info.as_mut().unwrap().git_revision = "wrong-label".into();
        assert!(response(info.clone()).verify_live(&build).is_err());
        info.deployment_info = None;
        assert!(response(info).verify_live(&build).is_err());
    }

    #[test]
    fn provisioner_rotate_kp_set_request_rejects_wrong_cert_count() {
        let mut cert_sets = mock_attested_kp_certs(5);
        cert_sets.pop();
        let certs_roster = KpCertRoster::new(cert_sets).unwrap();
        assert!(matches!(
            ProvisionerRotateKpSetRequest::new(
                "session".into(),
                DeploymentConfig::mock_for_testing().digest(),
                GuardianEncryptedShare {
                    id: ShareID::new(1).unwrap(),
                    ciphertext: Ciphertext {
                        encapsulated_key: vec![0],
                        aes_ciphertext: vec![0],
                    },
                },
                certs_roster,
                5,
                3,
            )
            .unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn kp_certs_roster_rejects_duplicate_certs() {
        let mut cert_sets = mock_attested_kp_certs(5);
        cert_sets[1] = cert_sets[0].clone();
        assert!(matches!(
            KpCertRoster::new(cert_sets).unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn provisioner_rotate_kp_set_signature_commits_to_roster_order() {
        let cert_sets = mock_attested_kp_certs(5);
        let reversed: Vec<AttestedKpCert> = cert_sets.iter().rev().cloned().collect();
        let deployment_config_hash = DeploymentConfig::mock_for_testing().digest();
        let encrypted_old_share = GuardianEncryptedShare {
            id: ShareID::new(1).unwrap(),
            ciphertext: Ciphertext {
                encapsulated_key: vec![0],
                aes_ciphertext: vec![0],
            },
        };
        let a = ProvisionerRotateKpSetRequest::new(
            "session".into(),
            deployment_config_hash,
            encrypted_old_share.clone(),
            KpCertRoster::new(cert_sets).unwrap(),
            5,
            3,
        )
        .unwrap();
        let b = ProvisionerRotateKpSetRequest::new(
            "session".into(),
            deployment_config_hash,
            encrypted_old_share,
            KpCertRoster::new(reversed).unwrap(),
            5,
            3,
        )
        .unwrap();
        assert_ne!(a.new_kp_certs_roster(), b.new_kp_certs_roster());
        assert_ne!(KpSigned::signed_bytes(&a), KpSigned::signed_bytes(&b));
    }
}
