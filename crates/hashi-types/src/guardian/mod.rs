// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod attestation;
pub mod crypto;
pub mod errors;
pub mod lifecycle;
pub mod log;
pub mod proto_conversions;
pub(crate) mod serde_utils;
pub mod signing;
pub mod test_utils;
pub mod time_utils;

pub mod limiter;
pub mod s3_utils;

pub use attestation::BuildPcrs;
pub use attestation::GitRevision;
pub use attestation::NitroAttestation;
pub use attestation::PcrAllowlist;
pub use attestation::VerifiedSessionInfo;
pub use lifecycle::*;
pub use limiter::LimiterConfig;
pub use limiter::LimiterState;
pub use limiter::RateLimiter;
pub use log::*;
pub use signing::GuardianSigned;
pub use signing::IntentType;
pub use signing::KpSigned;
pub use signing::KpSigningIntent;
pub use signing::KpSigningIntentType;
pub use signing::SigningIntent;
pub use time_utils::UnixMillis;
pub use time_utils::now_timestamp_ms;
pub use time_utils::now_timestamp_secs;
pub use time_utils::unix_millis_to_seconds;

use self::errors::GuardianError::*;
use crate::bitcoin::BitcoinPubkey;
use crate::bitcoin::BitcoinSignature;
use crate::bitcoin::HashiMasterG;
use crate::bitcoin::TxUTXOs;
use crate::bitcoin::TxUTXOsWire;
pub use crate::committee::Committee as HashiCommittee;
pub use crate::committee::CommitteeMember as HashiCommitteeMember;
pub use crate::committee::SignedMessage as HashiSigned;
use crate::pgp::PgpPublicCert;
use bitcoin::Network;
use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::consts::U32;
pub use crypto::*;
pub use ed25519_consensus::Signature as GuardianSignature;
pub use ed25519_consensus::SigningKey as GuardianSignKeyPair;
pub use ed25519_consensus::VerificationKey as GuardianPubKey;
pub use errors::*;
use rand_core::CryptoRng;
use rand_core::RngCore;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;

// ---------------------------------
//    Common requests and responses
// ---------------------------------

/// Operator-supplied bootstrap. A ceremony-mode enclave (setup/rotate) needs only
/// `s3_config`; a withdraw-mode enclave additionally carries the stable
/// `InitConfig` whose digest KPs authenticate during provisioner init.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorInitRequest {
    s3_config: S3Config,
    init_config: Option<InitConfig>,
}

/// Operator-trusted one-time bootstrap request for `genesis/record.json`.
/// The operator must source the committee from on-chain state during first deploy.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorWriteGenesisRequest {
    committee: crate::move_types::Committee,
}

#[derive(Debug, PartialEq, Clone)]
pub struct GetGuardianInfoResponse {
    /// AWS Nitro attestation
    attestation: NitroAttestation,
    /// Signing pub key of the guardian
    signing_pub_key: GuardianPubKey,
    /// Signed guardian info
    signed_info: GuardianSigned<GuardianInfo>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct VerifiedGuardianInfo {
    pub info: GuardianInfo,
    pub signing_pub_key: GuardianPubKey,
    pub session_id: SessionID,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    /// Signed enclave mode and its current lifecycle stage.
    pub lifecycle: EnclaveLifecycle,
    /// Secret-sharing instance (if set). Used by KPs to check that the right key will be used.
    pub secret_sharing_instance: Option<SecretSharingInstance>,
    /// S3 bucket name (if set). Used by KPs to check S3 bucket info.
    pub bucket_info: Option<S3BucketInfo>,
    /// Encryption key. Used by KPs to encrypt their shares.
    #[serde(with = "hex::serde")]
    pub encryption_pubkey: EncPubKeyBytes,
    /// Digest of the operator-supplied `InitConfig` (set after operator_init).
    /// KPs recompute it from their verified sources and match to confirm config.
    #[serde(with = "crate::guardian::serde_utils::option_hex_32")]
    pub config_hash: Option<[u8; 32]>,
    /// Git revision of the guardian build. Untrusted (enclave-self-reported);
    /// verified out-of-band by reproducibly building at this revision and matching
    /// PCRs against the session's attestation.
    pub untrusted_git_revision: GitRevision,
    /// Enclave BTC signing pubkey (x-only). Absent before `provisioner_init`.
    pub enclave_btc_pubkey: Option<BitcoinPubkey>,
    /// Current rate limiter state (set after operator_activate).
    pub limiter_state: Option<LimiterState>,
    /// Immutable limiter configuration (set after operator_init).
    pub limiter_config: Option<LimiterConfig>,
    /// Current committee epoch (set after operator_activate). Drives
    /// `UpdateCommittee` catch-up.
    pub current_committee_epoch: Option<u64>,
    /// MPC committee verifying key `G` (the derivation master, NOT the guardian's
    /// own BTC key). Set after operator_init; lets KPs verify it directly.
    #[serde(with = "crate::guardian::serde_utils::option_mpc_master_g")]
    pub mpc_master_g: Option<HashiMasterG>,
    // TODO: report the full committee too, so its membership is directly
    // verifiable from GuardianInfo; it's large, though.
}

// ---------------------------------------
//    Withdraw mode requests and responses
// ---------------------------------------

/// Stable operator-supplied config for arming a withdraw-mode standby. Its
/// `digest()` is the `config_hash` that KPs authenticate in their PI submissions,
/// and that the enclave exposes via `GuardianInfo`.
#[derive(Debug, Clone, PartialEq)]
pub struct InitConfig {
    /// Limiter config.
    limiter_config: LimiterConfig,
    /// Raw MPC verifying key (curve point with y-parity preserved).
    hashi_btc_master_pubkey: HashiMasterG,
    /// Guardian build PCR pins used to verify attested guardian sessions.
    pcr_allowlist: PcrAllowlist,
    /// BTC network.
    network: Network,
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
pub struct ProvisionerInitRequest(pub Vec<KpSigned<SingleProvisionerInitRequest>>);

/// Relay-facing request carrying one KP's signed contribution toward
/// `ProvisionerInit` for a specific guardian session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SingleProvisionerInitRequest {
    expected_session_id: SessionID,
    #[serde(with = "hex::serde")]
    expected_config_hash: [u8; 32],
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
    /// TODO: rename to `withdraw_seq` (and `LimiterState.next_seq` →
    /// `next_withdraw_seq`) to disambiguate from `SecretSharingInstance.sharing_seq`.
    seq: u64,
}

impl crate::intent::IntentMessage for StandardWithdrawalRequest {
    const INTENT: crate::intent::Intent = crate::intent::Intent::GuardianWithdrawalRequest;
}

/// `EnclaveSigned<T>`
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

// ---------------------------------------
//    Ceremony mode requests and responses
// ---------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct SetupNewKeyRequest {
    key_provisioner_pgp_certs: Vec<PgpPublicCert>,
    params: SecretSharingParams,
}

/// `EnclaveSigned<T>`
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SetupNewKeyResponse {
    pub encrypted_shares: KPEncryptedShares,
    pub secret_sharing_instance: SecretSharingInstance,
    /// x-only BTC master pubkey, surfaced so the operator can publish it on-chain
    /// as `guardian_btc_public_key` before the guardian is provisioned.
    pub btc_master_pubkey: BitcoinPubkey,
}

/// Ceremony-mode rotation request, assembled by the operator from the current KPs'
/// encrypted old shares (each bound to `state.digest()` as AAD) and the shared
/// rotation target `state`.
#[derive(Debug, Clone, PartialEq)]
pub struct RotateKpsRequest {
    // TODO: Use the same unique-id wrapper as ProvisionerInitRequest once we
    // centralize validation for submitted guardian share batches.
    encrypted_old_shares: Vec<GuardianEncryptedShare>,
    old_instance: SecretSharingInstance,
    state: RotateKpsState,
}

/// The shared rotation target all current KPs authorize. Each binds
/// `state.digest()` as HPKE AAD on its submission, so the enclave only decrypts
/// ones that agree on it. Old/new (`n`, `t`) may differ.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RotateKpsState {
    /// OpenPGP certs for the new KP set, sorted to a canonical order
    /// (see `RotateKpsState::new`). Length equals `new_params.num_shares()`.
    new_kp_pgp_certs: Vec<PgpPublicCert>,
    new_params: SecretSharingParams,
}

/// `EnclaveSigned<T>`. The new KP set's encrypted shares, returned by `rotate_kps`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RotateKpsResponse {
    pub encrypted_shares: KPEncryptedShares,
}

// ---------------------------------
//      Helper types & structs
// ---------------------------------

/// 32-byte UID of the on-chain `WithdrawalTransaction` Sui object.
/// Used to correlate events across Sui, hashi nodes, and the guardian.
pub type WithdrawalID = sui_sdk_types::Address;

/// Guardian session identifier. Canonical IDs are short prefixes of the
/// hex-encoded signing public key and tag per-session S3 objects.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct SessionID(String);

impl SessionID {
    /// Length of the signing-public-key prefix used for canonical session IDs.
    pub const HEX_LEN: usize = 16;

    pub fn from_signing_pubkey(signing_pub_key: &GuardianPubKey) -> Self {
        let mut session_id = ::hex::encode(signing_pub_key.as_bytes());
        session_id.truncate(Self::HEX_LEN);
        Self(session_id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SessionID {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SessionID {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<SessionID> for String {
    fn from(value: SessionID) -> Self {
        value.0
    }
}

impl AsRef<str> for SessionID {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for SessionID {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Deref for SessionID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for SessionID {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub bucket_info: S3BucketInfo,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3BucketInfo {
    pub bucket: String,
    pub region: String,
}

// ---------------------------------
//          Helper impl's
// ---------------------------------

impl S3Config {
    pub fn bucket_name(&self) -> &str {
        &self.bucket_info.bucket
    }

    pub fn region(&self) -> &str {
        &self.bucket_info.region
    }
}

impl SetupNewKeyRequest {
    pub fn new(
        pgp_certs: Vec<PgpPublicCert>,
        num_shares: usize,
        threshold: usize,
    ) -> GuardianResult<Self> {
        let params = SecretSharingParams::new(num_shares, threshold)?;
        if pgp_certs.len() != params.num_shares() {
            return Err(InvalidInputs(format!(
                "expected {} OpenPGP certificates, got {}",
                params.num_shares(),
                pgp_certs.len()
            )));
        }
        ensure_unique_pgp_cert_fingerprints(&pgp_certs)?;
        Ok(Self {
            key_provisioner_pgp_certs: pgp_certs,
            params,
        })
    }

    pub fn pgp_certs(&self) -> &[PgpPublicCert] {
        &self.key_provisioner_pgp_certs
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

fn ensure_unique_pgp_cert_fingerprints(pgp_certs: &[PgpPublicCert]) -> GuardianResult<()> {
    let mut seen = std::collections::HashSet::with_capacity(pgp_certs.len());
    for cert in pgp_certs {
        let fingerprint = cert.fingerprint();
        if !seen.insert(fingerprint.clone()) {
            return Err(InvalidInputs(format!(
                "duplicate OpenPGP certificate fingerprint {fingerprint}"
            )));
        }
    }
    Ok(())
}

impl OperatorInitRequest {
    /// Build a ceremony-mode request (S3 only).
    pub fn new_ceremony_mode(s3_config: S3Config) -> Self {
        Self {
            s3_config,
            init_config: None,
        }
    }

    /// Build a withdraw-mode request carrying the stable operator config.
    pub fn new_withdraw_mode(s3_config: S3Config, init_config: InitConfig) -> Self {
        Self {
            s3_config,
            init_config: Some(init_config),
        }
    }

    pub fn s3_config(&self) -> &S3Config {
        &self.s3_config
    }

    pub fn init_config(&self) -> Option<&InitConfig> {
        self.init_config.as_ref()
    }

    /// `init_config` must be present iff the enclave runs in withdraw mode.
    pub fn validate(&self, mode: EnclaveMode) -> GuardianResult<()> {
        match (mode, self.init_config.is_some()) {
            (EnclaveMode::Withdraw, false) => Err(InvalidInputs(
                "withdraw-mode operator_init requires an InitConfig".into(),
            )),
            (EnclaveMode::Ceremony, true) => Err(InvalidInputs(
                "ceremony-mode operator_init must carry only S3 config".into(),
            )),
            _ => Ok(()),
        }
    }

    pub fn into_parts(self) -> (S3Config, Option<InitConfig>) {
        (self.s3_config, self.init_config)
    }
}

impl OperatorWriteGenesisRequest {
    pub fn new(committee: HashiCommittee) -> Self {
        Self {
            committee: (&committee).into(),
        }
    }

    pub fn from_move_committee(committee: crate::move_types::Committee) -> Self {
        Self { committee }
    }

    pub fn committee(&self) -> &crate::move_types::Committee {
        &self.committee
    }

    pub fn into_committee(self) -> crate::move_types::Committee {
        self.committee
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
    pub fn new(
        limiter_config: LimiterConfig,
        hashi_btc_master_pubkey: HashiMasterG,
        pcr_allowlist: PcrAllowlist,
        network: Network,
    ) -> GuardianResult<Self> {
        Ok(Self {
            limiter_config,
            hashi_btc_master_pubkey,
            pcr_allowlist,
            network,
        })
    }

    pub fn into_parts(self) -> (LimiterConfig, HashiMasterG, PcrAllowlist, Network) {
        (
            self.limiter_config,
            self.hashi_btc_master_pubkey,
            self.pcr_allowlist,
            self.network,
        )
    }

    pub fn limiter_config(&self) -> &LimiterConfig {
        &self.limiter_config
    }

    pub fn hashi_btc_master_pubkey(&self) -> HashiMasterG {
        self.hashi_btc_master_pubkey
    }

    pub fn pcr_allowlist(&self) -> &PcrAllowlist {
        &self.pcr_allowlist
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The `config_hash`: the digest KPs authenticate in their signed PI
    /// submissions.
    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(&InitConfigRepr::from(self)).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl SingleProvisionerInitRequest {
    /// Build one KP's PI contribution, encrypting `share` to the enclave's
    /// session key. Agreement on the stable config is authenticated by the KP
    /// signature over this request, not by HPKE AAD.
    pub fn build_from_share<R: CryptoRng + RngCore>(
        expected_session_id: SessionID,
        expected_config_hash: [u8; 32],
        share: &Share,
        enclave_pub_key: &EncPubKey,
        rng: &mut R,
    ) -> Self {
        Self::new(
            expected_session_id,
            expected_config_hash,
            encrypt_share(share, enclave_pub_key, None, rng),
        )
    }

    pub fn new(
        expected_session_id: SessionID,
        expected_config_hash: [u8; 32],
        encrypted_share: GuardianEncryptedShare,
    ) -> Self {
        Self {
            expected_session_id,
            expected_config_hash,
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

    pub fn into_parts(self) -> (SessionID, [u8; 32], GuardianEncryptedShare) {
        (
            self.expected_session_id,
            self.expected_config_hash,
            self.encrypted_share,
        )
    }
}

impl RotateKpsState {
    pub fn new(
        new_kp_pgp_certs: Vec<PgpPublicCert>,
        new_num_shares: usize,
        new_threshold: usize,
    ) -> GuardianResult<Self> {
        let new_params = SecretSharingParams::new(new_num_shares, new_threshold)?;
        if new_kp_pgp_certs.len() != new_params.num_shares() {
            return Err(InvalidInputs(format!(
                "expected {} new KP certs, got {}",
                new_params.num_shares(),
                new_kp_pgp_certs.len()
            )));
        }
        ensure_unique_pgp_cert_fingerprints(&new_kp_pgp_certs)?;
        // Sort to a canonical order so the serialized state's digest (which all
        // T old KPs must agree on) is independent of submission order.
        let mut new_kp_pgp_certs = new_kp_pgp_certs;
        new_kp_pgp_certs.sort();
        Ok(Self {
            new_kp_pgp_certs,
            new_params,
        })
    }

    pub fn new_kp_pgp_certs(&self) -> &[PgpPublicCert] {
        &self.new_kp_pgp_certs
    }

    pub fn new_params(&self) -> &SecretSharingParams {
        &self.new_params
    }

    pub fn into_parts(self) -> (Vec<PgpPublicCert>, SecretSharingParams) {
        (self.new_kp_pgp_certs, self.new_params)
    }

    pub fn digest(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(self).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl RotateKpsRequest {
    pub fn new(
        encrypted_old_shares: Vec<GuardianEncryptedShare>,
        old_instance: SecretSharingInstance,
        state: RotateKpsState,
    ) -> Self {
        Self {
            encrypted_old_shares,
            old_instance,
            state,
        }
    }

    /// Encrypt one KP's `share` to `enclave_pub_key` with `state.digest()` bound
    /// as HPKE AAD — tying the share to the specific rotation target that KP is
    /// authorizing. Each current KP produces one of these; the operator bundles
    /// them into a `RotateKpsRequest`.
    pub fn build_from_share_and_state<R: CryptoRng + RngCore>(
        share: &Share,
        enclave_pub_key: &EncPubKey,
        state: &RotateKpsState,
        rng: &mut R,
    ) -> GuardianEncryptedShare {
        encrypt_share(share, enclave_pub_key, Some(&state.digest()), rng)
    }

    pub fn encrypted_old_shares(&self) -> &[GuardianEncryptedShare] {
        &self.encrypted_old_shares
    }

    pub fn old_instance(&self) -> &SecretSharingInstance {
        &self.old_instance
    }

    pub fn state(&self) -> &RotateKpsState {
        &self.state
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<GuardianEncryptedShare>,
        SecretSharingInstance,
        RotateKpsState,
    ) {
        (self.encrypted_old_shares, self.old_instance, self.state)
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
        signed_info: GuardianSigned<GuardianInfo>,
    ) -> Self {
        Self {
            attestation,
            signing_pub_key,
            signed_info,
        }
    }

    /// Verify a live guardian response.
    ///
    /// Used by operator and KP tooling while initializing a guardian (ceremony,
    /// provisioning, and activation).
    ///
    /// Checks:
    /// - `signed_info` is signed by `signing_pub_key`;
    /// - its git revision matches `expected_build`;
    /// - the Nitro attestation has a valid signature;
    /// - the certificate chain is valid now;
    /// - the attested public key and PCR0 match `signing_pub_key` and `expected_build`.
    pub fn verify_live(&self, expected_build: &BuildPcrs) -> GuardianResult<VerifiedGuardianInfo> {
        let info = self.signed_info.clone().verify(&self.signing_pub_key)?;
        if info.untrusted_git_revision != expected_build.git_revision() {
            return Err(InvalidInputs(format!(
                "guardian info reports build '{}', expected current build '{}'",
                info.untrusted_git_revision,
                expected_build.git_revision()
            )));
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
        (self.signed_info.into_data_unchecked(), self.signing_pub_key)
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

/// Serializable representation of InitConfig. Used for computing its digest.
#[derive(Serialize)]
struct InitConfigRepr {
    pub limiter_config: LimiterConfig,
    pub hashi_btc_master_pubkey: HashiMasterG,
    pub pcr_allowlist: PcrAllowlist,
    pub network: String,
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

impl From<&InitConfig> for InitConfigRepr {
    fn from(config: &InitConfig) -> Self {
        let (limiter_config, hashi_btc_master_pubkey, pcr_allowlist, network) =
            config.clone().into_parts();
        Self {
            limiter_config,
            hashi_btc_master_pubkey,
            pcr_allowlist,
            network: network.to_string(),
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

    #[test]
    fn guardian_info_json_encodes_binary_fields_as_strings() {
        let (mut info, _) = GetGuardianInfoResponse::mock_for_testing().into_info_unchecked();
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
        let expected_info = resp.signed_info.data.clone();
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

        assert!(matches!(
            resp.verify_live(&BuildPcrs::new("test-revision", vec![0]))
                .unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn rotate_kps_state_new_rejects_wrong_cert_count() {
        let mut certs = test_utils::mock_pgp_certs(5);
        certs.pop();
        assert!(matches!(
            RotateKpsState::new(certs, 5, 3).unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn rotate_kps_state_new_rejects_duplicate_certs() {
        let mut certs = test_utils::mock_pgp_certs(5);
        certs[1] = certs[0].clone();
        assert!(matches!(
            RotateKpsState::new(certs, 5, 3).unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn setup_new_key_request_rejects_duplicate_cert_fingerprints() {
        let mut certs = test_utils::mock_pgp_certs(5);
        certs[1] = certs[0].clone();
        let err = SetupNewKeyRequest::new(certs, 5, 3).unwrap_err();
        assert!(
            matches!(err, InvalidInputs(msg) if msg.contains("duplicate OpenPGP certificate fingerprint"))
        );
    }

    #[test]
    fn pcr_allowlist_resolves_current_and_multiple_prev_builds() {
        let allowlist = PcrAllowlist::new(
            BuildPcrs::new("current", vec![0]),
            vec![
                BuildPcrs::new("prev-1", vec![1]),
                BuildPcrs::new("prev-2", vec![2]),
            ],
        )
        .unwrap();

        let current_build = allowlist.resolve("current").unwrap();
        assert_eq!(current_build.pcr0(), &[0]);
        assert!(allowlist.is_current_build(current_build));
        let prev_build = allowlist.resolve("prev-1").unwrap();
        assert_eq!(prev_build.pcr0(), &[1]);
        assert!(!allowlist.is_current_build(prev_build));
        let prev2_build = allowlist.resolve("prev-2").unwrap();
        assert_eq!(prev2_build.pcr0(), &[2]);
    }

    #[test]
    fn pcr_allowlist_rejects_duplicate_build_revisions() {
        let err = PcrAllowlist::new(
            BuildPcrs::new("current", vec![0]),
            vec![BuildPcrs::new("current", vec![1])],
        )
        .unwrap_err();

        assert!(matches!(err, InvalidInputs(msg) if msg.contains("duplicate PCR allowlist entry")));
    }

    #[test]
    fn pcr_allowlist_deserializes_hex_wire_form() {
        let allowlist: PcrAllowlist = serde_json::from_value(serde_json::json!({
            "current_build": {
                "git_revision": "current",
                "pcr0": "0x00ff"
            },
            "prev_builds": [
                {
                    "git_revision": "prev",
                    "pcr0": "01"
                }
            ]
        }))
        .unwrap();

        let current_build = allowlist.resolve("current").unwrap();
        assert_eq!(current_build.pcr0(), &[0x00, 0xff]);
        let prev_build = allowlist.resolve("prev").unwrap();
        assert_eq!(prev_build.pcr0(), &[0x01]);
    }

    #[test]
    fn pcr_allowlist_requires_current_build() {
        let allowlist = PcrAllowlist::new(
            BuildPcrs::new("current", vec![0]),
            vec![BuildPcrs::new("prev", vec![1])],
        )
        .unwrap();

        let current_build = allowlist.resolve("current").unwrap();
        allowlist.require_current_build(current_build).unwrap();

        let prev_build = allowlist.resolve("prev").unwrap();
        assert!(allowlist.require_current_build(prev_build).is_err());
    }

    #[test]
    fn rotate_kps_state_digest_is_order_independent() {
        let certs = test_utils::mock_pgp_certs(5);
        let reversed: Vec<PgpPublicCert> = certs.iter().rev().cloned().collect();
        let a = RotateKpsState::new(certs, 5, 3).unwrap();
        let b = RotateKpsState::new(reversed, 5, 3).unwrap();
        // Same set, different input order ⇒ identical canonical form and digest.
        assert_eq!(a.new_kp_pgp_certs(), b.new_kp_pgp_certs());
        assert_eq!(a.digest(), b.digest());
    }
}
