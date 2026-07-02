// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod attestation;
pub mod crypto;
pub mod errors;
pub mod log;
pub mod proto_conversions;
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
pub use limiter::LimiterConfig;
pub use limiter::LimiterState;
pub use limiter::RateLimiter;
pub use log::*;
pub use signing::GuardianSigned;
pub use signing::IntentType;
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
// ---------------------------------
//          Constants
// ---------------------------------

/// Length of the session ID prefix (hex chars) used in S3 keys. 16 hex =
/// 64 bits of the signing pubkey, comfortably below any collision risk for
/// realistic session counts.
pub const SESSION_ID_HEX_LEN: usize = 16;

/// Canonical guardian session ID — a short prefix of the hex-encoded signing
/// public key. Used as a per-session tag in S3 object keys; full pubkey
/// verification still happens via the signed log payload.
pub fn session_id_from_signing_pubkey(signing_pub_key: &GuardianPubKey) -> SessionID {
    let mut s = ::hex::encode(signing_pub_key.as_bytes());
    s.truncate(SESSION_ID_HEX_LEN);
    s
}

/// Which flows an enclave serves, fixed at boot. A `Ceremony` enclave runs
/// `setup_new_key`/`rotate_kps`; a `Withdraw` enclave runs `provisioner_init` +
/// `standard_withdrawal`. `operator_init`, `get_guardian_info` are enabled in both modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveMode {
    Ceremony,
    Withdraw,
}

// ---------------------------------
//    Common requests and responses
// ---------------------------------

/// Operator-supplied bootstrap. A ceremony-mode enclave (setup/rotate) needs only
/// `s3_config`; a withdraw-mode enclave additionally carries the `WithdrawModeConfig`
/// (committee, limiter, BTC master pubkey, secret-sharing instance, network) whose
/// digest is the share-decryption AAD.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorInitRequest {
    s3_config: S3Config,
    state: Option<WithdrawModeConfig>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct GetGuardianInfoResponse {
    /// AWS Nitro attestation
    attestation: NitroAttestation,
    /// Signing pub key of the guardian
    signing_pub_key: GuardianPubKey,
    /// Signed guardian info
    signed_info: GuardianSigned<GuardianInfo>,
    /// Encrypted shares from the ceremony (empty in non-ceremony mode); KPs
    /// fetch their share here and verify it against the instance commitments.
    encrypted_shares: KPEncryptedShares,
}

#[derive(Debug, PartialEq, Clone)]
pub struct VerifiedGuardianInfo {
    pub info: GuardianInfo,
    pub signing_pub_key: GuardianPubKey,
    pub session_id: SessionID,
    pub encrypted_shares: KPEncryptedShares,
}

/// TODO: Add network?
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GuardianInfo {
    // TODO: expose the enclave `EnclaveMode` here so clients can assert they
    // are talking to a ceremony-mode or withdraw-mode guardian from signed info.
    /// Secret-sharing instance (if set). Used by KPs to check that the right key will be used.
    pub secret_sharing_instance: Option<SecretSharingInstance>,
    /// S3 bucket name (if set). Used by KPs to check S3 bucket info.
    pub bucket_info: Option<S3BucketInfo>,
    /// Encryption key. Used by KPs to encrypt their shares.
    pub encryption_pubkey: EncPubKeyBytes,
    /// Digest of the operator-supplied `WithdrawModeState` (set after operator_init).
    /// KPs recompute it from their verified sources and match to confirm config.
    pub state_hash: Option<[u8; 32]>,
    /// Git revision of the guardian build. Untrusted (enclave-self-reported);
    /// verified out-of-band by reproducibly building at this revision and matching
    /// PCRs against the session's attestation.
    pub untrusted_git_revision: GitRevision,
    /// Enclave BTC signing pubkey (x-only). Absent before `provisioner_init`.
    pub enclave_btc_pubkey: Option<BitcoinPubkey>,
    /// Current rate limiter state (if initialized).
    pub limiter_state: Option<LimiterState>,
    /// Immutable limiter configuration (if initialized).
    pub limiter_config: Option<LimiterConfig>,
    /// Current committee epoch (if initialized). Drives `UpdateCommittee` catch-up.
    pub current_committee_epoch: Option<u64>,
    /// MPC committee verifying key `G` (the derivation master, NOT the guardian's
    /// own BTC key). Set after operator_init; lets KPs verify it directly.
    pub mpc_master_g: Option<HashiMasterG>,
    /// Fingerprints of the KPs authorized to submit shares to the relay. Empty
    /// before operator_init. Read directly (not via `into_parts`) by the
    /// out-of-enclave relay to reject submissions from non-KPs.
    pub authorized_kp_fingerprints: Vec<KPFingerprint>,
    // TODO: report the full committee too, so its membership is directly
    // verifiable (today only the `state_hash` digest covers it); it's large, though.
}

// ---------------------------------------
//    Withdraw mode requests and responses
// ---------------------------------------

/// Full operator-supplied withdraw-mode config: the attested `WithdrawModeState`
/// plus delivery-only fields that are enforced elsewhere and so are excluded from
/// the digest (the instance via direct share verification; network is share-irrelevant).
/// Supplied to `operator_init`.
#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawModeConfig {
    state: WithdrawModeState,
    /// Secret-sharing scheme for the current BTC key (commitments + N + T).
    secret_sharing_instance: SecretSharingInstance,
    /// BTC network.
    network: Network,
    /// Fingerprints of the KPs authorized to provision this key. Surfaced via
    /// GuardianInfo for the relay's submitter check; not part of the digest.
    authorized_kp_fingerprints: Vec<KPFingerprint>,
}

/// The withdraw-mode state KPs attest to. Its `digest()` is the `state_hash`:
/// bound as HPKE AAD on each KP's share and exposed (as a hash) via `GuardianInfo`.
/// These are exactly the fields whose agreement is enforced *only* via the digest.
#[derive(Debug, Clone, PartialEq)]
pub struct WithdrawModeState {
    /// Current Hashi committee
    committee: HashiCommittee,
    /// Limiter config
    limiter_config: LimiterConfig,
    /// Limiter state (tokens available, timestamp, seq)
    limiter_state: LimiterState,
    /// Raw MPC verifying key (curve point with y-parity preserved). The
    /// guardian uses this directly for `derive_verifying_key` so the
    /// 2-of-2 child key in the leaf script matches the MPC signature.
    hashi_btc_master_pubkey: HashiMasterG,
}

/// The current KPs' encrypted key shares, assembled into one submission (in the
/// relay model, by the relay once it has collected enough). Each share's HPKE AAD
/// binds the enclave's `state_hash` (the `WithdrawModeState` digest), so a share
/// only decrypts if the KP agreed on the operator-supplied state.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionerInitRequest {
    // TODO: Wrap submitted guardian shares in a domain type that rejects
    // duplicate share ids. Unlike KP output shares, submitted shares are a
    // threshold batch and need not be contiguous 1..=n.
    encrypted_shares: Vec<GuardianEncryptedShare>,
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

/// Guardian session identifier — a short prefix of the hex-encoded signing
/// pubkey (see [`session_id_from_signing_pubkey`]). Tags per-session S3 objects.
pub type SessionID = String;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct S3Config {
    pub access_key: String,
    pub secret_key: String,
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
            state: None,
        }
    }

    /// Build a withdraw-mode request carrying the full operator config.
    pub fn new_withdraw_mode(s3_config: S3Config, state: WithdrawModeConfig) -> Self {
        Self {
            s3_config,
            state: Some(state),
        }
    }

    pub fn s3_config(&self) -> &S3Config {
        &self.s3_config
    }

    pub fn state(&self) -> Option<&WithdrawModeConfig> {
        self.state.as_ref()
    }

    /// `state` must be present iff the enclave runs in withdraw mode.
    pub fn validate(&self, mode: EnclaveMode) -> GuardianResult<()> {
        match (mode, self.state.is_some()) {
            (EnclaveMode::Withdraw, false) => Err(InvalidInputs(
                "withdraw-mode operator_init requires a WithdrawModeConfig".into(),
            )),
            (EnclaveMode::Ceremony, true) => Err(InvalidInputs(
                "ceremony-mode operator_init must carry only S3 config".into(),
            )),
            _ => Ok(()),
        }
    }

    pub fn into_parts(self) -> (S3Config, Option<WithdrawModeConfig>) {
        (self.s3_config, self.state)
    }
}

impl WithdrawModeState {
    pub fn new(
        committee: HashiCommittee,
        limiter_config: LimiterConfig,
        limiter_state: LimiterState,
        hashi_btc_master_pubkey: HashiMasterG,
    ) -> GuardianResult<Self> {
        // Validate that limiter state is consistent with config.
        if limiter_state.num_tokens_available > limiter_config.max_bucket_capacity {
            return Err(InvalidInputs(
                "limiter num_tokens_available exceeds max_bucket_capacity".into(),
            ));
        }
        Ok(Self {
            committee,
            limiter_config,
            limiter_state,
            hashi_btc_master_pubkey,
        })
    }

    pub fn into_parts(self) -> (HashiCommittee, LimiterConfig, LimiterState, HashiMasterG) {
        (
            self.committee,
            self.limiter_config,
            self.limiter_state,
            self.hashi_btc_master_pubkey,
        )
    }

    pub fn limiter_config(&self) -> &LimiterConfig {
        &self.limiter_config
    }

    pub fn hashi_btc_master_pubkey(&self) -> HashiMasterG {
        self.hashi_btc_master_pubkey
    }

    /// The `state_hash`: the digest KPs bind as their share-encryption AAD.
    /// Excludes `secret_sharing_instance` (enforced via verify_share) and
    /// `network` (share-irrelevant), which is why those live outside this struct.
    pub fn digest(&self) -> [u8; 32] {
        let bytes =
            bcs::to_bytes(&WithdrawModeStateRepr::from(self)).expect("serialization should work");
        Blake2b::<U32>::digest(bytes).into()
    }
}

impl WithdrawModeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        committee: HashiCommittee,
        limiter_config: LimiterConfig,
        limiter_state: LimiterState,
        hashi_btc_master_pubkey: HashiMasterG,
        secret_sharing_instance: SecretSharingInstance,
        network: Network,
        authorized_kp_fingerprints: Vec<KPFingerprint>,
    ) -> GuardianResult<Self> {
        let state = WithdrawModeState::new(
            committee,
            limiter_config,
            limiter_state,
            hashi_btc_master_pubkey,
        )?;
        Ok(Self {
            state,
            secret_sharing_instance,
            network,
            authorized_kp_fingerprints,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        WithdrawModeState,
        SecretSharingInstance,
        Network,
        Vec<KPFingerprint>,
    ) {
        (
            self.state,
            self.secret_sharing_instance,
            self.network,
            self.authorized_kp_fingerprints,
        )
    }

    pub fn state(&self) -> &WithdrawModeState {
        &self.state
    }

    pub fn secret_sharing_instance(&self) -> &SecretSharingInstance {
        &self.secret_sharing_instance
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn authorized_kp_fingerprints(&self) -> &[KPFingerprint] {
        &self.authorized_kp_fingerprints
    }
}

/// Domain tag mixed into the bytes a KP signs to authenticate a relay
/// submission. Bump the version if the signed layout ever changes.
const RELAY_SUBMISSION_DOMAIN: &str = "hashi-kp-relay-submission-v1";

#[derive(Serialize)]
struct RelaySubmissionAuthPayload<'a> {
    domain: &'static str,
    session_id: &'a str,
    share: &'a GuardianEncryptedShare,
}

/// The exact bytes a key provisioner detached-signs (and the relay verifies) to
/// prove a relay submission came from a rostered KP. Binds the guardian session
/// and the encrypted share, so a captured signature can't be replayed against a
/// different share or session.
pub fn relay_submission_signed_bytes(session_id: &str, share: &GuardianEncryptedShare) -> Vec<u8> {
    bcs::to_bytes(&RelaySubmissionAuthPayload {
        domain: RELAY_SUBMISSION_DOMAIN,
        session_id,
        share,
    })
    .expect("BCS serialization of a relay submission payload is infallible")
}

impl ProvisionerInitRequest {
    pub fn new(encrypted_shares: Vec<GuardianEncryptedShare>) -> Self {
        Self { encrypted_shares }
    }

    /// Encrypt one KP's `share` to the enclave's public key, binding `state_hash`
    /// (the enclave's `WithdrawModeConfig` digest) as HPKE AAD — so the enclave
    /// only decrypts shares from KPs that agreed on that state. Each KP produces
    /// one of these; they are bundled into a `ProvisionerInitRequest`.
    pub fn build_from_share<R: CryptoRng + RngCore>(
        share: &Share,
        enclave_pub_key: &EncPubKey,
        state_hash: [u8; 32],
        rng: &mut R,
    ) -> GuardianEncryptedShare {
        encrypt_share(share, enclave_pub_key, Some(&state_hash), rng)
    }

    pub fn encrypted_shares(&self) -> &[GuardianEncryptedShare] {
        &self.encrypted_shares
    }

    pub fn into_parts(self) -> Vec<GuardianEncryptedShare> {
        self.encrypted_shares
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

impl GuardianInfo {
    /// Destructure an operator-initialized `GuardianInfo`, erroring if any field
    /// set at operator-init is absent. `enclave_btc_pubkey` stays `Option` — it
    /// is only set later, at `provisioner_init`.
    // Returns every info field by design; a tuple alias wouldn't read any clearer.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> GuardianResult<(
        SecretSharingInstance,
        S3BucketInfo,
        EncPubKeyBytes,
        [u8; 32],
        GitRevision,
        Option<BitcoinPubkey>,
        LimiterState,
        LimiterConfig,
        u64,
        HashiMasterG,
    )> {
        Ok((
            self.secret_sharing_instance
                .ok_or(InvalidInputs("missing secret sharing instance".into()))?,
            self.bucket_info
                .ok_or(InvalidInputs("missing bucket info".into()))?,
            self.encryption_pubkey,
            self.state_hash
                .ok_or(InvalidInputs("missing state hash".into()))?,
            self.untrusted_git_revision,
            self.enclave_btc_pubkey,
            self.limiter_state
                .ok_or(InvalidInputs("missing limiter state".into()))?,
            self.limiter_config
                .ok_or(InvalidInputs("missing limiter config".into()))?,
            self.current_committee_epoch
                .ok_or(InvalidInputs("missing current committee epoch".into()))?,
            self.mpc_master_g
                .ok_or(InvalidInputs("missing mpc master g".into()))?,
        ))
    }
}

impl GetGuardianInfoResponse {
    pub fn new(
        attestation: NitroAttestation,
        signing_pub_key: GuardianPubKey,
        signed_info: GuardianSigned<GuardianInfo>,
        encrypted_shares: KPEncryptedShares,
    ) -> Self {
        Self {
            attestation,
            signing_pub_key,
            signed_info,
            encrypted_shares,
        }
    }

    /// Verify the response end to end and return the trusted guardian payload:
    /// the attestation anchors `signing_pub_key`, `signed_info` must be signed by
    /// it, the signed git revision must match `expected_build`, and PCR0 must
    /// match `expected_build`.
    pub fn verify(&self, expected_build: &BuildPcrs) -> GuardianResult<VerifiedGuardianInfo> {
        let info = self.signed_info.clone().verify(&self.signing_pub_key)?;
        if info.untrusted_git_revision != expected_build.git_revision() {
            return Err(InvalidInputs(format!(
                "guardian info reports build '{}', expected current build '{}'",
                info.untrusted_git_revision,
                expected_build.git_revision()
            )));
        }
        self.attestation
            .verify(&self.signing_pub_key, expected_build)?;
        Ok(VerifiedGuardianInfo {
            info,
            signing_pub_key: self.signing_pub_key,
            session_id: session_id_from_signing_pubkey(&self.signing_pub_key),
            encrypted_shares: self.encrypted_shares.clone(),
        })
    }

    /// Verify only the signed `GuardianInfo` payload.
    ///
    /// This does not authenticate the enclave image, the Nitro attestation, or
    /// PCRs. Prefer [`Self::verify`] whenever the caller has PCR config.
    pub fn verify_signed_info_without_attestation(&self) -> GuardianResult<VerifiedGuardianInfo> {
        let info = self.signed_info.clone().verify(&self.signing_pub_key)?;
        Ok(VerifiedGuardianInfo {
            info,
            signing_pub_key: self.signing_pub_key,
            session_id: session_id_from_signing_pubkey(&self.signing_pub_key),
            encrypted_shares: self.encrypted_shares.clone(),
        })
    }

    /// Extract the guardian's self-reported `GuardianInfo` WITHOUT verifying the
    /// signature or attestation. The node uses this after authenticating the
    /// guardian over TLS; withdrawals are gated by the on-chain BTC key, and the
    /// ed25519 signing key is verified only by KPs/monitors on the S3 audit logs.
    pub fn into_info_unchecked(self) -> GuardianInfo {
        self.signed_info.into_data_unchecked()
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

/// Serializable representation of WithdrawModeState. Used for computing its digest.
#[derive(Serialize)]
struct WithdrawModeStateRepr {
    pub committee: crate::move_types::Committee,
    pub limiter_config: LimiterConfig,
    pub limiter_state: LimiterState,
    pub hashi_btc_master_pubkey: HashiMasterG,
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

impl From<&WithdrawModeState> for WithdrawModeStateRepr {
    fn from(state: &WithdrawModeState) -> Self {
        let (committee, config, limiter_state, pubkey) = state.clone().into_parts();
        Self {
            committee: (&committee).into(),
            limiter_config: config,
            limiter_state,
            hashi_btc_master_pubkey: pubkey,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_guardian_info_verify_signed_info_passes_for_valid_signature() {
        let resp = GetGuardianInfoResponse::mock_for_testing();
        let verified = resp.verify_signed_info_without_attestation().unwrap();

        assert_eq!(verified.signing_pub_key, resp.signing_pub_key);
        assert_eq!(
            verified.session_id,
            session_id_from_signing_pubkey(&resp.signing_pub_key)
        );
        assert_eq!(verified.info, resp.signed_info.data);
        assert_eq!(verified.encrypted_shares, resp.encrypted_shares);
    }

    #[test]
    fn get_guardian_info_verify_uses_signed_info_verification() {
        let mut resp = GetGuardianInfoResponse::mock_for_testing();
        let mut sig_bytes: [u8; 64] = resp.signed_info.signature.to_bytes();
        sig_bytes[0] ^= 0xff;
        resp.signed_info.signature = GuardianSignature::from(sig_bytes);

        assert!(matches!(
            resp.verify(&BuildPcrs::new("test-revision", vec![0]))
                .unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn get_guardian_info_verify_signed_info_fails_when_pubkey_did_not_sign() {
        let mut resp = GetGuardianInfoResponse::mock_for_testing();
        let wrong_signing_key = GuardianSignKeyPair::new(rand::thread_rng());
        resp.signing_pub_key = wrong_signing_key.verification_key();

        assert!(matches!(
            resp.verify_signed_info_without_attestation().unwrap_err(),
            InvalidInputs(_)
        ));
    }

    #[test]
    fn get_guardian_info_verify_signed_info_fails_when_signature_tampered() {
        let mut resp = GetGuardianInfoResponse::mock_for_testing();
        let mut sig_bytes: [u8; 64] = resp.signed_info.signature.to_bytes();
        sig_bytes[0] ^= 0xff;
        resp.signed_info.signature = GuardianSignature::from(sig_bytes);

        assert!(matches!(
            resp.verify_signed_info_without_attestation().unwrap_err(),
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
