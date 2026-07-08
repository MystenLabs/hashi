// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The `LogMessage` family the enclave emits, and the per-message S3 key naming
//! (`log_dir`/`log_name`). The `LogRecord` wrapper that carries these to S3 lives
//! in `super::envelope`.

use super::S3_DIR_CEREMONY;
use super::S3_DIR_COMMITTEE_UPDATE;
use super::S3_DIR_HEARTBEAT;
use super::S3_DIR_INIT;
use super::S3_DIR_SHARES;
use super::S3_DIR_WITHDRAW;
use crate::bitcoin::BitcoinPubkey;
use crate::committee::CommitteeSignature;
use crate::guardian::GuardianError;
use crate::guardian::GuardianInfo;
use crate::guardian::GuardianPubKey;
use crate::guardian::KPEncryptedShares;
use crate::guardian::KPFingerprint;
use crate::guardian::LimiterState;
use crate::guardian::NitroAttestation;
use crate::guardian::SecretSharingInstance;
use crate::guardian::ShareID;
use crate::guardian::StandardWithdrawalRequestWire;
use crate::guardian::StandardWithdrawalResponse;
use crate::guardian::UnixMillis;
use crate::guardian::WithdrawalID;
use crate::guardian::s3_utils::S3HourScopedDirectory;
use crate::guardian::unix_millis_to_seconds;
use bitcoin::Txid;
use serde::Deserialize;
use serde::Serialize;

/// All log messages emitted by the guardian enclave.
/// Uses enum discriminator for automatic domain separation between variants.
#[derive(Debug, Serialize, Deserialize)]
pub enum LogMessage {
    Heartbeat { seq: u64 },
    Init(Box<InitLogMessage>),
    Withdrawal(Box<WithdrawalLogMessage>),
    Ceremony(Box<CeremonyLogMessage>),
    Shares(Box<SharesLogMessage>),
    CommitteeUpdate(Box<CommitteeUpdateLogMessage>),
}

/// Encrypted KP shares persisted for recovery, written to `shares/` after each
/// ceremony. Keyed by `sharing_seq` so it pairs with the matching `ceremony/`
/// instance; carries the ciphertexts the `ceremony/` log deliberately omits.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharesLogMessage {
    pub sharing_seq: u64,
    pub encrypted_shares: KPEncryptedShares,
}

impl SharesLogMessage {
    /// `shares/{sharing_seq:020}-{session_id}.json` — the object key a reader
    /// fetches for `(session_id, sharing_seq)`.
    pub fn object_key(session_id: &str, sharing_seq: u64) -> String {
        super::seq_scoped_object_key(S3_DIR_SHARES, sharing_seq, session_id)
    }
}

/// The authoritative share state, written to `ceremony/` after each ceremony.
/// Carries the instance (commitments + n/t/seq) plus the recipient roster; the
/// ciphertexts live in `shares/`. A rotation records the `old_instance` it
/// consumed so the chain is auditable from the log alone.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CeremonyLogMessage {
    /// Initial key setup (`setup_new_key`); `instance` has `sharing_seq` 0.
    NewKey {
        instance: SecretSharingInstance,
        /// Recipient fingerprints ordered by share id; lets a KP check the full
        /// roster against the agreed set from the immutable log, not just the
        /// operator-served shares.
        roster: Vec<KPFingerprint>,
        /// The x-only BTC master pubkey this ceremony produced; lets KPs and
        /// monitors cross-check it against the on-chain `guardian_btc_public_key`.
        btc_master_pubkey: BitcoinPubkey,
    },
    /// Key rotation (`rotate_kps`) from `old_instance` to `new_instance`.
    Rotate {
        old_instance: SecretSharingInstance,
        new_instance: SecretSharingInstance,
        /// Recipient fingerprints for `new_instance`; see [`Self::NewKey`].
        roster: Vec<KPFingerprint>,
        /// See [`Self::NewKey`]; invariant across rotations (the same key is re-shared).
        btc_master_pubkey: BitcoinPubkey,
    },
}

impl CeremonyLogMessage {
    /// The resulting instance's `sharing_seq` — used as the `ceremony/` object key.
    pub fn sharing_seq(&self) -> u64 {
        match self {
            CeremonyLogMessage::NewKey { instance, .. } => instance.sharing_seq(),
            CeremonyLogMessage::Rotate { new_instance, .. } => new_instance.sharing_seq(),
        }
    }
}

/// OI: operator_init
/// PI: provisioner_init
/// Init messages are expected to be logged in the following order:
/// OIAttestationUnsigned -> OIGuardianInfo -> PIEnclaveFullyInitialized -> OAActivated.
#[derive(Debug, Serialize, Deserialize)]
pub enum InitLogMessage {
    /// Attestation and signing public key posted in /operator_init
    OIAttestationUnsigned {
        attestation: NitroAttestation,
        signing_public_key: GuardianPubKey,
    },
    /// Signed GuardianInfo logged in /operator_init (secret-sharing instance,
    /// config_hash, encryption/BTC pubkeys). Boxed: much larger than the other
    /// variants (`clippy::large_enum_variant`).
    OIGuardianInfo(Box<GuardianInfo>),
    /// Threshold reached — enclave BTC key reconstructed (happens once). Records
    /// the ids of the shares that were combined.
    PIEnclaveFullyInitialized { share_ids: Vec<ShareID> },
    /// Operator activation succeeded and installed live serving state.
    OAActivated { state_hash: [u8; 32] },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WithdrawalLogMessage {
    Success {
        txid: Txid,
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        response: StandardWithdrawalResponse,
        /// Limiter state after this withdrawal was consumed. The KP rotating in
        /// the next enclave reads the max-seq Success log and uses its
        /// `post_state` as the new enclave's initial limiter state.
        post_state: LimiterState,
    },
    Failure {
        request_data: StandardWithdrawalRequestWire,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CommitteeUpdateLogMessage {
    /// `from_epoch` is the guardian's current epoch at the time; the
    /// applied epoch is `new_committee.epoch`. Both are recorded because
    /// hashi reconfig is sparse — `new_committee.epoch` is not
    /// necessarily `from_epoch + 1`.
    Success {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
    },
    /// `from_epoch` is the guardian's current epoch at the time;
    /// `new_committee` is what was proposed (and rejected).
    Failure {
        from_epoch: u64,
        new_committee: crate::move_types::Committee,
        request_sign: CommitteeSignature,
        error: GuardianError,
    },
}

impl InitLogMessage {
    pub const OI_ATTEST_UNSIGNED: &'static str = "oi-attestation-unsigned";
    pub const OI_GUARDIAN_INFO: &'static str = "oi-guardian-info";
    pub const PI_FULLY_INITIALIZED: &'static str = "pi-enclave-fully-initialized";
    pub const OA_ACTIVATED: &'static str = "oa-activated";

    pub fn log_name(&self, prefix: &str) -> String {
        let suffix = match self {
            InitLogMessage::OIAttestationUnsigned { .. } => Self::OI_ATTEST_UNSIGNED.to_string(),
            InitLogMessage::OIGuardianInfo(_) => Self::OI_GUARDIAN_INFO.to_string(),
            InitLogMessage::PIEnclaveFullyInitialized { .. } => {
                Self::PI_FULLY_INITIALIZED.to_string()
            }
            InitLogMessage::OAActivated { .. } => Self::OA_ACTIVATED.to_string(),
        };

        format!("{}-{}.json", prefix, suffix)
    }

    pub fn attestation_object_key(session_id: &str) -> String {
        format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            Self::OI_ATTEST_UNSIGNED
        )
    }

    pub fn guardian_info_object_key(session_id: &str) -> String {
        format!(
            "{}/{}-{}.json",
            S3_DIR_INIT,
            session_id,
            Self::OI_GUARDIAN_INFO
        )
    }
}

impl WithdrawalLogMessage {
    /// Success keys lead with `success-{seq:020}` so that lexicographic listing
    /// within an hour bucket is also seq-sorted — the last key is the max-seq
    /// log, which the KP reads to recover limiter state. Failures don't have a
    /// meaningful seq (the request's seq may be stale), so they use a random
    /// suffix for dedup.
    pub fn log_name(&self, prefix: &str) -> String {
        match self {
            WithdrawalLogMessage::Success { request_data, .. } => format!(
                "success-{:020}-{}-wid{}.json",
                request_data.seq,
                prefix,
                self.wid()
            ),
            WithdrawalLogMessage::Failure { .. } => {
                let random_suffix = rand::random::<u32>();
                format!(
                    "failure-{}-wid{}-{:08x}.json",
                    prefix,
                    self.wid(),
                    random_suffix
                )
            }
        }
    }

    pub fn wid(&self) -> WithdrawalID {
        match self {
            WithdrawalLogMessage::Success { request_data, .. } => request_data.wid,
            WithdrawalLogMessage::Failure { request_data, .. } => request_data.wid,
        }
    }
}

impl CommitteeUpdateLogMessage {
    /// Success keys lead with the new epoch (zero-padded) so a lex listing
    /// is epoch-sorted; failures lead with `failure-` so they sort after
    /// all successes, leaving the lex-last success key as the latest
    /// successfully-applied epoch.
    pub fn log_name(&self, prefix: &str) -> String {
        match self {
            CommitteeUpdateLogMessage::Success { new_committee, .. } => {
                format!("{:020}-{}.json", new_committee.epoch, prefix)
            }
            CommitteeUpdateLogMessage::Failure { new_committee, .. } => {
                let random_suffix = rand::random::<u32>();
                format!(
                    "failure-{:020}-{}-{:08x}.json",
                    new_committee.epoch, prefix, random_suffix
                )
            }
        }
    }
}

impl LogMessage {
    pub fn is_allowed_unsigned(&self) -> bool {
        if let LogMessage::Init(init_message) = self {
            matches!(**init_message, InitLogMessage::OIAttestationUnsigned { .. })
        } else {
            false
        }
    }

    pub fn must_be_signed(&self) -> bool {
        !self.is_allowed_unsigned()
    }

    /// The directory under which logs are written. Ends with a slash.
    pub fn log_dir(&self, timestamp_ms: UnixMillis) -> String {
        match self {
            LogMessage::Init(_) => format!("{}/", S3_DIR_INIT),
            LogMessage::Heartbeat { .. } => {
                S3HourScopedDirectory::new(S3_DIR_HEARTBEAT, unix_millis_to_seconds(timestamp_ms))
                    .to_string()
            }
            LogMessage::Withdrawal(..) => {
                S3HourScopedDirectory::new(S3_DIR_WITHDRAW, unix_millis_to_seconds(timestamp_ms))
                    .to_string()
            }
            LogMessage::Ceremony(..) => format!("{}/", S3_DIR_CEREMONY),
            LogMessage::Shares(..) => format!("{}/", S3_DIR_SHARES),
            LogMessage::CommitteeUpdate(..) => format!("{}/", S3_DIR_COMMITTEE_UPDATE),
        }
    }

    /// The name of the log.
    pub fn log_name(&self, prefix: &str) -> String {
        match self {
            LogMessage::Init(init_message) => init_message.log_name(prefix),
            LogMessage::Heartbeat { seq } => format!("{}-{:020}.json", prefix, seq),
            LogMessage::Withdrawal(withdrawal_message) => withdrawal_message.log_name(prefix),
            LogMessage::Ceremony(ss) => format!("{:020}-{}.json", ss.sharing_seq(), prefix),
            LogMessage::Shares(s) => format!("{:020}-{}.json", s.sharing_seq, prefix),
            LogMessage::CommitteeUpdate(committee_message) => committee_message.log_name(prefix),
        }
    }

    pub fn into_init_log(self) -> Option<InitLogMessage> {
        match self {
            LogMessage::Init(init_message) => Some(*init_message),
            _ => None,
        }
    }
}
