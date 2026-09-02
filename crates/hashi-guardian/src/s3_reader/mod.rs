// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Verified reads from the guardian's S3 logs.
//!
//! [`GuardianReader`] applies each log stream's S3 immutability policy, verifies
//! records with their writing session's attestation-anchored key and required
//! initialization logs, and caches the verified session info for reuse.

use crate::s3_client::GuardianS3Client;
use crate::s3_client::ImmutabilityCheck;
use hashi_types::guardian::s3::S3HourScopedDirectory;
use hashi_types::guardian::CeremonyCompletionLogMessage;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::CeremonyState;
use hashi_types::guardian::CommitteeUpdateLogMessage;
use hashi_types::guardian::GenesisLogMessage;
use hashi_types::guardian::GuardianError::InvalidInputs;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::KpShareStateLogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::ResolvedS3Config;
use hashi_types::guardian::SessionID;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;
use hashi_types::guardian::WithdrawalLogMessage;
use hashi_types::move_types::Committee;
use std::collections::HashMap;
use tracing::info;

mod heartbeat_checks;
mod limiter_recovery;
mod verified;

pub use verified::VerifiedLogRecord;
pub use verified::VerifiedSessionInfo;

/// Verified reader over the guardian's S3 logs.
///
/// Reads accept any allowlisted build unless the method explicitly requires
/// the current build. Reuse one reader so repeated reads can share cached
/// session attestations and signing keys.
pub struct GuardianReader {
    s3: GuardianS3Client,
    allowlist: PcrAllowlist,
    sessions: HashMap<SessionID, VerifiedSessionInfo>,
}

impl GuardianReader {
    /// Create a reader after checking S3 connectivity and object-lock support.
    pub async fn new(config: &ResolvedS3Config, allowlist: PcrAllowlist) -> GuardianResult<Self> {
        let s3 = GuardianS3Client::new_checked(config).await?;
        Ok(Self::from_s3_client(s3, allowlist))
    }

    /// Create a reader from an existing S3 client without another connectivity
    /// check.
    pub fn from_s3_client(s3: GuardianS3Client, allowlist: PcrAllowlist) -> Self {
        Self {
            s3,
            allowlist,
            sessions: HashMap::new(),
        }
    }

    /// Load and verify a session's attestation and guardian info on first use.
    async fn ensure_session_info_loaded(&mut self, session_id: &str) -> GuardianResult<()> {
        if !self.sessions.contains_key(session_id) {
            let session_info =
                VerifiedSessionInfo::read_from_s3(&self.s3, session_id, &self.allowlist).await?;
            self.sessions.insert(session_id.into(), session_info);
        }
        Ok(())
    }

    /// Verify a record and the initialization checkpoint required to emit it.
    async fn verify_record(&mut self, record: LogRecord) -> GuardianResult<VerifiedLogRecord> {
        self.ensure_session_info_loaded(record.session_id()).await?;
        let session_info = self
            .sessions
            .get_mut(record.session_id())
            .expect("session info was loaded above");
        session_info.verify_record(&self.s3, record).await
    }

    /// Read an immutable S3 record and verify it against its writing session.
    async fn read_verified_record(&mut self, key: &str) -> GuardianResult<VerifiedLogRecord> {
        let record = self.s3.get_log_record(key).await?;
        self.verify_record(record).await
    }

    /// Read and verify every immutable record in an hour-scoped directory.
    ///
    /// Each result retains its writing session's attested build PCRs because a
    /// directory may contain records from more than one build.
    pub async fn read_logs_in_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let prefix = dir.to_string();
        self.read_logs_with_prefix(&prefix).await
    }

    async fn read_logs_with_prefix(
        &mut self,
        prefix: &str,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let all_logs = self.s3.list_all_log_records_with_prefix(prefix).await?;

        let mut out = Vec::with_capacity(all_logs.len());
        for record in all_logs {
            let verified_record = self.verify_record(record).await?;
            out.push(verified_record);
        }
        Ok(out)
    }

    /// Read and verify successful withdrawal records in `dir`.
    ///
    /// This excludes rejected withdrawal requests, which do not represent
    /// Guardian approval events and are not inputs to the monitor state machine.
    pub async fn read_successful_withdrawals_in_dir(
        &mut self,
        dir: &S3HourScopedDirectory,
    ) -> GuardianResult<Vec<VerifiedLogRecord>> {
        let prefix = format!("{dir}{}", WithdrawalLogMessage::SUCCESS_OBJECT_KEY_PREFIX);
        self.read_logs_with_prefix(&prefix).await
    }

    /// Return verified session info after requiring the attested PCRs to match
    /// the current build.
    pub async fn get_current_session_info(
        &mut self,
        session_id: &str,
    ) -> GuardianResult<VerifiedSessionInfo> {
        self.ensure_session_info_loaded(session_id).await?;
        let session_info = self
            .sessions
            .get(session_id)
            .expect("session info was loaded above");
        self.allowlist
            .require_current_build(session_info.build_pcrs())?;
        Ok(session_info.clone())
    }

    /// Read and verify one ceremony record under the requested build policy.
    async fn read_ceremony_log_at_key(
        &mut self,
        key: &str,
        require_current: bool,
    ) -> GuardianResult<CeremonyLogMessage> {
        let verified_record = self.read_verified_record(key).await?;
        if require_current {
            self.allowlist
                .require_current_build(verified_record.build_pcrs())?;
        }
        let session_id = verified_record.entry().session_id().clone();
        let message = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::Ceremony(message)) | V2(LogMessageV2::Ceremony(message)) => *message,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a ceremony log at {key}")));
            }
        };
        log_verified_read(key, &session_id);
        Ok(message)
    }

    /// Read the highest unique ceremony completion marker.
    async fn read_latest_ceremony_completion(
        &mut self,
    ) -> GuardianResult<Option<(CeremonyCompletionLogMessage, SessionID)>> {
        let prefix = CeremonyCompletionLogMessage::object_key_dir();
        let keys = self.s3.list_keys(&prefix, true).await?;
        let Some((_, key)) = latest_unique_versioned_session_key(keys, &prefix, None)? else {
            return Ok(None);
        };

        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let message = match verified_record.into_entry().into_message() {
            V2(LogMessageV2::CeremonyCompletion(message)) => *message,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!(
                    "expected a ceremony completion log at {key}"
                )));
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some((message, session_id)))
    }

    /// Read the newest certificate snapshot after `cert_seq = 0`, if any.
    ///
    /// KP-share locks are expected to expire, so this authenticates the record
    /// without claiming S3 immutability.
    async fn read_latest_kp_share_state_log(
        &mut self,
        sharing_seq: u64,
    ) -> GuardianResult<Option<KpShareStateLogMessage>> {
        let prefix = KpShareStateLogMessage::object_key_dir(sharing_seq);
        let keys = self.s3.list_keys(&prefix, false).await?;
        let Some((_, key)) = latest_unique_versioned_session_key(keys, &prefix, Some(0))? else {
            return Ok(None);
        };
        let msg = self.read_kp_share_state_log_at_key(&key, false).await?;
        Ok(Some(msg))
    }

    /// Read and verify an exact encrypted KP-share state written by the current
    /// build.
    ///
    /// The object key binds the writing guardian session and the two sequence
    /// numbers. This lets callers verify the snapshot produced by one request
    /// even if a later request has already advanced the latest state.
    pub async fn read_kp_share_state_log_from_current_build(
        &mut self,
        session_id: &SessionID,
        sharing_seq: u64,
        cert_seq: u64,
    ) -> GuardianResult<KpShareStateLogMessage> {
        let key = KpShareStateLogMessage::object_key(session_id, sharing_seq, cert_seq);
        self.read_kp_share_state_log_at_key(&key, true).await
    }

    /// Read and verify one KP-share object under the requested build policy.
    async fn read_kp_share_state_log_at_key(
        &mut self,
        key: &str,
        require_current: bool,
    ) -> GuardianResult<KpShareStateLogMessage> {
        // KP-share locks are expected to expire, so authenticate the record
        // without claiming that S3 still makes it immutable.
        let record = self
            .s3
            .get_log_record_inner(key, ImmutabilityCheck::Skipped)
            .await?;
        let verified_record = self.verify_record(record).await?;
        if require_current {
            self.allowlist
                .require_current_build(verified_record.build_pcrs())?;
        }
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::KpShareState(msg)) => (*msg)
                .try_into()
                .map_err(|e| InvalidS3Log(format!("log schema conversion failed: {e}")))?,
            V2(LogMessageV2::KpShareState(msg)) => *msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a kp-shares log at {key}")));
            }
        };
        log_verified_read(key, &session_id);
        Ok(msg)
    }

    /// Read one current-build ceremony by session and sequence.
    pub async fn read_pending_ceremony_state_from_current_build(
        &mut self,
        session_id: &SessionID,
        sharing_seq: u64,
    ) -> GuardianResult<CeremonyState> {
        let ceremony_key = format!(
            "{}{sharing_seq:020}-{session_id}.json",
            CeremonyLogMessage::object_key_dir()
        );
        let ceremony = self.read_ceremony_log_at_key(&ceremony_key, true).await?;

        let kp_share_state = self
            .read_kp_share_state_log_from_current_build(session_id, sharing_seq, 0)
            .await?;
        CeremonyState::new(ceremony, kp_share_state)
    }

    /// Read the latest ceremony authorized by a completion marker.
    pub async fn read_latest_ceremony_state(&mut self) -> GuardianResult<CeremonyState> {
        let (completion, session_id) = self
            .read_latest_ceremony_completion()
            .await?
            .ok_or_else(|| InvalidInputs("no ceremony found".into()))?;
        let sharing_seq = completion.sharing_seq;
        let ceremony_key = format!(
            "{}{sharing_seq:020}-{session_id}.json",
            CeremonyLogMessage::object_key_dir()
        );
        let ceremony = self.read_ceremony_log_at_key(&ceremony_key, false).await?;
        let initial_key = KpShareStateLogMessage::object_key(&session_id, sharing_seq, 0);
        let initial_kp_share_state = self
            .read_kp_share_state_log_at_key(&initial_key, false)
            .await?;

        let latest_kp_share_state = self.read_latest_kp_share_state_log(sharing_seq).await?;
        ceremony_state_from_completion(
            &completion,
            ceremony,
            initial_kp_share_state,
            latest_kp_share_state,
        )
    }

    /// Read the latest serving committee.
    ///
    /// Prefer the latest successful `committee-update/` record, then fall back
    /// to the KP-authorized `genesis/record.json` bootstrap record. Return
    /// `None` if neither source exists.
    pub async fn read_latest_committee(&mut self) -> GuardianResult<Option<Committee>> {
        if let Some(committee) = self.read_latest_committee_update().await? {
            return Ok(Some(committee));
        }
        Ok(self
            .read_genesis_log()
            .await?
            .map(|genesis| genesis.committee))
    }

    /// Read and verify the successfully applied committee with the highest
    /// epoch, or return `None` if no successful update exists.
    ///
    /// Success keys begin with a zero-padded epoch, so the lexicographically
    /// greatest non-failure key identifies the latest applied committee.
    async fn read_latest_committee_update(&mut self) -> GuardianResult<Option<Committee>> {
        let keys = self
            .s3
            .list_keys(&CommitteeUpdateLogMessage::object_key_dir(), true)
            .await?;
        let Some(key) = keys
            .into_iter()
            .filter(|key| !CommitteeUpdateLogMessage::is_failure_object_key(key))
            .max()
        else {
            return Ok(None);
        };
        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::CommitteeUpdate(msg)) | V2(LogMessageV2::CommitteeUpdate(msg)) => msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!(
                    "expected a committee-update log at {key}"
                )));
            }
        };
        let committee = match *msg {
            CommitteeUpdateLogMessage::Success { new_committee, .. } => new_committee,
            CommitteeUpdateLogMessage::Failure { .. } => {
                unreachable!("a verified non-failure key cannot contain a Failure log")
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(committee))
    }

    /// Read and verify the fixed KP-authorized bootstrap record, or return
    /// `None` if `genesis/record.json` has not been written.
    async fn read_genesis_log(&mut self) -> GuardianResult<Option<GenesisLogMessage>> {
        let key = GenesisLogMessage::object_key();
        let keys = self
            .s3
            .list_keys(&GenesisLogMessage::object_key_dir(), true)
            .await?;
        if keys.is_empty() {
            return Ok(None);
        }
        if keys != [key.clone()] {
            return Err(InvalidS3Log(format!(
                "expected exactly one genesis record at {key}, found {keys:?}"
            )));
        }
        let verified_record = self.read_verified_record(&key).await?;
        let session_id = verified_record.entry().session_id().clone();
        let msg = match verified_record.into_entry().into_message() {
            V1(LogMessageV1::Genesis(msg)) | V2(LogMessageV2::Genesis(msg)) => msg,
            V1(_) | V2(_) => {
                return Err(InvalidS3Log(format!("expected a genesis log at {key}")));
            }
        };
        log_verified_read(&key, &session_id);
        Ok(Some(*msg))
    }
}

fn ceremony_state_from_completion(
    completion: &CeremonyCompletionLogMessage,
    ceremony: CeremonyLogMessage,
    initial_kp_share_state: KpShareStateLogMessage,
    latest_kp_share_state: Option<KpShareStateLogMessage>,
) -> GuardianResult<CeremonyState> {
    let initial_state = CeremonyState::new(ceremony.clone(), initial_kp_share_state)?;
    if initial_state.digest() != completion.ceremony_digest {
        return Err(InvalidS3Log("ceremony completion digest mismatch".into()));
    }
    match latest_kp_share_state {
        Some(state) => CeremonyState::new(ceremony, state),
        None => Ok(initial_state),
    }
}

fn versioned_session_key_seq(key: &str, prefix: &str) -> GuardianResult<u64> {
    let malformed = || InvalidS3Log(format!("non-canonical key {key} under {prefix}"));
    let (sequence, session_id) = key
        .strip_prefix(prefix)
        .and_then(|key| key.strip_suffix(".json"))
        .and_then(|key| key.split_once('-'))
        .ok_or_else(&malformed)?;
    if sequence.len() != 20
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || session_id.len() != SessionID::HEX_LEN
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(malformed());
    }
    sequence.parse().map_err(|_| malformed())
}

fn latest_unique_versioned_session_key(
    keys: Vec<String>,
    prefix: &str,
    minimum_exclusive: Option<u64>,
) -> GuardianResult<Option<(u64, String)>> {
    let mut latest = None;
    let mut ambiguous = false;
    for key in keys {
        let sequence = versioned_session_key_seq(&key, prefix)?;
        if minimum_exclusive.is_some_and(|minimum| sequence <= minimum) {
            continue;
        }
        match latest {
            None => latest = Some((sequence, key)),
            Some((current, _)) if sequence > current => {
                latest = Some((sequence, key));
                ambiguous = false;
            }
            Some((current, _)) if sequence == current => ambiguous = true,
            Some(_) => {}
        }
    }
    if ambiguous {
        return Err(InvalidS3Log(format!(
            "multiple records found for sequence {} under {prefix}",
            latest.as_ref().expect("ambiguous sequence exists").0
        )));
    }
    Ok(latest)
}

fn log_verified_read(key: &str, session_id: &SessionID) {
    info!("Successfully read {key} from session {session_id}.");
}
#[cfg(test)]
mod tests {
    use super::ceremony_state_from_completion;
    use super::latest_unique_versioned_session_key;
    use super::versioned_session_key_seq;
    use hashi_types::guardian::CeremonyCompletionLogMessage;
    use hashi_types::guardian::CeremonyLogMessage;
    use hashi_types::guardian::CeremonyState;
    use hashi_types::guardian::KpShareStateLogMessage;
    use hashi_types::guardian::SetupNewKeyResponse;

    #[test]
    fn completion_pins_initial_state_but_returns_latest_cert_snapshot() {
        let response = SetupNewKeyResponse::mock_for_testing();
        let initial_state = CeremonyState::from(response.clone());
        let sharing_seq = response.secret_sharing_instance.sharing_seq();
        let ceremony = CeremonyLogMessage::NewKey {
            instance: response.secret_sharing_instance,
            btc_master_pubkey: response.btc_master_pubkey,
        };
        let initial =
            KpShareStateLogMessage::new(sharing_seq, 0, response.encrypted_shares.clone());
        let latest = KpShareStateLogMessage::new(sharing_seq, 1, response.encrypted_shares);

        assert!(ceremony_state_from_completion(
            &CeremonyCompletionLogMessage::new(sharing_seq, [0; 32]),
            ceremony.clone(),
            initial.clone(),
            Some(latest.clone()),
        )
        .is_err());
        let state = ceremony_state_from_completion(
            &CeremonyCompletionLogMessage::new(sharing_seq, initial_state.digest()),
            ceremony,
            initial,
            Some(latest),
        )
        .unwrap();
        assert_eq!(state.cert_seq, 1);
    }

    #[test]
    fn completion_keys_are_canonical_and_unambiguous() {
        let prefix = "ceremony-complete/";
        for malformed in [
            "ceremony-complete/1-0123456789abcdef.json",
            "ceremony-complete/00000000000000000001-0123456789ABCDEF.json",
        ] {
            assert!(versioned_session_key_seq(malformed, prefix).is_err());
        }
        assert!(latest_unique_versioned_session_key(
            vec![
                "ceremony-complete/00000000000000000001-0123456789abcdef.json".into(),
                "ceremony-complete/00000000000000000001-fedcba9876543210.json".into(),
            ],
            prefix,
            None,
        )
        .is_err());

        let prefix = "kp-shares/00000000000000000007/";
        let latest = format!("{prefix}00000000000000000001-2222222222222222.json");
        assert_eq!(
            latest_unique_versioned_session_key(
                vec![
                    format!("{prefix}00000000000000000000-0000000000000000.json"),
                    format!("{prefix}00000000000000000000-1111111111111111.json"),
                    latest.clone(),
                ],
                prefix,
                Some(0),
            )
            .unwrap(),
            Some((1, latest))
        );
    }
}
