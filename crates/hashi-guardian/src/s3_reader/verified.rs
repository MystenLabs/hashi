// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::s3_client::GuardianS3Client;
use hashi_types::guardian::BuildPcrs;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianInfo;
use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::GuardianResult;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogEntry;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::PcrAllowlist;
use hashi_types::guardian::VersionedLogMessage::V1;
use hashi_types::guardian::VersionedLogMessage::V2;

/// A session's verified guardian info: the attestation-anchored signing key,
/// the signed [`GuardianInfo`], and the build PCRs proven by attestation.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    signing_pubkey: GuardianPubKey,
    info: GuardianInfo,
    build_pcrs: BuildPcrs,
}

impl VerifiedSessionInfo {
    pub(super) async fn read_from_s3(
        s3: &GuardianS3Client,
        session_id: &str,
        allowlist: &PcrAllowlist,
    ) -> GuardianResult<Self> {
        // 1. Attestation (unsigned: authenticated by AWS, not the enclave key) →
        //    the signing pubkey it commits to.
        let att_key = InitLogMessage::attestation_object_key(session_id);
        let attestation_record = s3.get_log_record(&att_key).await?;
        let attestation_message =
            match validate_into_entry(attestation_record, None)?.into_message() {
                V1(LogMessageV1::Init(message)) | V2(LogMessageV2::Init(message)) => message,
                V1(_) | V2(_) => {
                    return Err(InvalidS3Log(format!(
                        "expected OIAttestationUnsigned at key {att_key}"
                    )));
                }
            };
        let InitLogMessage::OIAttestationUnsigned {
            attestation,
            signing_public_key: signing_pubkey,
        } = *attestation_message
        else {
            return Err(InvalidS3Log(format!(
                "expected OIAttestationUnsigned at key {att_key}"
            )));
        };

        // 2. GuardianInfo, signature-verified under that pubkey → the reported build.
        let info_key = InitLogMessage::guardian_info_object_key(session_id);
        let info_record = s3.get_log_record(&info_key).await?;
        let info_message =
            match validate_into_entry(info_record, Some(&signing_pubkey))?.into_message() {
                V1(LogMessageV1::Init(message)) | V2(LogMessageV2::Init(message)) => message,
                V1(_) | V2(_) => {
                    return Err(InvalidS3Log(format!(
                        "expected OIGuardianInfo at key {info_key}"
                    )));
                }
            };
        let InitLogMessage::OIGuardianInfo(info) = *info_message else {
            return Err(InvalidS3Log(format!(
                "expected OIGuardianInfo at key {info_key}"
            )));
        };
        let info = *info;

        // 3. Anchor the pubkey and pin PCR0 to the allowlist entry for the
        //    reported build. This replays a logged attestation whose short-lived
        //    leaf cert has typically expired, so the chain is checked at the
        //    document's own signed timestamp, not now.
        let build_pcrs = allowlist.resolve(&info.untrusted_git_revision)?.clone();
        attestation
            .verify_replay(&signing_pubkey, &build_pcrs)
            .map_err(|e| InvalidS3Log(format!("attestation at key {att_key}: {e}")))?;

        Ok(Self {
            signing_pubkey,
            info,
            build_pcrs,
        })
    }

    /// Verify a record with this session's attestation-anchored signing key.
    pub(super) fn verify_record(&self, record: LogRecord) -> GuardianResult<VerifiedLogRecord> {
        let entry = validate_into_entry(record, Some(&self.signing_pubkey))?;
        Ok(VerifiedLogRecord {
            entry,
            build_pcrs: self.build_pcrs.clone(),
        })
    }

    pub fn signing_pubkey(&self) -> &GuardianPubKey {
        &self.signing_pubkey
    }

    pub fn info(&self) -> &GuardianInfo {
        &self.info
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }
}

/// A log record whose message signature and writing session's attestation/PCRs
/// have both been verified. The exact versioned entry is retained so callers
/// can choose which schema versions they accept and how to interpret them.
#[derive(Debug)]
pub struct VerifiedLogRecord {
    entry: LogEntry,
    build_pcrs: BuildPcrs,
}

impl VerifiedLogRecord {
    #[cfg(test)]
    pub(super) fn new_for_test(entry: LogEntry, build_pcrs: BuildPcrs) -> Self {
        Self { entry, build_pcrs }
    }

    pub fn entry(&self) -> &LogEntry {
        &self.entry
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }

    pub fn into_entry(self) -> LogEntry {
        self.entry
    }
}

fn validate_into_entry(
    record: LogRecord,
    signing_public_key: Option<&GuardianPubKey>,
) -> GuardianResult<LogEntry> {
    record.validate(signing_public_key)?;
    Ok(record.into_entry_unchecked())
}
