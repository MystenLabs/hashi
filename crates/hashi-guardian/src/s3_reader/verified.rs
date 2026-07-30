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
use hashi_types::guardian::VersionedLogMessage;

/// A session's verified guardian info: the attestation-anchored signing key,
/// the signed [`GuardianInfo`], and the build PCRs proven by attestation.
#[derive(Debug, Clone)]
pub struct VerifiedSessionInfo {
    signing_pubkey: GuardianPubKey,
    info: GuardianInfo,
    build_pcrs: BuildPcrs,
}

impl VerifiedSessionInfo {
    pub(super) async fn new(
        s3: &GuardianS3Client,
        session_id: &str,
        allowlist: &PcrAllowlist,
    ) -> GuardianResult<Self> {
        // 1. Attestation (unsigned: authenticated by AWS, not the enclave key) →
        //    the signing pubkey it commits to.
        let att_key = InitLogMessage::attestation_object_key(session_id);
        let attestation_record = s3.get_log_record(&att_key).await?;
        attestation_record.validate(None)?;
        let attestation_message = match into_validated_entry(attestation_record).into_message() {
            VersionedLogMessage::V1(LogMessageV1::Init(message)) => message,
            VersionedLogMessage::V2(LogMessageV2::Init(message)) => message,
            VersionedLogMessage::V1(_) | VersionedLogMessage::V2(_) => {
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
        info_record.validate(Some(&signing_pubkey))?;
        let info_message = match into_validated_entry(info_record).into_message() {
            VersionedLogMessage::V1(LogMessageV1::Init(message)) => message,
            VersionedLogMessage::V2(LogMessageV2::Init(message)) => message,
            VersionedLogMessage::V1(_) | VersionedLogMessage::V2(_) => {
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

    pub fn signing_pubkey(&self) -> &GuardianPubKey {
        &self.signing_pubkey
    }

    pub fn info(&self) -> &GuardianInfo {
        &self.info
    }

    pub fn build_pcrs(&self) -> &BuildPcrs {
        &self.build_pcrs
    }

    pub fn into_info(self) -> GuardianInfo {
        self.info
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
    pub(super) fn new(
        record: LogRecord,
        session_info: &VerifiedSessionInfo,
    ) -> GuardianResult<Self> {
        record.validate(Some(&session_info.signing_pubkey))?;
        let entry = into_validated_entry(record);
        Ok(Self {
            entry,
            build_pcrs: session_info.build_pcrs.clone(),
        })
    }

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

fn into_validated_entry(record: LogRecord) -> LogEntry {
    match record {
        LogRecord::Signed(signed) => signed.into_data_unchecked(),
        LogRecord::Unsigned(entry) => entry,
    }
}
