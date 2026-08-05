// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Offline verification of a downloaded guardian S3 bucket.
//!
//! Diagnostic harness: proves whether records written by an older guardian
//! build still parse and signature-verify under the current reader, with no
//! network and no S3 object-lock involvement.
//!
//! `OFFLINE_BUCKET_DIR=/path/to/bucket cargo nextest run -p hashi-types \
//!   --run-ignored all offline_bucket`

use hashi_types::guardian::GuardianPubKey;
use hashi_types::guardian::InitLogMessage;
use hashi_types::guardian::LogMessageV1;
use hashi_types::guardian::LogMessageV2;
use hashi_types::guardian::LogRecord;
use hashi_types::guardian::VersionedLogMessage;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;

fn json_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn read_record(path: &Path) -> LogRecord {
    let bytes = std::fs::read(path).expect("readable file");
    serde_json::from_slice::<LogRecord>(&bytes)
        .unwrap_or_else(|e| panic!("{} failed to deserialize: {e}", path.display()))
}

/// Both schema versions carry the same `InitLogMessage`, and a bucket written
/// across an upgrade holds both.
fn as_init(message: &VersionedLogMessage) -> Option<&InitLogMessage> {
    match message {
        VersionedLogMessage::V1(LogMessageV1::Init(init)) => Some(init),
        VersionedLogMessage::V2(LogMessageV2::Init(init)) => Some(init),
        _ => None,
    }
}

fn message_kind(message: &VersionedLogMessage) -> &'static str {
    macro_rules! kind {
        ($m:expr, $v:ident) => {
            match $m {
                $v::Heartbeat(..) => "Heartbeat",
                $v::Init(..) => "Init",
                $v::Withdrawal(..) => "Withdrawal",
                $v::Ceremony(..) => "Ceremony",
                $v::KpShareState(..) => "KpShareState",
                $v::CommitteeUpdate(..) => "CommitteeUpdate",
                $v::Genesis(..) => "Genesis",
            }
        };
    }
    match message {
        VersionedLogMessage::V1(m) => kind!(m, LogMessageV1),
        VersionedLogMessage::V2(m) => kind!(m, LogMessageV2),
    }
}

#[test]
#[ignore = "requires OFFLINE_BUCKET_DIR pointing at a downloaded bucket"]
fn downloaded_bucket_records_parse_and_verify() {
    let root = PathBuf::from(
        std::env::var("OFFLINE_BUCKET_DIR").expect("set OFFLINE_BUCKET_DIR to the bucket copy"),
    );
    let files = json_files(&root);
    assert!(
        !files.is_empty(),
        "no .json records under {}",
        root.display()
    );

    // Pass 1: the unsigned OI attestations anchor each session's signing key.
    // These are authenticated by AWS (Nitro), not by the enclave key, so they
    // validate with `None`.
    let mut session_keys: BTreeMap<String, GuardianPubKey> = BTreeMap::new();
    for path in &files {
        let record = read_record(path);
        if !matches!(record, LogRecord::Unsigned(_)) {
            continue;
        }
        let session_id = record.session_id().as_str().to_owned();
        record
            .validate(None)
            .unwrap_or_else(|e| panic!("{} failed unsigned validation: {e}", path.display()));
        let Some(InitLogMessage::OIAttestationUnsigned {
            signing_public_key, ..
        }) = as_init(record.message())
        else {
            panic!("{}: expected OIAttestationUnsigned", path.display());
        };
        println!("ANCHOR  {} -> session {session_id}", path.display());
        session_keys.insert(session_id, *signing_public_key);
    }
    assert!(!session_keys.is_empty(), "no OI attestation found");

    // Pass 2: every signed record must verify under its own session's key.
    let mut verified = 0usize;
    for path in &files {
        let record = read_record(path);
        if matches!(record, LogRecord::Unsigned(_)) {
            continue;
        }
        let session_id = record.session_id().as_str().to_owned();
        let key = session_keys
            .get(&session_id)
            .unwrap_or_else(|| panic!("{}: no anchor for session {session_id}", path.display()));
        record
            .validate(Some(key))
            .unwrap_or_else(|e| panic!("{} FAILED verification: {e}", path.display()));
        println!(
            "VERIFY  {:<14} {}",
            message_kind(record.message()),
            path.display()
        );
        verified += 1;
    }
    println!(
        "\n{verified} signed record(s) verified, {} session anchor(s)",
        session_keys.len()
    );
}
