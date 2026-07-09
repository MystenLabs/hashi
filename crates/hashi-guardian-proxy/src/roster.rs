// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The relay's KP roster, read from the guardian's S3 share log. A ceremony
//! commits who holds shares — every encrypted share is labeled with its
//! recipient's PGP fingerprint — so the latest share log IS the authorization
//! roster: exactly the set that can produce a share worth relaying. The read is
//! deliberately unverified (no enclave-signature check): the bucket only admits
//! enclave writes, and this gate is DoS-tier — the enclave still verifies every
//! share cryptographically (config_hash AAD + commitments).
//!
//! Two layouts are in flight (#779 migrates the first to the second):
//!   `shares/{sharing_seq:020}-{session}.json` (message `Shares`)
//!   `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session}.json` (`KpShareState`)
//! The reader prefers `kp-shares/` and falls back to `shares/`, parsing a local
//! tolerant shape rather than the hashi-types enum, so the proxy keeps working
//! on either side of that migration and on buckets whose ceremony predates it.

use anyhow::Context as _;
use hashi_types::pgp::Fingerprint;
use serde::Deserialize;

use crate::widlog::LogStore;

const LEGACY_SHARES_PREFIX: &str = "shares/";
const KP_SHARES_PREFIX: &str = "kp-shares/";

/// Recipient fingerprints of the latest committed share set. `Ok(None)` means
/// no share log exists anywhere (no ceremony yet) — a definitive miss; any
/// `Err` is indeterminate and the caller must fail closed.
pub async fn latest_kp_roster<L: LogStore>(log: &L) -> anyhow::Result<Option<Vec<Fingerprint>>> {
    let Some(key) = latest_share_log_key(log).await? else {
        return Ok(None);
    };
    let bytes = log.get(&key).await?;
    let roster = parse_roster(&bytes).with_context(|| format!("parse share log {key}"))?;
    Ok(Some(roster))
}

/// Key of the latest share-state record: the lex-greatest object under the
/// lex-greatest `kp-shares/` sharing-seq dir, else the lex-greatest flat
/// `shares/` key (zero-padded seqs make lex order the seq order).
async fn latest_share_log_key<L: LogStore>(log: &L) -> anyhow::Result<Option<String>> {
    if let Some(dir) = log.list_dirs(KP_SHARES_PREFIX).await?.into_iter().max() {
        let key = log
            .list_keys(&dir)
            .await?
            .into_iter()
            .max()
            .with_context(|| format!("share dir {dir} listed but has no keys"))?;
        return Ok(Some(key));
    }
    Ok(log.list_keys(LEGACY_SHARES_PREFIX).await?.into_iter().max())
}

/// Just the fields the roster needs, tolerant of everything else. Any record
/// under a share prefix carries one of these two message shapes; anything else
/// is a poisoned log and fails closed upstream.
#[derive(Deserialize)]
struct ShareLogRecord {
    message: ShareLogMessage,
}

#[derive(Deserialize)]
enum ShareLogMessage {
    Shares(ShareState),
    KpShareState(ShareState),
}

#[derive(Deserialize)]
struct ShareState {
    encrypted_shares: Vec<LabeledShare>,
}

#[derive(Deserialize)]
struct LabeledShare {
    recipient_fingerprint: String,
}

fn parse_roster(bytes: &[u8]) -> anyhow::Result<Vec<Fingerprint>> {
    let record: ShareLogRecord = serde_json::from_slice(bytes)?;
    let (ShareLogMessage::Shares(state) | ShareLogMessage::KpShareState(state)) = record.message;
    state
        .encrypted_shares
        .iter()
        .map(|share| parse_recipient_fingerprint(&share.recipient_fingerprint))
        .collect()
}

fn parse_recipient_fingerprint(label: &str) -> anyhow::Result<Fingerprint> {
    label
        .parse::<Fingerprint>()
        .ok()
        // Sequoia parses odd-sized hex into `Fingerprint::Unknown` rather than
        // failing; only real v4/v6 shapes can name a KP cert.
        .filter(|fp| matches!(fp, Fingerprint::V4(_) | Fingerprint::V6(_)))
        .with_context(|| format!("share label {label:?} is not a PGP fingerprint"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widlog::test_store::MemStore;
    use hashi_types::guardian::GuardianSignKeyPair;
    use hashi_types::guardian::KPEncryptedShare;
    use hashi_types::guardian::KPEncryptedShares;
    use hashi_types::guardian::LogMessage;
    use hashi_types::guardian::LogRecord;
    use hashi_types::guardian::ShareID;
    use hashi_types::guardian::SharesLogMessage;

    const FP_A: &str = "AAAABBBBCCCCDDDDEEEE11112222333344445555";
    const FP_B: &str = "AAAABBBBCCCCDDDDEEEE1111222233334444FFFF";

    fn fp(hex: &str) -> Fingerprint {
        hex.parse().unwrap()
    }

    /// A genuine legacy `shares/` record, serialized exactly as the enclave
    /// writes it today, keyed by `LogRecord::object_key()`.
    fn legacy_shares_record(sharing_seq: u64, fingerprints: &[&str]) -> (String, Vec<u8>) {
        let shares = fingerprints
            .iter()
            .enumerate()
            .map(|(i, fp)| KPEncryptedShare {
                id: ShareID::new((i + 1) as u16).unwrap(),
                recipient_fingerprint: fp.to_string(),
                armored_ciphertext: String::new(),
            })
            .collect();
        let record = LogRecord::new(
            "test-session".to_string(),
            LogMessage::Shares(Box::new(SharesLogMessage {
                sharing_seq,
                encrypted_shares: KPEncryptedShares::new(shares).unwrap(),
            })),
            &GuardianSignKeyPair::from([7u8; 32]),
        );
        (record.object_key(), serde_json::to_vec(&record).unwrap())
    }

    /// A `kp-shares/` record in #779's shape (not yet constructible via
    /// hashi-types on main, so hand-rolled at the JSON layer the parser sees).
    fn kp_shares_record(
        sharing_seq: u64,
        cert_seq: u64,
        fingerprints: &[&str],
    ) -> (String, Vec<u8>) {
        let shares: Vec<serde_json::Value> = fingerprints
            .iter()
            .enumerate()
            .map(|(i, fp)| {
                serde_json::json!({
                    "id": i + 1,
                    "recipient_fingerprint": fp,
                    "armored_ciphertext": "",
                })
            })
            .collect();
        let record = serde_json::json!({
            "session_id": "test-session",
            "timestamp_ms": 0,
            "message": { "KpShareState": {
                "sharing_seq": sharing_seq,
                "cert_seq": cert_seq,
                "encrypted_shares": shares,
            }},
            "signature": null,
        });
        let key = format!("kp-shares/{sharing_seq:020}/{cert_seq:020}-test-session.json");
        (key, serde_json::to_vec(&record).unwrap())
    }

    #[tokio::test]
    async fn reads_the_legacy_shares_layout() {
        let store = MemStore::default();
        let (key, bytes) = legacy_shares_record(0, &[FP_A, FP_B]);
        store.insert(key, bytes);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_A), fp(FP_B)]);
    }

    #[tokio::test]
    async fn latest_sharing_seq_wins_in_the_legacy_layout() {
        let store = MemStore::default();
        let (key0, bytes0) = legacy_shares_record(0, &[FP_A]);
        let (key1, bytes1) = legacy_shares_record(1, &[FP_B]);
        store.insert(key0, bytes0);
        store.insert(key1, bytes1);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_B)]);
    }

    #[tokio::test]
    async fn kp_shares_layout_is_preferred_over_legacy() {
        let store = MemStore::default();
        let (legacy_key, legacy_bytes) = legacy_shares_record(0, &[FP_A]);
        let (key, bytes) = kp_shares_record(0, 0, &[FP_B]);
        store.insert(legacy_key, legacy_bytes);
        store.insert(key, bytes);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_B)]);
    }

    #[tokio::test]
    async fn latest_cert_seq_wins_within_a_sharing_seq() {
        let store = MemStore::default();
        let (key0, bytes0) = kp_shares_record(3, 0, &[FP_A]);
        let (key1, bytes1) = kp_shares_record(3, 1, &[FP_B]);
        // An older sharing seq must lose to the newer dir regardless of cert_seq.
        let (key_old, bytes_old) = kp_shares_record(2, 9, &[FP_A]);
        store.insert(key0, bytes0);
        store.insert(key1, bytes1);
        store.insert(key_old, bytes_old);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_B)]);
    }

    #[tokio::test]
    async fn no_share_log_is_a_definitive_none() {
        let store = MemStore::default();
        assert!(latest_kp_roster(&store).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        let (key, bytes) = legacy_shares_record(0, &[FP_A]);
        store.insert(key, bytes);
        store
            .fail_lists
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn unparseable_latest_record_fails_closed() {
        // Unlike the wid scan (where a skip degrades to a re-sign), silently
        // falling back past a garbled newest record could authorize a
        // rotated-out roster — so a parse failure is an error.
        let store = MemStore::default();
        let (key, _) = legacy_shares_record(0, &[FP_A]);
        store.insert(key, b"not json".to_vec());

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn bad_fingerprint_label_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = legacy_shares_record(0, &["ABCD"]);
        store.insert(key, bytes);

        assert!(latest_kp_roster(&store).await.is_err());
    }
}
