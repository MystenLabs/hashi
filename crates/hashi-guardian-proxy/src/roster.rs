// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The relay's KP roster, read from the guardian's S3 share log. A ceremony
//! commits who holds shares — every encrypted share is labeled with its
//! recipient's PGP fingerprint — so the latest share log IS the authorization
//! roster. The read is deliberately unverified: the bucket only admits enclave
//! writes and this gate is DoS-tier, with the enclave still verifying every
//! share cryptographically (config_hash AAD + commitments).
//!
//! `ceremony-complete/` selects the active `kp-shares/{sharing_seq:020}/`
//! directory; unmarked ceremony records and orphan share directories are ignored.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as _;
use hashi_types::guardian::log::CeremonyCompletionLogMessage;
use hashi_types::guardian::log::KpShareStateLogMessage;
use hashi_types::pgp::Fingerprint;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::widlog::LogStore;

/// The committed roster only changes at a ceremony, a re-deal, or a cert
/// rotation — and rotation invalidates explicitly — so a minute of staleness
/// costs nothing and bounds S3 reads under submission spam.
const ROSTER_TTL: Duration = Duration::from_secs(60);
/// "No ceremony yet" is cached far more briefly: the first ceremony should be
/// authorized promptly once its log lands, but an unauthenticated caller must
/// not be able to drive an S3 read per request while we wait.
const MISSING_ROSTER_TTL: Duration = Duration::from_secs(5);

struct Cached {
    at: Instant,
    roster: Option<Arc<Vec<Fingerprint>>>,
}

/// TTL-cached view of [`latest_kp_roster`]. The mutex is held across the fetch,
/// so concurrent misses collapse into one S3 read.
pub struct RosterCache<L> {
    store: L,
    cached: Mutex<Option<Cached>>,
}

impl<L: LogStore> RosterCache<L> {
    pub fn new(store: L) -> Self {
        Self {
            store,
            cached: Mutex::new(None),
        }
    }

    /// `Ok(None)` means no ceremony has committed a share set yet.
    pub async fn get(&self) -> anyhow::Result<Option<Arc<Vec<Fingerprint>>>> {
        let mut cached = self.cached.lock().await;
        if let Some(entry) = cached.as_ref() {
            let ttl = if entry.roster.is_some() {
                ROSTER_TTL
            } else {
                MISSING_ROSTER_TTL
            };
            if entry.at.elapsed() < ttl {
                return Ok(entry.roster.clone());
            }
        }
        let roster = latest_kp_roster(&self.store).await?.map(Arc::new);
        *cached = Some(Cached {
            at: Instant::now(),
            roster: roster.clone(),
        });
        Ok(roster)
    }

    /// Drop the cached roster so the next read observes a just-committed change.
    pub async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

/// Recipient fingerprints of the latest committed share set. `Ok(None)` means
/// no ceremony has completed yet; any `Err` is indeterminate and fails closed.
pub async fn latest_kp_roster<L: LogStore>(log: &L) -> anyhow::Result<Option<Vec<Fingerprint>>> {
    let Some(key) = latest_share_log_key(log).await? else {
        return Ok(None);
    };
    let bytes = log.get(&key).await?;
    parse_roster(&bytes)
        .map(Some)
        .with_context(|| format!("parse share log {key}"))
}

async fn latest_share_log_key<L: LogStore>(log: &L) -> anyhow::Result<Option<String>> {
    let completion_prefix = CeremonyCompletionLogMessage::object_key_dir();
    let completion_keys = log.list_keys(&completion_prefix).await?;
    let Some((sharing_seq, completion_key)) = latest_unique_key(&completion_keys, |key| {
        key_parts(key, &completion_prefix, "ceremony completion").map(|(seq, _)| Some(seq))
    })?
    else {
        return Ok(None);
    };
    let (_, session_id) = key_parts(&completion_key, &completion_prefix, "ceremony completion")?;

    let share_prefix = KpShareStateLogMessage::object_key_dir(sharing_seq);
    let share_keys = log.list_keys(&share_prefix).await?;
    if let Some((_, key)) = latest_unique_key(&share_keys, |key| {
        key_parts(key, &share_prefix, "kp-shares")
            .map(|(cert_seq, _)| (cert_seq > 0).then_some(cert_seq))
    })? {
        return Ok(Some(key));
    }

    let key = KpShareStateLogMessage::object_key(session_id, sharing_seq, 0);
    anyhow::ensure!(
        share_keys.contains(&key),
        "ceremony {completion_key} has no kp-shares log"
    );
    Ok(Some(key))
}

fn latest_unique_key(
    keys: &[String],
    sequence: impl Fn(&str) -> anyhow::Result<Option<u64>>,
) -> anyhow::Result<Option<(u64, String)>> {
    let mut latest = None;
    let mut ambiguous = false;
    for key in keys {
        let Some(sequence) = sequence(key)? else {
            continue;
        };
        match latest {
            None => latest = Some((sequence, key.clone())),
            Some((current, _)) if sequence > current => {
                latest = Some((sequence, key.clone()));
                ambiguous = false;
            }
            Some((current, _)) if sequence == current => ambiguous = true,
            Some(_) => {}
        }
    }
    anyhow::ensure!(!ambiguous, "multiple records claim the latest sequence");
    Ok(latest)
}

fn key_parts<'a>(key: &'a str, prefix: &str, kind: &str) -> anyhow::Result<(u64, &'a str)> {
    let malformed = || anyhow::anyhow!("malformed {kind} key {key:?}");
    let (sequence, session_id) = key
        .strip_prefix(prefix)
        .and_then(|name| name.strip_suffix(".json"))
        .and_then(|name| name.split_once('-'))
        .ok_or_else(malformed)?;
    anyhow::ensure!(
        sequence.len() == 20
            && sequence.bytes().all(|byte| byte.is_ascii_digit())
            && !session_id.is_empty()
            && !session_id.contains('/'),
        malformed()
    );
    Ok((
        sequence
            .parse()
            .with_context(|| format!("{kind} key {key:?} has an out-of-range sequence"))?,
        session_id,
    ))
}

/// Just the fields the roster needs, tolerant of everything else.
#[derive(Deserialize)]
struct ShareLogRecord {
    message: ShareLogMessage,
}

#[derive(Deserialize)]
enum ShareLogMessage {
    KpShareState(ShareState),
}

#[derive(Deserialize)]
struct ShareState {
    encrypted_shares: Vec<LabeledShare>,
}

/// A share names its recipient in one of two shapes, and both are live: the
/// guardian deployed on testnet writes `schema_version: 1` records carrying a
/// single `recipient_fingerprint`, while current builds write
/// `schema_version: 2` with `ciphertexts_by_fingerprint`, one entry per cert
/// since a KP may hold several. A rotation reads the old record before it
/// writes the new one, so the relay has to accept either.
#[derive(Deserialize)]
#[serde(untagged)]
enum LabeledShare {
    MultiCert {
        ciphertexts_by_fingerprint: BTreeMap<String, serde_json::Value>,
    },
    SingleCert {
        recipient_fingerprint: String,
    },
}

impl LabeledShare {
    /// Every fingerprint naming this share's holder. More than one only in the
    /// multi-cert shape, where they are all the same KP.
    fn fingerprints(&self) -> Vec<&str> {
        match self {
            Self::MultiCert {
                ciphertexts_by_fingerprint,
            } => ciphertexts_by_fingerprint
                .keys()
                .map(String::as_str)
                .collect(),
            Self::SingleCert {
                recipient_fingerprint,
            } => vec![recipient_fingerprint.as_str()],
        }
    }
}

fn parse_roster(bytes: &[u8]) -> anyhow::Result<Vec<Fingerprint>> {
    let record: ShareLogRecord = serde_json::from_slice(bytes)?;
    let ShareLogMessage::KpShareState(state) = record.message;
    state
        .encrypted_shares
        .iter()
        .flat_map(|share| share.fingerprints())
        .map(parse_recipient_fingerprint)
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
    use std::sync::atomic::Ordering;

    const FP_A: &str = "AAAABBBBCCCCDDDDEEEE11112222333344445555";
    const FP_B: &str = "AAAABBBBCCCCDDDDEEEE1111222233334444FFFF";

    fn fp(hex: &str) -> Fingerprint {
        hex.parse().unwrap()
    }

    /// `schema_version: 1` shares — one cert each, named by a scalar. This is
    /// what the guardian currently deployed on testnet writes, so a rotation
    /// reads this shape before it writes anything.
    fn single_cert_shares(fingerprints: &[&str]) -> Vec<serde_json::Value> {
        fingerprints
            .iter()
            .enumerate()
            .map(|(i, fp)| {
                serde_json::json!({
                    "id": i + 1,
                    "recipient_fingerprint": fp,
                    "armored_ciphertext": "",
                })
            })
            .collect()
    }

    /// `schema_version: 2` shares — a map, because one KP may hold several
    /// certs. This is what current builds write.
    fn multi_cert_shares(per_share: &[&[&str]]) -> Vec<serde_json::Value> {
        per_share
            .iter()
            .enumerate()
            .map(|(i, fps)| {
                let ciphertexts: serde_json::Map<String, serde_json::Value> = fps
                    .iter()
                    .map(|fp| ((*fp).to_string(), serde_json::json!("")))
                    .collect();
                serde_json::json!({
                    "id": i + 1,
                    "ciphertexts_by_fingerprint": ciphertexts,
                })
            })
            .collect()
    }

    /// Mark `sharing_seq` as complete.
    fn complete_ceremony(store: &MemStore, sharing_seq: u64) {
        complete_ceremony_for_session(store, sharing_seq, "test-session");
    }

    fn complete_ceremony_for_session(store: &MemStore, sharing_seq: u64, session_id: &str) {
        store.insert(
            CeremonyCompletionLogMessage::object_key(session_id, sharing_seq),
            b"{}".to_vec(),
        );
    }

    /// A current `kp-shares/` record. One cert per share; construct a custom
    /// record directly for a KP holding several.
    fn kp_shares_record(
        sharing_seq: u64,
        cert_seq: u64,
        fingerprints: &[&str],
    ) -> (String, Vec<u8>) {
        let per_share: Vec<&[&str]> = fingerprints.iter().map(std::slice::from_ref).collect();
        let shares = multi_cert_shares(&per_share);
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
    async fn marker_session_and_cert_seq_select_the_roster() {
        let store = MemStore::default();
        let (initial_key, initial_bytes) = kp_shares_record(3, 0, &[FP_A]);
        let (abandoned_key, abandoned_bytes) = kp_shares_record(3, 0, &[FP_B]);
        store.insert(initial_key, initial_bytes);
        store.insert(
            abandoned_key.replace("test-session", "other-session"),
            abandoned_bytes,
        );
        complete_ceremony(&store, 3);
        assert_eq!(
            latest_kp_roster(&store).await.unwrap().unwrap(),
            vec![fp(FP_A)]
        );

        let (latest_key, latest_bytes) = kp_shares_record(3, 1, &[FP_B]);
        store.insert(latest_key.clone(), latest_bytes.clone());
        assert_eq!(
            latest_kp_roster(&store).await.unwrap().unwrap(),
            vec![fp(FP_B)]
        );

        store.insert(
            latest_key.replace("test-session", "other-session"),
            latest_bytes,
        );
        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn an_aborted_ceremony_does_not_move_the_roster() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);

        let (pending_key, pending_bytes) = kp_shares_record(1, 0, &[FP_B]);
        store.insert(pending_key, pending_bytes);

        assert_eq!(
            latest_kp_roster(&store).await.unwrap().unwrap(),
            vec![fp(FP_A)]
        );
    }

    #[tokio::test]
    async fn malformed_completion_key_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(5, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 5);
        store.insert(
            "ceremony-complete/6-test-session.json".to_string(),
            b"{}".to_vec(),
        );

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn duplicate_highest_sequence_completion_markers_fail_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(5, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony_for_session(&store, 5, "session-a");
        complete_ceremony_for_session(&store, 5, "session-b");

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn a_ceremony_without_its_shares_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        complete_ceremony(&store, 1);

        assert!(latest_kp_roster(&store).await.is_err());
    }

    /// The shape the guardian deployed on testnet writes: a `kp-shares/` record
    /// whose shares name one cert each via a scalar `recipient_fingerprint`
    /// (`schema_version: 1`). Fingerprints are the real gen-3 roster; the
    /// ciphertexts are elided because the roster read never decrypts.
    ///
    /// Regression: the relay parsed only one share shape, so against a real
    /// bucket it failed closed with "KP roster unavailable" and no KP could
    /// submit a share.
    #[tokio::test]
    async fn deployed_testnet_single_cert_shares_parse() {
        const DEPLOYED: &[&str] = &[
            "010AFFD5514AE454CA0D56DAA40FE24388998D2A",
            "69A798B4CD1FE3F7C827381BC56DF2575EC846C3",
            "8D798722C24B2A15C15036A1DEFA2C01C4350A31",
        ];
        let record = serde_json::json!({
            "schema_version": 1,
            "session_id": "916c711a5e81c2b0",
            "timestamp_ms": 1784219535816u64,
            "message": { "KpShareState": {
                "sharing_seq": 0,
                "cert_seq": 0,
                "encrypted_shares": single_cert_shares(DEPLOYED),
            }},
            "signature": null,
        });
        let store = MemStore::default();
        store.insert(
            "kp-shares/00000000000000000000/00000000000000000000-916c711a5e81c2b0.json".to_string(),
            serde_json::to_vec(&record).unwrap(),
        );
        complete_ceremony_for_session(&store, 0, "916c711a5e81c2b0");

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, DEPLOYED.iter().map(|f| fp(f)).collect::<Vec<_>>());
    }

    /// One KP holding several certs contributes every one of them: any of its
    /// certs can sign a submission that is still that single share holder.
    #[tokio::test]
    async fn multi_cert_share_contributes_every_fingerprint() {
        let store = MemStore::default();
        let shares = multi_cert_shares(&[&[FP_A, FP_B]]);
        let record = serde_json::json!({
            "schema_version": 2,
            "session_id": "test-session",
            "timestamp_ms": 0,
            "message": { "KpShareState": {
                "sharing_seq": 0,
                "cert_seq": 0,
                "encrypted_shares": shares,
            }},
            "signature": null,
        });
        store.insert(
            "kp-shares/00000000000000000000/00000000000000000000-test-session.json".to_string(),
            serde_json::to_vec(&record).unwrap(),
        );
        complete_ceremony(&store, 0);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_A), fp(FP_B)]);
    }

    #[tokio::test]
    async fn no_completion_marker_ignores_orphan_shares() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        assert!(latest_kp_roster(&store).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn store_failure_is_an_error_not_a_miss() {
        let store = MemStore::default();
        store
            .fail_lists
            .store(true, std::sync::atomic::Ordering::SeqCst);

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn unparseable_latest_record_fails_closed() {
        // Silently falling back past a garbled newest record could authorize a
        // rotated-out roster, so a parse failure is an error.
        let store = MemStore::default();
        let (key, _) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, b"not json".to_vec());
        complete_ceremony(&store, 0);

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn bad_fingerprint_label_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &["ABCD"]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn cache_reads_the_committed_roster() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);

        let roster = RosterCache::new(store).get().await.unwrap().unwrap();
        assert_eq!(*roster, vec![fp(FP_A)]);
    }

    #[tokio::test]
    async fn cache_serves_the_cached_roster_within_the_ttl() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        let cache = RosterCache::new(store);

        let first = cache.get().await.unwrap();
        // The store now fails hard; a fresh read would error, the cache must not.
        cache.store.fail_lists.store(true, Ordering::SeqCst);
        assert_eq!(first, cache.get().await.unwrap());
    }

    #[tokio::test]
    async fn cache_reports_a_missing_share_log_as_none() {
        assert!(RosterCache::new(MemStore::default())
            .get()
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn invalidate_makes_the_next_read_observe_a_rotated_cert() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        let cache = RosterCache::new(store);
        assert_eq!(*cache.get().await.unwrap().unwrap(), vec![fp(FP_A)]);

        // A cert rotation commits a higher cert_seq under the same sharing_seq.
        let (key, bytes) = kp_shares_record(0, 1, &[FP_B]);
        cache.store.insert(key, bytes);
        assert_eq!(
            *cache.get().await.unwrap().unwrap(),
            vec![fp(FP_A)],
            "still cached until invalidated"
        );

        cache.invalidate().await;
        assert_eq!(*cache.get().await.unwrap().unwrap(), vec![fp(FP_B)]);
    }
}
