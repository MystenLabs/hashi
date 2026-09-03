// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The proxy's KP roster, read from the guardian's S3 share log. A ceremony
//! commits who holds shares — every encrypted share is labeled with its
//! recipient's PGP fingerprint — so the latest share log IS the authorization
//! roster. The read is deliberately unverified: the bucket only admits enclave
//! writes and this gate is DoS-tier, with the enclave still verifying every
//! KP-signed request against its own roster.
//!
//! Two layouts are in flight (#779 migrates the first to the second):
//!   `shares/{sharing_seq:020}-{session}.json` (message `Shares`)
//!   `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session}.json` (`KpShareState`)
//! The reader prefers `kp-shares/`, parsing a local tolerant shape rather than
//! the hashi-types enum so it keeps working across that migration.
//!
//! Which `sharing_seq` is current comes from `ceremony/`, not from the newest
//! `kp-shares/` dir: a ceremony publishes its shares before its `ceremony/`
//! record, so an aborted one leaves an orphan dir that was never authorized.
//! This is the resolution the enclave performs
//! (`hashi-guardian::s3_reader::read_latest_ceremony_state`), and the relay has
//! to agree with it or it rejects the very KPs the enclave would accept.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use hashi_types::guardian::log::CeremonyLogMessage;
use hashi_types::guardian::log::KpShareStateLogMessage;
use hashi_types::pgp::Fingerprint;
use serde::Deserialize;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::Status;
use tracing::warn;

use crate::widlog::LogStore;

/// The pre-#779 layout, read-only: hashi-types no longer models it, so unlike
/// the current prefixes this one has no constructor to borrow.
const LEGACY_SHARES_PREFIX: &str = "shares/";

/// The committed roster only changes at a ceremony, a re-deal, or a cert
/// rotation — and rotation invalidates explicitly — so a minute of staleness
/// costs nothing and bounds S3 reads under submission spam.
const ROSTER_TTL: Duration = Duration::from_secs(60);
/// A miss — no roster yet, or a signer the cached roster does not name — may
/// be a share set the guardian committed since the last read: `SetupNewKey`
/// and `RotateKpSet` run over the operator's tunnel, so nothing invalidates
/// this cache for them. A miss re-reads at most this often, so a new roster
/// admits its KPs on their first call while unrostered callers cannot force
/// an S3 read each.
const MISS_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

struct Cached {
    at: Instant,
    roster: Option<Arc<Vec<Fingerprint>>>,
}

#[derive(Default)]
struct State {
    cached: Option<Cached>,
    miss_refreshed_at: Option<Instant>,
}

impl State {
    fn miss_refresh_due(&self) -> bool {
        self.miss_refreshed_at
            .is_none_or(|at| at.elapsed() >= MISS_REFRESH_INTERVAL)
    }
}

/// TTL-cached view of [`latest_kp_roster`]. The mutex is held across the fetch,
/// so concurrent misses collapse into one S3 read.
pub struct RosterCache<L> {
    store: L,
    state: Mutex<State>,
}

impl<L: LogStore> RosterCache<L> {
    pub fn new(store: L) -> Self {
        Self {
            store,
            state: Mutex::new(State::default()),
        }
    }

    /// Drop the cached roster so the next read observes a just-committed change.
    pub async fn invalidate(&self) {
        self.state.lock().await.cached = None;
    }

    /// Admit `signer` only if the latest committed share set names it. No share
    /// log yet is a definitive "not ready"; a read error is transient.
    pub async fn authorize(&self, signer: &Fingerprint) -> Result<(), Status> {
        let mut state = self.state.lock().await;
        let fresh = state
            .cached
            .as_ref()
            .filter(|cached| cached.at.elapsed() < ROSTER_TTL)
            .map(|cached| cached.roster.clone());
        let (mut roster, just_read) = match fresh {
            Some(roster) => (roster, false),
            None => (self.read(&mut state).await?, true),
        };
        let names_signer = |roster: &Option<Arc<Vec<Fingerprint>>>| {
            roster
                .as_deref()
                .is_some_and(|roster| roster.contains(signer))
        };
        if !names_signer(&roster) && !just_read && state.miss_refresh_due() {
            state.miss_refreshed_at = Some(Instant::now());
            roster = self.read(&mut state).await?;
        }
        match roster {
            Some(roster) if roster.contains(signer) => Ok(()),
            Some(_) => Err(Status::permission_denied(format!(
                "signer {signer} is not in the ceremony's committed KP roster"
            ))),
            None => Err(Status::failed_precondition(
                "no KP share log in the guardian bucket; run the key ceremony first",
            )),
        }
    }

    /// One read of the share log, cached whatever it finds.
    async fn read(&self, state: &mut State) -> Result<Option<Arc<Vec<Fingerprint>>>, Status> {
        let roster = latest_kp_roster(&self.store)
            .await
            .map_err(|e| {
                warn!(error = %format!("{e:#}"), "KP roster read failed");
                Status::unavailable("KP roster unavailable; retry")
            })?
            .map(Arc::new);
        state.cached = Some(Cached {
            at: Instant::now(),
            roster: roster.clone(),
        });
        Ok(roster)
    }
}

#[cfg(test)]
pub(crate) mod test_utils {
    use crate::widlog::test_store::MemStore;

    /// Commit a one-cert-per-share roster at `sharing_seq`, in the layout the
    /// enclave writes today.
    pub(crate) fn seed_roster(store: &MemStore, sharing_seq: u64, fingerprints: &[&str]) {
        let shares: Vec<serde_json::Value> = fingerprints
            .iter()
            .enumerate()
            .map(|(i, fp)| {
                let ciphertexts: serde_json::Map<String, serde_json::Value> =
                    std::iter::once(((*fp).to_string(), serde_json::json!(""))).collect();
                serde_json::json!({ "id": i + 1, "ciphertexts_by_fingerprint": ciphertexts })
            })
            .collect();
        let record = serde_json::json!({
            "session_id": "test-session",
            "timestamp_ms": 0,
            "message": { "KpShareState": {
                "sharing_seq": sharing_seq,
                "cert_seq": 0,
                "encrypted_shares": shares,
            }},
            "signature": null,
        });
        store.insert(
            format!("kp-shares/{sharing_seq:020}/00000000000000000000-test-session.json"),
            serde_json::to_vec(&record).unwrap(),
        );
        store.insert(
            format!("ceremony/{sharing_seq:020}-test-session.json"),
            b"{}".to_vec(),
        );
    }
}

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

/// Key of the share-state record the latest completed ceremony committed: the
/// lex-greatest `cert_seq` under that ceremony's `sharing_seq` dir. Zero-padded
/// seqs make lex order the seq order throughout.
///
/// Pre-#779 buckets have no `ceremony/` records at all; there the lex-greatest
/// flat `shares/` key is the whole story.
async fn latest_share_log_key<L: LogStore>(log: &L) -> anyhow::Result<Option<String>> {
    let Some(ceremony_key) = log
        .list_keys(&CeremonyLogMessage::object_key_dir())
        .await?
        .into_iter()
        .max()
    else {
        return Ok(log.list_keys(LEGACY_SHARES_PREFIX).await?.into_iter().max());
    };
    let sharing_seq = ceremony_sharing_seq(&ceremony_key)?;
    log.list_keys(&KpShareStateLogMessage::object_key_dir(sharing_seq))
        .await?
        .into_iter()
        .max()
        .map(Some)
        // Shares are written first, so a ceremony without them is a corrupt
        // log, not a not-ready one. Fail closed rather than fall back to a
        // roster this ceremony did not authorize.
        .with_context(|| format!("ceremony {ceremony_key} has no kp-shares log"))
}

/// The `sharing_seq` a `ceremony/{sharing_seq:020}-{session}.json` key records.
/// The canonical padding is required, not just parsed: lex order over these
/// keys is the seq order only while every one of them pads to the same width.
fn ceremony_sharing_seq(key: &str) -> anyhow::Result<u64> {
    key.strip_prefix(&CeremonyLogMessage::object_key_dir())
        .and_then(|name| name.split('-').next())
        .filter(|seq| seq.len() == 20 && seq.bytes().all(|b| b.is_ascii_digit()))
        .with_context(|| format!("ceremony key {key:?} has no sharing_seq"))?
        .parse()
        .with_context(|| format!("ceremony key {key:?} has an out-of-range sharing_seq"))
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
    let (ShareLogMessage::Shares(state) | ShareLogMessage::KpShareState(state)) = record.message;
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
    use super::test_utils::seed_roster;
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

    /// A pre-#779 `shares/` record. Hand-rolled at the JSON layer the parser
    /// sees: hashi-types no longer models this layout, and binding the fixture
    /// to the current enum is what the tolerant parse exists to avoid.
    fn legacy_shares_record(sharing_seq: u64, fingerprints: &[&str]) -> (String, Vec<u8>) {
        let record = serde_json::json!({
            "session_id": "test-session",
            "timestamp_ms": 0,
            "message": { "Shares": {
                "sharing_seq": sharing_seq,
                "encrypted_shares": single_cert_shares(fingerprints),
            }},
            "signature": null,
        });
        let key = format!("shares/{sharing_seq:020}-test-session.json");
        (key, serde_json::to_vec(&record).unwrap())
    }

    /// Mark `sharing_seq` as completed. Only the key matters — the reader takes
    /// the seq from there and never opens a ceremony record.
    fn complete_ceremony(store: &MemStore, sharing_seq: u64) {
        store.insert(
            format!("ceremony/{sharing_seq:020}-test-session.json"),
            b"{}".to_vec(),
        );
    }

    /// A `kp-shares/` record in #779's shape — the layout the enclave writes
    /// today. One cert per share; use `kp_shares_record_multi_cert` for a KP
    /// holding several.
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
        complete_ceremony(&store, 0);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_B)]);
    }

    #[tokio::test]
    async fn latest_cert_seq_wins_within_a_sharing_seq() {
        let store = MemStore::default();
        let (key0, bytes0) = kp_shares_record(3, 0, &[FP_A]);
        let (key1, bytes1) = kp_shares_record(3, 1, &[FP_B]);
        // An older sharing seq must lose regardless of cert_seq.
        let (key_old, bytes_old) = kp_shares_record(2, 9, &[FP_A]);
        store.insert(key0, bytes0);
        store.insert(key1, bytes1);
        store.insert(key_old, bytes_old);
        complete_ceremony(&store, 2);
        complete_ceremony(&store, 3);

        let roster = latest_kp_roster(&store).await.unwrap().unwrap();
        assert_eq!(roster, vec![fp(FP_B)]);
    }

    /// The regression: shares are published before the `ceremony/` record, so a
    /// ceremony that dies in between leaves a `kp-shares/` dir that was never
    /// authorized. Taking the newest dir would swap the roster out from under
    /// the KPs the enclave still accepts, and block provisioning.
    #[tokio::test]
    async fn an_aborted_ceremony_does_not_move_the_roster() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        // A re-deal wrote its shares, then failed before committing.
        let (orphan_key, orphan_bytes) = kp_shares_record(1, 0, &[FP_B]);
        store.insert(orphan_key, orphan_bytes);

        assert_eq!(
            latest_kp_roster(&store).await.unwrap().unwrap(),
            vec![fp(FP_A)]
        );

        // Once that ceremony does commit, the new roster takes over.
        complete_ceremony(&store, 1);
        assert_eq!(
            latest_kp_roster(&store).await.unwrap().unwrap(),
            vec![fp(FP_B)]
        );
    }

    /// Selecting the latest ceremony by lex order only holds while every key
    /// pads to the same width: an unpadded key sorts above every padded one, so
    /// without the width check this resolves to seq 3 and silently serves the
    /// superseded roster instead of seq 5's.
    #[tokio::test]
    async fn an_unpadded_ceremony_key_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(5, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 5);
        let (key, bytes) = kp_shares_record(3, 0, &[FP_B]);
        store.insert(key, bytes);
        store.insert("ceremony/3-test-session.json".to_string(), b"{}".to_vec());

        assert!(latest_kp_roster(&store).await.is_err());
    }

    #[tokio::test]
    async fn a_ceremony_without_its_shares_fails_closed() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        // Its own shares are missing, so falling back to seq 0 would authorize
        // a roster this ceremony replaced.
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
        complete_ceremony(&store, 0);

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

    #[tokio::test(start_paused = true)]
    async fn a_rostered_signer_is_served_from_cache_until_the_ttl() {
        let store = MemStore::default();
        seed_roster(&store, 0, &[FP_A]);
        let cache = RosterCache::new(store);
        cache.authorize(&fp(FP_A)).await.unwrap();

        // The store now fails hard; a fresh read would error, the cache must not.
        cache.store.fail_lists.store(true, Ordering::SeqCst);
        cache.authorize(&fp(FP_A)).await.unwrap();

        tokio::time::advance(ROSTER_TTL).await;
        let err = cache.authorize(&fp(FP_A)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    #[tokio::test]
    async fn authorize_matches_fingerprints_by_value() {
        let store = MemStore::default();
        // Share-log labels are bare hex, so case must not matter.
        seed_roster(&store, 0, &[&FP_A.to_lowercase()]);
        let cache = RosterCache::new(store);

        cache.authorize(&fp(FP_A)).await.unwrap();
        let err = cache.authorize(&fp(FP_B)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    /// `SetupNewKey` and `RotateKpSet` commit a new roster over the operator's
    /// tunnel, never through the proxy, so nothing invalidates the cache: a KP
    /// the new roster adds must be admitted on its first call, not after the
    /// TTL (`key-provisioner ceremony` confirms once and does not retry).
    #[tokio::test]
    async fn a_kp_added_since_the_last_read_is_admitted_on_its_first_call() {
        let store = MemStore::default();
        seed_roster(&store, 0, &[FP_A]);
        let cache = RosterCache::new(store);
        cache.authorize(&fp(FP_A)).await.unwrap();

        // A KP-set rotation commits sharing_seq 1 with a new holder.
        seed_roster(&cache.store, 1, &[FP_A, FP_B]);
        cache.authorize(&fp(FP_B)).await.unwrap();
        cache.authorize(&fp(FP_A)).await.unwrap();
    }

    #[tokio::test]
    async fn the_first_ceremony_is_admitted_from_a_cached_none() {
        let cache = RosterCache::new(MemStore::default());
        let err = cache.authorize(&fp(FP_A)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        seed_roster(&cache.store, 0, &[FP_A]);
        cache.authorize(&fp(FP_A)).await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn miss_refreshes_are_bounded() {
        let store = MemStore::default();
        seed_roster(&store, 0, &[FP_A]);
        let cache = RosterCache::new(store);
        cache.authorize(&fp(FP_A)).await.unwrap();
        let reads = || cache.store.list_calls.load(Ordering::SeqCst);

        // The first unrostered signer costs one re-read; the next does not.
        let before = reads();
        let err = cache.authorize(&fp(FP_B)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(reads() > before);
        let before = reads();
        let err = cache.authorize(&fp(FP_B)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert_eq!(reads(), before);

        // The budget renews after the interval.
        tokio::time::advance(MISS_REFRESH_INTERVAL).await;
        let err = cache.authorize(&fp(FP_B)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(reads() > before);
    }

    #[tokio::test]
    async fn authorize_before_any_ceremony_is_a_failed_precondition() {
        let err = RosterCache::new(MemStore::default())
            .authorize(&fp(FP_A))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn authorize_maps_a_store_failure_to_unavailable() {
        let store = MemStore::default();
        store.fail_lists.store(true, Ordering::SeqCst);
        let err = RosterCache::new(store)
            .authorize(&fp(FP_A))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        // The node classifies guardian errors by substring; this must stay in
        // its retriable bucket.
        assert!(!err.message().contains("seq mismatch"));
        assert!(!err.message().contains("Rate limit exceeded"));
    }

    #[tokio::test]
    async fn invalidate_makes_the_next_read_observe_a_rotated_cert() {
        let store = MemStore::default();
        let (key, bytes) = kp_shares_record(0, 0, &[FP_A]);
        store.insert(key, bytes);
        complete_ceremony(&store, 0);
        let cache = RosterCache::new(store);
        cache.authorize(&fp(FP_A)).await.unwrap();

        // A cert rotation commits a higher cert_seq under the same sharing_seq.
        let (key, bytes) = kp_shares_record(0, 1, &[FP_B]);
        cache.store.insert(key, bytes);
        cache
            .authorize(&fp(FP_A))
            .await
            .expect("still cached until invalidated");

        cache.invalidate().await;
        let err = cache.authorize(&fp(FP_A)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        cache.authorize(&fp(FP_B)).await.unwrap();
    }
}
