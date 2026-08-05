// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The relay's KP roster, read from the guardian's S3 share log. A ceremony
//! commits who holds shares — every encrypted share is labeled with its
//! recipient's PGP fingerprint — so the latest share log IS the authorization
//! roster. The read is deliberately unverified: the bucket only admits enclave
//! writes and this gate is DoS-tier, with the enclave still verifying every
//! share cryptographically (config_hash AAD + commitments).
//!
//! Two layouts are in flight (#779 migrates the first to the second):
//!   `shares/{sharing_seq:020}-{session}.json` (message `Shares`)
//!   `kp-shares/{sharing_seq:020}/{cert_seq:020}-{session}.json` (`KpShareState`)
//! The reader prefers `kp-shares/`, parsing a local tolerant shape rather than
//! the hashi-types enum so it keeps working across that migration.

use std::collections::BTreeMap;

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
    use super::*;
    use crate::widlog::test_store::MemStore;

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
}
