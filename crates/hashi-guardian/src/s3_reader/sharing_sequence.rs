// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use super::GuardianReader;
use hashi_types::guardian::CeremonyLogMessage;
use hashi_types::guardian::GuardianError::InvalidS3Log;
use hashi_types::guardian::GuardianResult;

impl GuardianReader {
    /// Choose a sequence above every completed ceremony and occupied share directory.
    /// Shares are published before the ceremony commit, so an interrupted attempt
    /// can occupy a sequence even though no ceremony record exists for it.
    ///
    /// This allocates under the single ceremony-writer assumption; it does not
    /// reserve the sequence. Conditional writes still reject competing records.
    pub(crate) async fn next_sharing_seq(&self) -> GuardianResult<u64> {
        let mut highest = None;
        for key in self
            .s3
            .list_keys(&CeremonyLogMessage::object_key_dir())
            .await?
        {
            let seq = parse_sequence(&key, "ceremony/", ".json")?;
            highest = Some(highest.map_or(seq, |previous: u64| previous.max(seq)));
        }
        for directory in self.s3.list_common_prefixes("kp-shares/").await? {
            if directory == "kp-shares/proposed/" {
                continue;
            }
            let seq = parse_sequence(&directory, "kp-shares/", "/")?;
            highest = Some(highest.map_or(seq, |previous| previous.max(seq)));
        }
        match highest {
            None => Ok(0),
            Some(seq) => seq
                .checked_add(1)
                .ok_or_else(|| InvalidS3Log("sharing_seq exhausted".into())),
        }
    }
}

fn parse_sequence(path: &str, prefix: &str, suffix: &str) -> GuardianResult<u64> {
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .filter(|seq| seq.len() == 20 && seq.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|seq| seq.parse().ok())
        .ok_or_else(|| InvalidS3Log(format!("invalid sharing sequence path {path}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::mock_logger_with_layout;
    use hashi_types::guardian::DeploymentConfig;

    async fn next(keys: &[&str]) -> GuardianResult<u64> {
        let s3 = mock_logger_with_layout(keys.iter().map(|key| key.to_string()));
        GuardianReader::from_s3_client(s3, DeploymentConfig::mock_for_testing())
            .next_sharing_seq()
            .await
    }

    #[tokio::test]
    async fn empty_bucket_and_proposals_do_not_consume_sequences() {
        assert_eq!(next(&[]).await.unwrap(), 0);
        assert_eq!(next(&["kp-shares/proposed/session.json"]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn skips_initial_shares_from_abandoned_setup() {
        assert_eq!(
            next(&["kp-shares/00000000000000000000/00000000000000000000.json"])
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn skips_abandoned_rotations_without_reusing_gaps() {
        assert_eq!(
            next(&[
                "ceremony/00000000000000000006.json",
                "kp-shares/00000000000000000006/00000000000000000099.json",
                "kp-shares/00000000000000000007/00000000000000000000.json",
                "kp-shares/00000000000000000009/00000000000000000000.json",
            ])
            .await
            .unwrap(),
            10
        );
    }

    #[tokio::test]
    async fn completed_ceremony_consumes_sequence_even_after_shares_are_purged() {
        assert_eq!(
            next(&["ceremony/00000000000000000006.json"]).await.unwrap(),
            7
        );
    }

    #[tokio::test]
    async fn delete_marked_orphan_still_consumes_its_sequence() {
        let s3 = crate::test_utils::mock_logger_with_deleted_layout(
            std::iter::empty(),
            ["kp-shares/00000000000000000007/00000000000000000000.json".to_string()],
        );
        let reader = GuardianReader::from_s3_client(s3, DeploymentConfig::mock_for_testing());
        assert_eq!(reader.next_sharing_seq().await.unwrap(), 8);
    }

    #[tokio::test]
    async fn rejects_malformed_or_exhausted_sequences() {
        for key in [
            "ceremony/9.json",
            "kp-shares/bad/record.json",
            "ceremony/18446744073709551615.json",
        ] {
            assert!(next(&[key]).await.is_err(), "{key}");
        }
    }
}
