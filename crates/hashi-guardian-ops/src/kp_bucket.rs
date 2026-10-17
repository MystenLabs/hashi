// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The key provisioners' bucket, `KP_BUCKET`: KPs upload their public keys to it with a shared upload key, and the
//! operator publishes the guardian configuration to its `_config/` prefix. The bucket comes from the infrastructure,
//! which must let that key read `_config/` and the guardian's log bucket but never write `_config/`, since it names the
//! build every key provisioner will trust. From hashi #1464 on, the signers of a KP-set rotation upload their
//! submissions to its `_rotate-kp-set/` prefix.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use sha2::Digest;
use sha2::Sha256;

use crate::Ctx;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;

/// The region `key-provisioner/scripts` reach the bucket in.
pub const REGION: &str = "us-west-2";
/// Uploads go under a user ID, which never starts with an underscore.
pub const CONFIG_PREFIX: &str = "_config";
/// `key-provisioner rotate-kp-set` uploads under this, then the session it signs for, in builds with hashi #1464.
pub const ROTATION_PREFIX: &str = "_rotate-kp-set";

/// `KP_BUCKET`, held to the rule `download-config.sh` holds a key provisioner's entry to.
pub fn kp_bucket(ctx: &Ctx) -> Result<String> {
    let bucket = ctx.env.require("KP_BUCKET")?;
    let valid = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && bucket
            .bytes()
            .next()
            .zip(bucket.bytes().last())
            .is_some_and(|(first, last)| {
                first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric()
            });
    if !valid {
        bail!("KP_BUCKET must have 3 to 63 lowercase letters, digits, dots, or hyphens: {bucket}");
    }
    Ok(bucket.to_owned())
}

/// The AWS account and identity the operator's credentials act as.
pub fn identity(ctx: &Ctx) -> Result<(String, String)> {
    let text = read(
        ctx.exec,
        &Cmd::new("aws").args([
            "sts",
            "get-caller-identity",
            "--query",
            "[Account, Arn]",
            "--output",
            "text",
        ]),
    )
    .context("Could not read the AWS identity. Log in to AWS first.")?;
    let mut fields = text.split_whitespace();
    match (fields.next(), fields.next()) {
        (Some(account), Some(arn)) => Ok((account.to_owned(), arn.to_owned())),
        _ => bail!("Could not read the AWS identity from: {}", text.trim()),
    }
}

/// A 40-character fingerprint in ten groups of four, with a wider gap in the middle, as gpg prints it.
pub fn format_fingerprint(fingerprint: &str) -> String {
    let groups: Vec<&str> = (0..fingerprint.len())
        .step_by(4)
        .map(|start| &fingerprint[start..(start + 4).min(fingerprint.len())])
        .collect();
    let (first, second) = groups.split_at(groups.len().min(5));
    format!("{}  {}", first.join(" "), second.join(" "))
}

/// A value in groups of four, for a person to compare group by group.
pub fn group_by_four(value: &str) -> String {
    (0..value.len())
        .step_by(4)
        .map(|start| &value[start..(start + 4).min(value.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

/// The digest key provisioners compare with the operator's post, as their `download-config.sh` computes it.
#[derive(Debug, PartialEq, Eq)]
pub enum DigestScheme {
    /// SHA-256 over a manifest of every published file's SHA-256: `config_digest`, since #1370.
    Manifest,
    /// The first 16 hex characters of `guardian-init.yaml`'s SHA-256, from #1359 until #1370.
    Legacy,
}

/// The in-tree script whose `config_digest` [`manifest_digest`] reproduces, checked against bash in a test.
pub(crate) const DOWNLOAD_CONFIG: &str =
    include_str!("../../../key-provisioner/scripts/download-config.sh");
const LEGACY_LINES: [&str; 2] = [
    "DIGEST=\"$(shasum -a 256 \"$PUBLISHED_CONFIG\")\"",
    "DIGEST=\"${DIGEST:0:16}\"",
];

impl DigestScheme {
    /// The scheme the key provisioners at `tree`'s commit compare. A scheme this tool doesn't know is refused, since
    /// the key provisioners could never match the digest it would post.
    pub fn of(tree: &Tree) -> Result<Self> {
        let path = tree.dir.join("key-provisioner/scripts/download-config.sh");
        let script = std::fs::read_to_string(&path)
            .with_context(|| format!("Could not read {}.", path.display()))?;
        match definition(&script, "config_digest") {
            Some(theirs) if Some(theirs) == definition(DOWNLOAD_CONFIG, "config_digest") => {
                Ok(Self::Manifest)
            }
            None if LEGACY_LINES
                .iter()
                .all(|line| script.lines().any(|l| l.trim() == *line)) =>
            {
                Ok(Self::Legacy)
            }
            _ => bail!(
                "download-config.sh at {} computes the configuration digest in a way this tool does not, so key provisioners could not match the one you would post. Publish from a checkout whose hashi-guardian-ops knows it.",
                tree.commit
            ),
        }
    }

    /// The digest of the files about to be published in `dir`.
    pub fn digest(&self, dir: &Path) -> Result<String> {
        match self {
            Self::Manifest => manifest_digest(dir),
            Self::Legacy => {
                let bytes = std::fs::read(dir.join("guardian-init.yaml"))?;
                Ok(hex::encode(Sha256::digest(bytes))[..16].to_owned())
            }
        }
    }

    /// The digest as the post shows it: two lines of 32 characters, or one of 16 for the legacy scheme.
    pub fn lines(&self, digest: &str) -> Vec<String> {
        match self {
            Self::Manifest => vec![group_by_four(&digest[..32]), group_by_four(&digest[32..])],
            Self::Legacy => vec![group_by_four(digest)],
        }
    }
}

/// A bash function's definition in `script`, from its first line to its closing brace.
fn definition<'a>(script: &'a str, name: &str) -> Option<&'a str> {
    let start = script.find(&format!("\n{name}() {{\n"))? + 1;
    let end = script[start..].find("\n}\n")? + start + 2;
    Some(&script[start..end])
}

/// `config_digest`: each file's SHA-256 and path, sorted by path as `sort -k 2` does under `LC_ALL=C`, then the
/// SHA-256 of those lines.
pub fn manifest_digest(dir: &Path) -> Result<String> {
    let mut lines = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(dir)?
                .to_str()
                .filter(|relative| {
                    relative
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
                })
                .ok_or_else(|| anyhow!("{} has a name shasum would escape.", path.display()))?
                .to_owned();
            let hash = hex::encode(Sha256::digest(std::fs::read(&path)?));
            lines.push((format!("./{relative}"), hash));
        }
    }
    lines.sort();
    let manifest: String = lines
        .iter()
        .map(|(path, hash)| format!("{hash}  {path}\n"))
        .collect();
    Ok(hex::encode(Sha256::digest(manifest)))
}

/// Whether `text` holds an AWS access key ID.
pub fn holds_access_key(text: &str) -> bool {
    text.match_indices("AKIA").any(|(start, _)| {
        text[start + 4..]
            .bytes()
            .take(16)
            .filter(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            .count()
            == 16
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_a_bucket_download_config_sh_would() {
        let repo = tempfile::tempdir().unwrap();
        let exec = crate::exec::fake::Fake::new(|_| None);
        let bucket =
            |name: &str| kp_bucket(&Ctx::for_test(repo.path(), &exec, &[("KP_BUCKET", name)]));
        assert_eq!(bucket("kp-bucket.testnet").unwrap(), "kp-bucket.testnet");
        for bad in [
            "ab",
            "-ab",
            "ab-",
            "Kp-bucket",
            "kp_bucket",
            &"a".repeat(64),
        ] {
            assert!(bucket(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn formats_like_the_scripts() {
        assert_eq!(
            format_fingerprint("0123456789ABCDEF0123456789ABCDEF01234567"),
            "0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567"
        );
        assert_eq!(group_by_four("0123456789abcdef"), "0123 4567 89ab cdef");
    }

    /// The tree a scheme is read from, holding only its `download-config.sh`.
    fn tree_with_script(dir: &Path, script: &str) -> Tree {
        let scripts = dir.join("key-provisioner/scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::write(scripts.join("download-config.sh"), script).unwrap();
        Tree {
            commit: "c".repeat(40),
            dir: dir.to_owned(),
        }
    }

    #[test]
    fn reads_the_scheme_from_the_guardians_commit() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            DigestScheme::of(&tree_with_script(dir.path(), DOWNLOAD_CONFIG)).unwrap(),
            DigestScheme::Manifest
        );
        let legacy = format!(
            "#!/bin/bash\n  {}\n  {}\n",
            LEGACY_LINES[0], LEGACY_LINES[1]
        );
        assert_eq!(
            DigestScheme::of(&tree_with_script(dir.path(), &legacy)).unwrap(),
            DigestScheme::Legacy
        );
        let changed = DOWNLOAD_CONFIG.replace("sort -k 2", "sort");
        assert!(DigestScheme::of(&tree_with_script(dir.path(), &changed)).is_err());
        assert!(DigestScheme::of(&tree_with_script(dir.path(), "#!/bin/bash\n")).is_err());
    }

    #[test]
    fn computes_the_manifest_digest_as_download_config_sh_does() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("certs")).unwrap();
        std::fs::write(dir.path().join("guardian-init.yaml"), "kp_roster: {}\n").unwrap();
        for name in [
            "zed-kp-pubkey.asc",
            "alice-kp-pubkey.asc",
            "alice-kp-pubkey.attestation-sig.pem",
        ] {
            std::fs::write(dir.path().join("certs").join(name), name).unwrap();
        }
        let function = definition(DOWNLOAD_CONFIG, "config_digest").unwrap();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "set -euo pipefail\nexport LC_ALL=C\n{function}\nconfig_digest \"$1\""
            ))
            .arg("bash")
            .arg(dir.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let theirs = String::from_utf8(output.stdout).unwrap();
        assert_eq!(theirs.len(), 64);
        assert_eq!(manifest_digest(dir.path()).unwrap(), theirs);

        std::fs::write(dir.path().join("certs/x y.asc"), "").unwrap();
        assert!(manifest_digest(dir.path()).is_err());
    }

    #[test]
    fn computes_the_legacy_digest_as_download_config_sh_did() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("guardian-init.yaml");
        std::fs::write(&config, "kp_roster: {}\n").unwrap();
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "set -euo pipefail\nPUBLISHED_CONFIG=\"$1\"\n{}\n{}\nprintf '%s' \"$DIGEST\"",
                LEGACY_LINES[0], LEGACY_LINES[1]
            ))
            .arg("bash")
            .arg(&config)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            DigestScheme::Legacy.digest(dir.path()).unwrap(),
            String::from_utf8(output.stdout).unwrap()
        );
    }

    #[test]
    fn finds_access_keys() {
        assert!(holds_access_key(&format!(
            "access_key: \"AKIA{}\"",
            "Q".repeat(16)
        )));
        assert!(!holds_access_key("access_key: \"AKIA-short\""));
        assert!(!holds_access_key("no keys here"));
    }
}
