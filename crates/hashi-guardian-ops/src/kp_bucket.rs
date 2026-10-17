// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The key provisioners' bucket, `KP_BUCKET`: KPs upload their public keys to it with a shared upload key, and the
//! operator publishes the guardian configuration to its `_config/` prefix. The bucket comes from the infrastructure,
//! which must let that key read `_config/` and the guardian's log bucket but never write `_config/`, since it names the
//! build every key provisioner will trust. From hashi #1464 on, the signers of a KP-set rotation upload their
//! submissions to its `_rotate-kp-set/` prefix.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;

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
    }
}
