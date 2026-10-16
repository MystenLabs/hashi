// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The key provisioners' bucket: KPs upload their public keys to it with a shared upload key, and the operator
//! publishes the guardian configuration to its `_config/` prefix, which the upload key may read but never write. From
//! hashi #1464 on, the signers of a KP-set rotation upload their submissions to its `_rotate-kp-set/` prefix.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;

pub const REGION: &str = "us-west-2";
/// Uploads go under a user ID, which never starts with an underscore.
pub const CONFIG_PREFIX: &str = "_config";
/// `key-provisioner rotate-kp-set` uploads under this, then the session it signs for, in builds with hashi #1464.
pub const ROTATION_PREFIX: &str = "_rotate-kp-set";
pub const IAM_PATH: &str = "/hashi-kp-pubkeys/";

/// The bucket and upload user a key provisioner collection's name implies.
pub struct KpBucket {
    pub name: String,
    pub bucket: String,
    pub iam_user: String,
}

impl KpBucket {
    pub fn new(name: &str) -> Result<Self> {
        let valid = !name.is_empty()
            && name.len() <= 39
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !name.starts_with('-')
            && !name.ends_with('-');
        if !valid {
            bail!(
                "KP_NAME must have at most 39 lowercase letters, digits, and inner hyphens: {name}"
            );
        }
        Ok(Self {
            name: name.to_owned(),
            bucket: format!("mysten-hashi-kp-pubkeys-{name}"),
            iam_user: format!("hashi-kp-pubkeys-{name}-upload"),
        })
    }

    pub fn from_env(ctx: &Ctx) -> Result<Self> {
        Self::new(ctx.env.require("KP_NAME")?)
    }
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
    .context(
        "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin",
    )?;
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

/// A digest in groups of four, for a person to compare group by group.
pub fn group_by_four(value: &str) -> String {
    (0..value.len())
        .step_by(4)
        .map(|start| &value[start..(start + 4).min(value.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the upload key may do: upload into the bucket, outside `_config/`.
pub fn upload_policy(bucket: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": format!("arn:aws:s3:::{bucket}/*"),
            },
            {
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": format!("arn:aws:s3:::{bucket}/{CONFIG_PREFIX}/*"),
            },
        ],
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_bucket_and_user() {
        let kp = KpBucket::new("testnet").unwrap();
        assert_eq!(kp.bucket, "mysten-hashi-kp-pubkeys-testnet");
        assert_eq!(kp.iam_user, "hashi-kp-pubkeys-testnet-upload");
        for bad in ["", "-x", "x-", "Testnet", "a_b", &"a".repeat(40)] {
            assert!(KpBucket::new(bad).is_err(), "{bad}");
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
}
