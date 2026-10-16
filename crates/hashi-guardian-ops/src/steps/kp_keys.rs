// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Collecting the key provisioners' public keys from their upload bucket: `download-kp-pubkeys`.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::Ctx;
use crate::commit::GuardianInit;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;
use crate::kp_bucket::CONFIG_PREFIX;
use crate::kp_bucket::KpBucket;
use crate::kp_bucket::ROTATION_PREFIX;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::identity;
use crate::say;
use crate::stack::Stack;

const KP_FILE_SUFFIXES: [&str; 5] = [
    "kp-pubkey.asc",
    "kp-fingerprint.txt",
    "kp-pubkey.attestation-device.pem",
    "kp-pubkey.attestation-sig.pem",
    "kp-pubkey.attestation-dec.pem",
];

#[derive(Deserialize)]
struct Listing {
    #[serde(rename = "Versions", default)]
    versions: Vec<Version>,
}

#[derive(Deserialize)]
struct Version {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "VersionId")]
    version_id: String,
    #[serde(rename = "IsLatest")]
    is_latest: bool,
}

/// What the bucket's listing holds, sorted out.
#[derive(Default)]
struct Uploads {
    /// The latest version of each key provisioner file: key and version, by user ID.
    latest: BTreeMap<String, Vec<(String, String)>>,
    /// Key provisioner files with more than one version.
    reuploaded: BTreeSet<String>,
    /// The latest version of anything else.
    unexpected: Vec<String>,
}

impl Uploads {
    fn sort(versions: Vec<Version>) -> Self {
        let mut uploads = Self::default();
        let mut seen = BTreeSet::new();
        for version in versions {
            if [CONFIG_PREFIX, ROTATION_PREFIX]
                .iter()
                .any(|prefix| version.key.starts_with(&format!("{prefix}/")))
            {
                continue;
            }
            match kp_file_owner(&version.key) {
                Some(id) => {
                    if !seen.insert(version.key.clone()) {
                        uploads.reuploaded.insert(version.key.clone());
                    }
                    if version.is_latest {
                        uploads
                            .latest
                            .entry(id)
                            .or_default()
                            .push((version.key, version.version_id));
                    }
                }
                None if version.is_latest => uploads.unexpected.push(version.key),
                None => {}
            }
        }
        uploads
    }
}

/// The user ID a key provisioner file belongs to, if `key` is one: `<id>/<id>-<suffix>`.
fn kp_file_owner(key: &str) -> Option<String> {
    let (id, file) = key.split_once('/')?;
    let valid_id = id.starts_with(|c: char| c.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    let valid_file = KP_FILE_SUFFIXES
        .iter()
        .any(|suffix| file == format!("{id}-{suffix}"));
    (valid_id && valid_file).then(|| id.to_owned())
}

enum Status {
    Verified(String),
    Incomplete(String),
    Invalid(String, Option<String>),
}

/// Downloads and verifies every key provisioner upload in the bucket `KP_NAME` names, then writes the roster in the
/// fingerprint order a ceremony deals by.
pub fn download_kp_pubkeys(ctx: &Ctx, out: Option<PathBuf>) -> Result<()> {
    let kp = KpBucket::from_env(ctx)?;
    let out = match out {
        Some(dir) if dir.is_absolute() => dir,
        Some(dir) => std::env::current_dir()?.join(dir),
        None => ctx.repo.join(".hashi/kp-pubkeys").join(format!(
            "{}-{}",
            kp.name,
            jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ")
        )),
    };
    say("Key provisioner upload download");
    println!(
        "This step downloads every key provisioner upload in s3://{},",
        kp.bucket
    );
    println!(
        "verifies each certificate and its YubiKey attestations as certificate-loading commands do,"
    );
    println!("and prints the roster once every upload verifies.");

    say("Check the AWS account");
    let (account, arn) = identity(ctx)?;
    println!("AWS account:  {account}\nAWS identity: {arn}");

    // Verify as the key provisioners' tools will: with the guardian's own build.
    say("Build the certificate verifier");
    let stack = Stack::load(ctx)?;
    let view = stack.slot(ctx, stack.active()?)?;
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    println!(
        "Verifying with hashi-guardian-init at {}, slot {}'s commit.",
        view.commit, view.slot
    );

    say("List the uploads");
    let listing: Listing = read_json(
        ctx.exec,
        &Cmd::new("aws")
            .args(["s3api", "list-object-versions", "--bucket", &kp.bucket])
            .args(["--expected-bucket-owner", &account, "--output", "json"]),
    )
    .with_context(|| format!("Could not list s3://{}.", kp.bucket))?;
    let uploads = Uploads::sort(listing.versions);
    if uploads.latest.is_empty() && uploads.unexpected.is_empty() {
        bail!("No uploads in s3://{} yet.", kp.bucket);
    }
    println!("User IDs: {}", uploads.latest.len());

    let width = uploads
        .latest
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(0)
        .max(2);
    if !uploads.latest.is_empty() {
        say("Download the uploads");
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::create_dir(&out).with_context(|| {
            format!(
                "Could not create a new output directory at {}.",
                out.display()
            )
        })?;
        let mut count = 0;
        for (id, files) in &uploads.latest {
            std::fs::create_dir_all(out.join(id))?;
            for (key, version_id) in files {
                read(
                    ctx.exec,
                    &Cmd::new("aws")
                        .args(["s3api", "get-object", "--bucket", &kp.bucket])
                        .args(["--expected-bucket-owner", &account, "--key", key])
                        .args(["--version-id", version_id])
                        .arg(out.join(key)),
                )
                .with_context(|| format!("Could not download s3://{}/{key}.", kp.bucket))?;
                count += 1;
            }
        }
        println!("Downloaded {count} files into {}", out.display());
    }

    say("Verify each key provisioner");
    // Downloads land on a case-insensitive filesystem, and each ID must name one key provisioner.
    let mut by_case: BTreeMap<String, usize> = BTreeMap::new();
    for id in uploads.latest.keys() {
        *by_case.entry(id.to_lowercase()).or_default() += 1;
    }
    let mut statuses: Vec<(String, Status)> = Vec::new();
    for id in uploads.latest.keys() {
        let status = verify_upload(
            ctx,
            &guardian_init,
            &out,
            id,
            by_case[&id.to_lowercase()] > 1,
        )?;
        statuses.push((id.clone(), status));
    }
    let mut fingerprints: BTreeMap<String, usize> = BTreeMap::new();
    for (_, status) in &statuses {
        if let Status::Verified(fingerprint) = status {
            *fingerprints.entry(fingerprint.clone()).or_default() += 1;
        }
    }
    let mut verified = Vec::new();
    for (id, status) in statuses {
        let status = match status {
            Status::Verified(fingerprint) if fingerprints[&fingerprint] > 1 => Status::Invalid(
                format!("same certificate as another user ID ({fingerprint})"),
                None,
            ),
            status => status,
        };
        match status {
            Status::Verified(fingerprint) => {
                println!(
                    "{id:<width$}  {:<10}  {}",
                    "VERIFIED",
                    format_fingerprint(&fingerprint)
                );
                verified.push((fingerprint, id));
            }
            Status::Incomplete(detail) => println!("{id:<width$}  {:<10}  {detail}", "INCOMPLETE"),
            Status::Invalid(detail, errors) => {
                println!("{id:<width$}  {:<10}  {detail}", "INVALID");
                for line in errors.iter().flat_map(|errors| errors.lines()) {
                    println!("    {line}");
                }
            }
        }
    }

    let reuploaded: Vec<&String> = uploads
        .latest
        .iter()
        .filter(|(_, files)| {
            files
                .iter()
                .any(|(key, _)| uploads.reuploaded.contains(key))
        })
        .map(|(id, _)| id)
        .collect();
    if !reuploaded.is_empty() {
        println!("\nNotes:");
        for id in reuploaded {
            println!(
                "  {id} uploaded some files more than once; the latest upload of each file is used."
            );
        }
    }
    if !uploads.unexpected.is_empty() {
        println!(
            "\nUnexpected objects (inspect them, remove them with aws s3 rm, then download again):"
        );
        for key in &uploads.unexpected {
            println!("  s3://{}/{key}", kp.bucket);
        }
    }
    if !uploads.unexpected.is_empty()
        || verified.is_empty()
        || verified.len() != uploads.latest.len()
    {
        if out.is_dir() {
            println!("\nDownloaded files: {}", out.display());
        }
        bail!(
            "Not every upload verified, so no roster was written. Fix the problems above and download again."
        );
    }

    // Share IDs follow the ascending fingerprint order in which a ceremony deals these certificates.
    say("Roster");
    verified.sort();
    let roster: String = verified
        .iter()
        .enumerate()
        .map(|(index, (fingerprint, id))| {
            format!(
                "{}  {id:<width$}  {}\n",
                index + 1,
                format_fingerprint(fingerprint)
            )
        })
        .collect();
    std::fs::write(out.join("roster.txt"), &roster)?;
    print!("{roster}");
    println!(
        "\nKey provisioners: {}\nRoster and files: {}",
        verified.len(),
        out.display()
    );
    println!(
        "\nRoster verified successfully! Post it in a code block and have each key provisioner confirm their row."
    );
    Ok(())
}

/// Checks one key provisioner's downloaded files, as certificate-loading commands do.
fn verify_upload(
    ctx: &Ctx,
    guardian_init: &GuardianInit,
    out: &std::path::Path,
    id: &str,
    case_collision: bool,
) -> Result<Status> {
    let missing: Vec<String> = KP_FILE_SUFFIXES
        .iter()
        .map(|suffix| format!("{id}-{suffix}"))
        .filter(|file| !out.join(id).join(file).is_file())
        .collect();
    if !missing.is_empty() {
        return Ok(Status::Incomplete(format!("missing {}", missing.join(" "))));
    }
    if case_collision {
        return Ok(Status::Invalid(
            "another user ID differs only by letter case".to_owned(),
            None,
        ));
    }
    let output = ctx.exec.output(
        &guardian_init
            .cmd()
            .args(["tools", "verify-kp-cert", "--kp-pgp-cert-path"])
            .arg(out.join(id).join(format!("{id}-kp-pubkey.asc")))
            .capture_stderr(),
    )?;
    if !output.success {
        return Ok(Status::Invalid(
            "certificate verification failed:".to_owned(),
            Some(output.stderr),
        ));
    }
    let fingerprint = output.stdout.trim();
    if fingerprint.len() != 40
        || !fingerprint
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
    {
        return Ok(Status::Invalid(
            format!("unexpected fingerprint: {fingerprint}"),
            None,
        ));
    }
    let recorded_path = out.join(id).join(format!("{id}-kp-fingerprint.txt"));
    // Anything the upload holds is checked against the certificate, so bytes that aren't UTF-8 just don't match.
    let recorded_text = String::from_utf8_lossy(&std::fs::read(&recorded_path)?).into_owned();
    let recorded = recorded_text.lines().next().unwrap_or("");
    if recorded != fingerprint {
        return Ok(Status::Invalid(
            format!(
                "{id}-kp-fingerprint.txt ({recorded}) does not match the certificate ({fingerprint})"
            ),
            None,
        ));
    }
    Ok(Status::Verified(fingerprint.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(key: &str, id: &str, is_latest: bool) -> Version {
        Version {
            key: key.to_owned(),
            version_id: id.to_owned(),
            is_latest,
        }
    }

    #[test]
    fn sorts_the_listing() {
        let uploads = Uploads::sort(vec![
            version("alice/alice-kp-pubkey.asc", "2", true),
            version("alice/alice-kp-pubkey.asc", "1", false),
            version("alice/alice-kp-fingerprint.txt", "1", true),
            version("_config/guardian-init.yaml", "1", true),
            version("_rotate-kp-set/309a48769f19b17a/0D8E.rotation", "1", true),
            version("bob/notes.txt", "1", true),
            version("bob/alice-kp-pubkey.asc", "1", true),
            version("stray.txt", "1", true),
            version("old/old-kp-pubkey.asc", "1", false),
        ]);
        assert_eq!(uploads.latest.keys().collect::<Vec<_>>(), ["alice"]);
        assert_eq!(uploads.latest["alice"].len(), 2);
        assert!(uploads.reuploaded.contains("alice/alice-kp-pubkey.asc"));
        assert_eq!(
            uploads.unexpected,
            ["bob/notes.txt", "bob/alice-kp-pubkey.asc", "stray.txt"]
        );
    }

    #[test]
    fn recognizes_key_provisioner_files() {
        assert_eq!(
            kp_file_owner("zhou/zhou-kp-pubkey.attestation-dec.pem").as_deref(),
            Some("zhou")
        );
        assert_eq!(kp_file_owner("zhou/luke-kp-pubkey.asc"), None);
        assert_eq!(kp_file_owner("_x/_x-kp-pubkey.asc"), None);
        assert_eq!(kp_file_owner("zhou-kp-pubkey.asc"), None);
    }
}
