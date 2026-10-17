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
use crate::kp_bucket::ROTATION_PREFIX;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::identity;
use crate::kp_bucket::kp_bucket;
use crate::say;
use crate::stack::Stack;

const ROSTER: &str = "roster.txt";

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

/// The user ID a key provisioner file belongs to, if `key` is one: `<id>/<id>-<suffix>`. The download writes the roster
/// beside the user IDs' directories, so none may take its name, in any case.
fn kp_file_owner(key: &str) -> Option<String> {
    let (id, file) = key.split_once('/')?;
    let valid_id = !id.eq_ignore_ascii_case(ROSTER)
        && id.starts_with(|c: char| c.is_ascii_alphanumeric())
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

/// Downloads and verifies every key provisioner upload in `KP_BUCKET`, then writes the roster in the fingerprint order a
/// ceremony deals by.
pub fn download_kp_pubkeys(ctx: &Ctx, out: Option<PathBuf>) -> Result<()> {
    let bucket = kp_bucket(ctx)?;
    let out = match out {
        Some(dir) if dir.is_absolute() => dir,
        Some(dir) => std::env::current_dir()?.join(dir),
        None => ctx.repo.join(".hashi/kp-pubkeys").join(format!(
            "{bucket}-{}",
            jiff::Timestamp::now().strftime("%Y%m%dT%H%M%SZ")
        )),
    };
    say("Key provisioner upload download");
    println!(
        "This step downloads every key provisioner upload in s3://{},",
        bucket
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
    if !guardian_init.has_tool(ctx, "verify-kp-cert")? {
        bail!(
            "hashi-guardian-init at {}, slot {}'s commit, has no tools verify-kp-cert, so it cannot verify uploads.",
            view.commit,
            view.slot
        );
    }
    println!(
        "Verifying with hashi-guardian-init at {}, slot {}'s commit.",
        view.commit, view.slot
    );

    say("List the uploads");
    let listing: Listing = read_json(
        ctx.exec,
        &Cmd::new("aws")
            .args(["s3api", "list-object-versions", "--bucket", &bucket])
            .args(["--expected-bucket-owner", &account, "--output", "json"]),
    )
    .with_context(|| format!("Could not list s3://{}.", bucket))?;
    let uploads = Uploads::sort(listing.versions);
    if uploads.latest.is_empty() && uploads.unexpected.is_empty() {
        bail!("No uploads in s3://{} yet.", bucket);
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
            let dir = out.join(id);
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Could not create {}.", dir.display()))?;
            for (key, version_id) in files {
                read(
                    ctx.exec,
                    &Cmd::new("aws")
                        .args(["s3api", "get-object", "--bucket", &bucket])
                        .args(["--expected-bucket-owner", &account, "--key", key])
                        .args(["--version-id", version_id])
                        .arg(out.join(key)),
                )
                .with_context(|| format!("Could not download s3://{}/{key}.", bucket))?;
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
                    println!("    {}", shown(line));
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
            println!("  s3://{bucket}/{}", shown(key));
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
    let roster_path = out.join(ROSTER);
    std::fs::write(&roster_path, &roster)
        .with_context(|| format!("Could not write {}.", roster_path.display()))?;
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
    let output = ctx
        .exec
        .output(
            &guardian_init
                .cmd()
                .args(["tools", "verify-kp-cert", "--kp-pgp-cert-path"])
                .arg(out.join(id).join(format!("{id}-kp-pubkey.asc")))
                .capture_stderr(),
        )
        .context("Could not run the guardian's tools.")?;
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
            format!("unexpected fingerprint: {}", shown(fingerprint)),
            None,
        ));
    }
    let recorded_path = out.join(id).join(format!("{id}-kp-fingerprint.txt"));
    // Anything the upload holds is checked against the certificate, so bytes that aren't UTF-8 just don't match.
    let recorded_bytes = std::fs::read(&recorded_path)
        .with_context(|| format!("Could not read {}.", recorded_path.display()))?;
    let recorded_text = String::from_utf8_lossy(&recorded_bytes).into_owned();
    let recorded = recorded_text.lines().next().unwrap_or("");
    if recorded != fingerprint {
        return Ok(Status::Invalid(
            format!(
                "{id}-kp-fingerprint.txt ({}) does not match the certificate ({fingerprint})",
                shown(recorded)
            ),
            None,
        ));
    }
    Ok(Status::Verified(fingerprint.to_owned()))
}

/// `text` with its control characters escaped: anyone with the upload key chooses what an upload holds.
pub(crate) fn shown(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
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
            version("_rotate-kp-set/0123456789abcdef/AAAA.rotation", "1", true),
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

    fn bundle(id: &str) -> Vec<serde_json::Value> {
        KP_FILE_SUFFIXES
            .iter()
            .map(|suffix| {
                serde_json::json!({ "Key": format!("{id}/{id}-{suffix}"), "VersionId": "1", "IsLatest": true })
            })
            .collect()
    }

    /// A one-slot stack, and a bucket holding `versions` whose certificates verify to `fingerprints`, by user ID. Each
    /// upload records its certificate's fingerprint, or what `recorded` gives for its user ID.
    fn bucket_world(
        versions: Vec<serde_json::Value>,
        fingerprints: &[(&str, String)],
        verifier: bool,
        recorded: &[(&str, &str)],
    ) -> crate::exec::fake::Fake {
        let stack = crate::stack::tests::one_slot();
        let fingerprints: BTreeMap<String, String> = fingerprints
            .iter()
            .map(|(id, fingerprint)| ((*id).to_owned(), fingerprint.clone()))
            .collect();
        let recorded: BTreeMap<String, String> = recorded
            .iter()
            .map(|(id, fingerprint)| ((*id).to_owned(), (*fingerprint).to_owned()))
            .collect();
        crate::exec::fake::Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["aws", "sts", "get-caller-identity", ..] => {
                    Some((true, "111122223333\tarn:aws:iam::111122223333:user/op\n".to_owned()))
                }
                ["pulumi", ..] => {
                    crate::exec::Exec::output(&stack, &Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                ["cargo", "build", ..] => Some((
                    true,
                    r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#
                        .to_owned(),
                )),
                ["/x/hashi-guardian-init", "tools", "--help"] => Some((
                    true,
                    if verifier { "  verify-kp-cert  Verify a certificate\n" } else { "" }.to_owned(),
                )),
                ["aws", "s3api", "list-object-versions", ..] => Some((
                    true,
                    serde_json::json!({ "Versions": versions }).to_string(),
                )),
                ["aws", "s3api", "get-object", ..] => {
                    let key = w[w.iter().position(|word| *word == "--key")? + 1];
                    let id = key.split('/').next()?;
                    let body = if key.ends_with("kp-fingerprint.txt") {
                        let fingerprint = recorded.get(id).or(fingerprints.get(id));
                        format!("{}\n", fingerprint.cloned().unwrap_or_default())
                    } else {
                        key.to_owned()
                    };
                    std::fs::write(w.last()?, body).ok()?;
                    Some((true, "{}".to_owned()))
                }
                ["/x/hashi-guardian-init", "tools", "verify-kp-cert", "--kp-pgp-cert-path", path] => {
                    let name = std::path::Path::new(path).file_name()?.to_str()?;
                    let id = name.strip_suffix("-kp-pubkey.asc")?;
                    Some(match fingerprints.get(id) {
                        Some(fingerprint) => (true, format!("{fingerprint}\n")),
                        None => (false, String::new()),
                    })
                }
                _ => None,
            }
        })
    }

    fn download(exec: &crate::exec::fake::Fake) -> (tempfile::TempDir, Result<()>) {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(
            repo.path()
                .join(".hashi/guardian-init")
                .join(crate::stack::tests::COMMIT),
        )
        .unwrap();
        let mut env = crate::stack::tests::stack_env();
        env.push(("KP_BUCKET", "kp-bucket"));
        let out = repo.path().join("out");
        let result = download_kp_pubkeys(&Ctx::for_test(repo.path(), exec, &env), Some(out));
        (repo, result)
    }

    #[test]
    fn writes_the_roster_in_share_order_and_never_writes_to_the_bucket() {
        let mut versions = bundle("alice");
        versions.extend(bundle("bob"));
        let exec = bucket_world(
            versions,
            &[("alice", "B".repeat(40)), ("bob", "A".repeat(40))],
            true,
            &[],
        );
        let (repo, result) = download(&exec);
        result.unwrap();
        let roster = std::fs::read_to_string(repo.path().join("out/roster.txt")).unwrap();
        assert!(roster.starts_with("1  bob"), "{roster}");
        assert!(roster.contains("\n2  alice"), "{roster}");
        for words in exec.log.borrow().iter().filter(|words| words[0] == "aws") {
            assert!(
                ["get-caller-identity", "list-object-versions", "get-object"]
                    .contains(&words[2].as_str()),
                "{words:?}"
            );
        }
    }

    #[test]
    fn writes_no_roster_unless_every_upload_verifies() {
        let mut versions = bundle("alice");
        versions.extend(bundle("roster.txt"));
        versions.extend(bundle("bob"));
        // bob's certificate fails to verify, and a user ID can't take the roster's name.
        let exec = bucket_world(versions, &[("alice", "B".repeat(40))], true, &[]);
        let (repo, result) = download(&exec);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("Not every upload verified")
        );
        assert!(!repo.path().join("out/roster.txt").exists());

        let exec = bucket_world(bundle("alice"), &[("alice", "B".repeat(40))], false, &[]);
        let (_, result) = download(&exec);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .ends_with("has no tools verify-kp-cert, so it cannot verify uploads.")
        );
    }

    #[test]
    fn writes_no_roster_past_any_one_refusal() {
        let fingerprint = |id: &'static str, digit: &str| (id, digit.repeat(40));
        let with =
            |ids: &[&str], extra: &[&str]| {
                let mut versions: Vec<serde_json::Value> =
                    ids.iter().flat_map(|id| bundle(id)).collect();
                versions.extend(extra.iter().map(
                    |key| serde_json::json!({ "Key": key, "VersionId": "1", "IsLatest": true }),
                ));
                versions
            };
        let cases = [
            (
                "an upload missing a file",
                bundle("alice")[1..].to_vec(),
                vec![fingerprint("alice", "B")],
                &[][..],
            ),
            (
                "an object that is no upload",
                with(&["alice"], &["stray.txt"]),
                vec![fingerprint("alice", "B")],
                &[],
            ),
            (
                "one certificate under two user IDs",
                with(&["alice", "bob"], &[]),
                vec![fingerprint("alice", "B"), fingerprint("bob", "B")],
                &[],
            ),
            (
                "user IDs that differ only by case",
                with(&["alice", "Alice"], &[]),
                vec![fingerprint("alice", "B"), fingerprint("Alice", "C")],
                &[],
            ),
            (
                "a user ID the roster file would take",
                with(&["alice", "Roster.txt"], &[]),
                vec![fingerprint("alice", "B"), fingerprint("Roster.txt", "C")],
                &[],
            ),
            (
                "a recorded fingerprint the certificate doesn't have",
                bundle("alice"),
                vec![fingerprint("alice", "B")],
                &[("alice", "CCCC")],
            ),
        ];
        for (case, versions, fingerprints, recorded) in cases {
            let exec = bucket_world(versions, &fingerprints, true, recorded);
            let (repo, result) = download(&exec);
            let error = result.unwrap_err().to_string();
            assert!(
                error.starts_with("Not every upload verified"),
                "{case}: {error}"
            );
            assert!(!repo.path().join("out/roster.txt").exists(), "{case}");
        }
    }

    #[test]
    fn recognizes_key_provisioner_files() {
        assert_eq!(
            kp_file_owner("dave/dave-kp-pubkey.attestation-dec.pem").as_deref(),
            Some("dave")
        );
        assert_eq!(kp_file_owner("dave/erin-kp-pubkey.asc"), None);
        assert_eq!(kp_file_owner("_x/_x-kp-pubkey.asc"), None);
        assert_eq!(kp_file_owner("dave-kp-pubkey.asc"), None);
    }
}
