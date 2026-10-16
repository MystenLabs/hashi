// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The key provisioners' upload bucket: `create-kp-upload-bucket`, collecting their public keys with
//! `download-kp-pubkeys`, and `revoke-kp-upload-key` once they no longer need it.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::Ctx;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::commit::GuardianInit;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;
use crate::kp_bucket::CONFIG_PREFIX;
use crate::kp_bucket::IAM_PATH;
use crate::kp_bucket::KpBucket;
use crate::kp_bucket::REGION;
use crate::kp_bucket::ROTATION_PREFIX;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::group_by_four;
use crate::kp_bucket::identity;
use crate::kp_bucket::upload_policy;
use crate::say;
use crate::stack::Stack;
use crate::warn;

const ROSTER: &str = "roster.txt";
const REVOKE: &str = "the revoke-kp-upload-key step";

/// Creates the upload bucket and an access key that can only upload into it, and tests the key with a real upload.
pub fn create_kp_upload_bucket(ctx: &Ctx) -> Result<()> {
    let kp = KpBucket::from_env(ctx)?;
    if !ctx.ask.interactive() {
        bail!("This setup is interactive and must run in a terminal.");
    }
    let (bucket, user) = (&kp.bucket, &kp.iam_user);
    say("Key provisioner upload bucket setup");
    println!("This step creates, in {REGION}:");
    println!("  S3 bucket s3://{bucket}, versioned, with public access blocked");
    println!(
        "  IAM user {IAM_PATH}{user}, allowed only s3:PutObject into that bucket, outside {CONFIG_PREFIX}/"
    );
    println!("  one access key for that user, tested with a real upload");
    println!(
        "Key provisioners enter the bucket and access key into key-provisioner/scripts/upload-pubkey.sh."
    );

    say("Check the AWS account");
    let (account, arn) = identity(ctx)?;
    println!("AWS account:  {account}\nAWS identity: {arn}");
    let existing = ctx.exec.output(
        &Cmd::new("aws")
            .args(["iam", "get-user", "--user-name", user])
            .capture_stderr(),
    )?;
    if existing.success {
        bail!(
            "IAM user {user} already exists. Choose another KP_NAME, or revoke it with {REVOKE} and delete its bucket if it holds nothing: aws s3 rb s3://{bucket}"
        );
    }
    if !existing.stderr.contains("(NoSuchEntity)") {
        bail!(
            "Could not check IAM user {user}: {}",
            existing.stderr.trim()
        );
    }
    // A run that failed after creating the bucket leaves it behind, and the next one could only fail on it.
    let found = ctx.exec.output(
        &Cmd::new("aws")
            .args(["s3api", "head-bucket", "--bucket", bucket])
            .args(["--expected-bucket-owner", &account])
            .capture_stderr(),
    )?;
    if found.success {
        bail!(
            "s3://{bucket} already exists. Choose another KP_NAME, or delete the bucket if it holds nothing: aws s3 rb s3://{bucket}"
        );
    }
    if !found.stderr.contains("(404)") {
        bail!("Could not check s3://{bucket}: {}", found.stderr.trim());
    }
    confirm(
        ctx.ask,
        &format!("Create these resources in AWS account {account}?"),
        &Unchanged {
            no_input: "No input received; nothing was created.",
            declined: "Creation not confirmed; nothing was created.",
        },
    )?;

    say("Create the bucket");
    let aws = |args: &[&str]| Cmd::new("aws").args(args);
    let delete_bucket = format!("Delete the empty bucket with: aws s3 rb s3://{bucket}");
    read(
        ctx.exec,
        &aws(&[
            "s3api",
            "create-bucket",
            "--bucket",
            bucket,
            "--region",
            REGION,
        ])
        .arg("--create-bucket-configuration")
        .arg(format!("LocationConstraint={REGION}")),
    )
    .with_context(|| format!("Could not create s3://{bucket}. Nothing was created."))?;
    read(
        ctx.exec,
        &aws(&["s3api", "put-public-access-block", "--bucket", bucket])
            .args(["--expected-bucket-owner", &account])
            .args(["--public-access-block-configuration", "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"]),
    )
    .with_context(|| format!("Could not block public access to s3://{bucket}. {delete_bucket}"))?;
    read(
        ctx.exec,
        &aws(&["s3api", "put-bucket-versioning", "--bucket", bucket])
            .args(["--expected-bucket-owner", &account])
            .args(["--versioning-configuration", "Status=Enabled"]),
    )
    .with_context(|| format!("Could not enable versioning on s3://{bucket}. {delete_bucket}"))?;
    println!("Created s3://{bucket}.");

    say("Create the upload user and access key");
    let remove_user = format!(
        "Remove the user with {REVOKE}, then delete the empty bucket with: aws s3 rb s3://{bucket}"
    );
    read(
        ctx.exec,
        &aws(&[
            "iam",
            "create-user",
            "--user-name",
            user,
            "--path",
            IAM_PATH,
        ]),
    )
    .with_context(|| format!("Could not create IAM user {user}. {delete_bucket}"))?;
    read(
        ctx.exec,
        &aws(&["iam", "put-user-policy", "--user-name", user])
            .args(["--policy-name", "put-kp-pubkeys", "--policy-document"])
            .arg(upload_policy(bucket)),
    )
    .with_context(|| format!("Could not add the upload policy to {user}. {remove_user}"))?;
    let key = read(
        ctx.exec,
        &aws(&["iam", "create-access-key", "--user-name", user]).args([
            "--query",
            "AccessKey.[AccessKeyId, SecretAccessKey]",
            "--output",
            "text",
        ]),
    )
    .with_context(|| format!("Could not create an access key for {user}. {remove_user}"))?;
    let mut fields = key.split_whitespace();
    let (Some(access_key_id), Some(secret_access_key)) = (fields.next(), fields.next()) else {
        bail!("AWS returned no access key for {user}. {remove_user}");
    };
    println!("Created IAM user {IAM_PATH}{user} and its access key.");

    // New IAM keys and policies take a few seconds to reach S3, so retry only the errors that produces.
    say("Test the upload key");
    println!(
        "Uploading an empty test object exactly as upload-pubkey.sh does. This can take up to 2 minutes."
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let version_id = loop {
        let output = ctx
            .exec
            .output(&upload_test(bucket, access_key_id, secret_access_key))
            .with_context(|| format!("Could not run the test upload. {remove_user}"))?;
        if output.success {
            break output.stdout.trim().to_owned();
        }
        if !propagating(&output.stderr) || Instant::now() >= deadline {
            eprintln!("{}", output.stderr.trim());
            bail!("The new access key could not upload. {remove_user}");
        }
        std::thread::sleep(Duration::from_secs(5));
    };
    println!("The access key can upload.");

    // The key works, so it is shown before anything else can fail.
    say("Setup complete");
    println!("Share these values in a code block over a private channel. Spaces are optional.\n");
    println!("  Bucket:            {bucket}");
    println!("  Access key ID:     {}", group_by_four(access_key_id));
    println!("  Secret access key: {}", group_by_four(secret_access_key));
    println!(
        "\nUpload bucket created successfully! Once the key provisioners no longer need the key, revoke it with {REVOKE}."
    );

    // download-kp-pubkeys refuses a bucket holding anything but uploads, so a test object left behind is caught there.
    say("Delete the test object");
    if version_id.is_empty() || version_id == "None" {
        warn(&format!(
            "The test upload got no version ID, so versioning of s3://{bucket} has not taken effect yet; AWS asks for up to 15 minutes. Delete the test object with: aws s3 rm s3://{bucket}/self-test. Then wait that long before key provisioners upload."
        ));
        return Ok(());
    }
    let deleted = read(
        ctx.exec,
        &aws(&["s3api", "delete-object", "--bucket", bucket])
            .args(["--expected-bucket-owner", &account, "--key", "self-test"])
            .args(["--version-id", &version_id]),
    );
    match deleted {
        Ok(_) => println!("Deleted the test object."),
        Err(error) => warn(&format!(
            "Could not delete version {version_id} of the test object: {error:#}. Delete it before key provisioners upload: aws s3api delete-object --bucket {bucket} --key self-test --version-id {version_id}"
        )),
    }
    Ok(())
}

/// An upload with only the new key, never the operator's own AWS configuration, exactly as `upload-pubkey.sh` does.
fn upload_test(bucket: &str, access_key_id: &str, secret_access_key: &str) -> Cmd {
    [
        "AWS_PROFILE",
        "AWS_DEFAULT_PROFILE",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
    ]
    .into_iter()
    .fold(Cmd::new("aws"), Cmd::env_remove)
    .env("AWS_CONFIG_FILE", "/dev/null")
    .env("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    .env("AWS_ACCESS_KEY_ID", access_key_id)
    .env("AWS_SECRET_ACCESS_KEY", secret_access_key)
    .args([
        "s3api",
        "put-object",
        "--region",
        REGION,
        "--bucket",
        bucket,
    ])
    .args(["--key", "self-test"])
    .args(["--query", "VersionId", "--output", "text"])
    .capture_stderr()
}

/// Whether an upload failed as it does while a new key or policy is still reaching S3.
fn propagating(stderr: &str) -> bool {
    stderr.contains("(InvalidAccessKeyId)") || stderr.contains("(AccessDenied)")
}

/// Deletes the upload user and its keys, so key provisioners can no longer upload, download the configuration or
/// read the guardian's log bucket. The bucket and its files stay.
pub fn revoke_kp_upload_key(ctx: &Ctx) -> Result<()> {
    let kp = KpBucket::from_env(ctx)?;
    if !ctx.ask.interactive() {
        bail!("This step is interactive and must run in a terminal.");
    }
    let (bucket, user) = (&kp.bucket, &kp.iam_user);
    say("Key provisioner upload key revocation");
    println!("This step deletes IAM user {IAM_PATH}{user} and its access keys,");
    println!("so key provisioners can no longer upload to s3://{bucket}, download the guardian");
    println!("configuration from it, or read the guardian's log bucket.");
    println!("The bucket and its files are kept.");

    say("Check the AWS account");
    let (account, arn) = identity(ctx)?;
    println!("AWS account:  {account}\nAWS identity: {arn}");
    let aws = |args: &[&str]| Cmd::new("aws").args(args);
    let path = ctx.exec.output(
        &aws(&["iam", "get-user", "--user-name", user])
            .args(["--query", "User.Path", "--output", "text"])
            .capture_stderr(),
    )?;
    if !path.success {
        if path.stderr.contains("(NoSuchEntity)") {
            println!("\nIAM user {user} does not exist; nothing to revoke.");
            return Ok(());
        }
        bail!("Could not read IAM user {user}: {}", path.stderr.trim());
    }
    // The fixed path marks users this tooling created; never delete anything else.
    let path = path.stdout.trim();
    if path != IAM_PATH {
        bail!("IAM user {user} has path {path}, not {IAM_PATH}; refusing to delete it.");
    }
    let attached = read(
        ctx.exec,
        &aws(&["iam", "list-attached-user-policies", "--user-name", user]).args([
            "--query",
            "AttachedPolicies[].PolicyArn",
            "--output",
            "text",
        ]),
    )
    .with_context(|| format!("Could not list the policies attached to {user}."))?;
    if !attached.trim().is_empty() {
        bail!(
            "IAM user {user} has attached policies ({}), which this tooling never adds; refusing to delete it.",
            attached.trim()
        );
    }
    confirm(
        ctx.ask,
        &format!("Delete IAM user {user} in AWS account {account}?"),
        &Unchanged {
            no_input: "No input received; nothing was deleted.",
            declined: "Revocation not confirmed; nothing was deleted.",
        },
    )?;

    say("Delete the upload key and user");
    let keys = read(
        ctx.exec,
        &aws(&["iam", "list-access-keys", "--user-name", user]).args([
            "--query",
            "AccessKeyMetadata[].AccessKeyId",
            "--output",
            "text",
        ]),
    )
    .with_context(|| format!("Could not list the access keys of {user}."))?;
    for key in keys.split_whitespace() {
        read(
            ctx.exec,
            &aws(&[
                "iam",
                "delete-access-key",
                "--user-name",
                user,
                "--access-key-id",
                key,
            ]),
        )
        .with_context(|| format!("Could not delete access key {key}."))?;
        println!("Deleted access key {key}");
    }
    let policies = read(
        ctx.exec,
        &aws(&["iam", "list-user-policies", "--user-name", user]).args([
            "--query",
            "PolicyNames",
            "--output",
            "text",
        ]),
    )
    .with_context(|| format!("Could not list the inline policies of {user}."))?;
    for policy in policies.split_whitespace() {
        read(
            ctx.exec,
            &aws(&[
                "iam",
                "delete-user-policy",
                "--user-name",
                user,
                "--policy-name",
                policy,
            ]),
        )
        .with_context(|| format!("Could not delete inline policy {policy}."))?;
    }
    read(ctx.exec, &aws(&["iam", "delete-user", "--user-name", user]))
        .with_context(|| format!("Could not delete IAM user {user}."))?;
    println!("Deleted IAM user {IAM_PATH}{user}");

    say("Revocation complete");
    println!("Upload key revoked successfully! The uploaded files remain in s3://{bucket}.");
    Ok(())
}

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
/// beside the user IDs' directories, so none may take its name.
fn kp_file_owner(key: &str) -> Option<String> {
    let (id, file) = key.split_once('/')?;
    let valid_id = id != ROSTER
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
            let dir = out.join(id);
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Could not create {}.", dir.display()))?;
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
            format!("unexpected fingerprint: {fingerprint}"),
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

    fn bundle(id: &str) -> Vec<serde_json::Value> {
        KP_FILE_SUFFIXES
            .iter()
            .map(|suffix| {
                serde_json::json!({ "Key": format!("{id}/{id}-{suffix}"), "VersionId": "1", "IsLatest": true })
            })
            .collect()
    }

    /// A one-slot stack, and a bucket holding `versions` whose certificates verify to `fingerprints`, by user ID.
    fn bucket_world(
        versions: Vec<serde_json::Value>,
        fingerprints: &[(&str, String)],
        verifier: bool,
    ) -> crate::exec::fake::Fake {
        let stack = crate::stack::tests::one_slot();
        let fingerprints: BTreeMap<String, String> = fingerprints
            .iter()
            .map(|(id, fingerprint)| ((*id).to_owned(), fingerprint.clone()))
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
                        format!("{}\n", fingerprints.get(id).cloned().unwrap_or_default())
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
        env.push(("KP_NAME", "testnet"));
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
        let exec = bucket_world(versions, &[("alice", "B".repeat(40))], true);
        let (repo, result) = download(&exec);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("Not every upload verified")
        );
        assert!(!repo.path().join("out/roster.txt").exists());

        let exec = bucket_world(bundle("alice"), &[("alice", "B".repeat(40))], false);
        let (_, result) = download(&exec);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .ends_with("has no tools verify-kp-cert, so it cannot verify uploads.")
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

    fn texts(values: &[std::ffi::OsString]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect()
    }

    /// AWS answering a first setup, where `bucket_exists` and the test upload's and cleanup's results vary.
    fn create(
        bucket_exists: bool,
        upload: crate::exec::Output,
        cleanup_works: bool,
        answers: &[&str],
    ) -> (Result<()>, crate::exec::fake::Fake) {
        let exec = crate::exec::fake::Fake::with_stderr(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            let ok = |stdout: &str| Some(reply(true, stdout, ""));
            match &w[1..3] {
                ["sts", "get-caller-identity"] => {
                    ok("123456789012\tarn:aws:iam::123456789012:user/op\n")
                }
                ["iam", "get-user"] => Some(reply(false, "", "An error occurred (NoSuchEntity)")),
                ["s3api", "head-bucket"] if bucket_exists => ok("{}"),
                ["s3api", "head-bucket"] => Some(reply(
                    false,
                    "",
                    "An error occurred (404) when calling the HeadBucket operation: Not Found",
                )),
                [
                    "s3api",
                    "create-bucket" | "put-public-access-block" | "put-bucket-versioning",
                ]
                | ["iam", "create-user" | "put-user-policy"] => ok("{}"),
                ["iam", "create-access-key"] => ok("AKIDTEST\ttest-secret\n"),
                ["s3api", "put-object"] => {
                    Some(reply(upload.success, &upload.stdout, &upload.stderr))
                }
                ["s3api", "delete-object"] => Some(reply(cleanup_works, "{}", "")),
                _ => None,
            }
        });
        let repo = tempfile::tempdir().unwrap();
        let ask = crate::ask::scripted::Scripted::new(answers);
        let result = create_kp_upload_bucket(
            &Ctx::for_test(repo.path(), &exec, &[("KP_NAME", "testnet")]).with_ask(&ask),
        );
        (result, exec)
    }

    #[test]
    fn creates_an_upload_only_key_and_keeps_it_when_cleanup_fails() {
        let (result, exec) = create(false, reply(true, "v1\n", ""), true, &["yes"]);
        result.unwrap();
        let log = exec.log.borrow();
        let calls: Vec<&str> = log.iter().map(|words| words[2].as_str()).collect();
        assert_eq!(
            calls,
            [
                "get-caller-identity",
                "get-user",
                "head-bucket",
                "create-bucket",
                "put-public-access-block",
                "put-bucket-versioning",
                "create-user",
                "put-user-policy",
                "create-access-key",
                "put-object",
                "delete-object"
            ]
        );
        // The secret reaches the upload only through its environment.
        assert!(
            log.iter()
                .flatten()
                .all(|word| !word.contains("test-secret"))
        );
        drop(log);

        // The key works, so a failed cleanup only warns: download-kp-pubkeys refuses the object it leaves.
        let (result, _) = create(false, reply(true, "v1\n", ""), false, &["yes"]);
        result.unwrap();
        let (result, exec) = create(false, reply(true, "None\n", ""), true, &["yes"]);
        result.unwrap();
        assert!(!exec.ran(&["aws", "s3api", "delete-object"]));
    }

    #[test]
    fn creates_nothing_it_was_not_asked_to() {
        let (result, exec) = create(true, reply(true, "v1\n", ""), true, &["yes"]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("s3://mysten-hashi-kp-pubkeys-testnet already exists.")
        );
        assert!(!exec.ran(&["aws", "s3api", "create-bucket"]));
        let (result, exec) = create(false, reply(true, "v1\n", ""), true, &["no"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Creation not confirmed; nothing was created."
        );
        assert!(!exec.ran(&["aws", "s3api", "create-bucket"]));
        // Only the errors key propagation produces are retried.
        let (result, exec) = create(
            false,
            reply(false, "", "An error occurred (NoSuchBucket)"),
            true,
            &["yes"],
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("The new access key could not upload.")
        );
        assert_eq!(
            exec.log
                .borrow()
                .iter()
                .filter(|words| words[2] == "put-object")
                .count(),
            1
        );
    }

    #[test]
    fn allows_the_upload_key_nothing_but_uploads_outside_config() {
        let policy: serde_json::Value =
            serde_json::from_str(&upload_policy("mysten-hashi-kp-pubkeys-testnet")).unwrap();
        assert_eq!(
            policy,
            serde_json::json!({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::mysten-hashi-kp-pubkeys-testnet/*",
                    },
                    {
                        "Effect": "Deny",
                        "Action": "s3:PutObject",
                        "Resource": "arn:aws:s3:::mysten-hashi-kp-pubkeys-testnet/_config/*",
                    },
                ],
            })
        );
    }

    #[test]
    fn tests_the_new_key_with_nothing_but_it() {
        let cmd = upload_test("bucket", "test-id", "test-secret");
        let removed = texts(cmd.removed_env());
        for name in [
            "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
        ] {
            assert!(removed.contains(&name.to_owned()), "{name}");
        }
        let set: Vec<(String, String)> = cmd
            .set_env()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
            .collect();
        for (name, value) in [
            ("AWS_CONFIG_FILE", "/dev/null"),
            ("AWS_SHARED_CREDENTIALS_FILE", "/dev/null"),
            ("AWS_ACCESS_KEY_ID", "test-id"),
            ("AWS_SECRET_ACCESS_KEY", "test-secret"),
        ] {
            assert!(set.contains(&(name.to_owned(), value.to_owned())), "{name}");
        }
        assert!(propagating(
            "An error occurred (AccessDenied) when calling the PutObject operation"
        ));
        assert!(propagating("An error occurred (InvalidAccessKeyId)"));
        assert!(!propagating("An error occurred (NoSuchBucket)"));
    }

    /// An IAM user with this path and these attached policies, and an operator who answers `answers`.
    fn revoke(
        path_reply: crate::exec::Output,
        attached: &'static str,
        answers: &[&str],
    ) -> (Result<()>, crate::exec::fake::Fake) {
        let path_reply = std::cell::RefCell::new(Some(path_reply));
        let exec = crate::exec::fake::Fake::with_stderr(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            let ok = |stdout: &str| {
                Some(crate::exec::Output {
                    success: true,
                    stdout: stdout.to_owned(),
                    stderr: String::new(),
                })
            };
            match &w[1..3] {
                ["sts", "get-caller-identity"] => {
                    ok("123456789012\tarn:aws:iam::123456789012:user/op\n")
                }
                ["iam", "get-user"] => path_reply.borrow_mut().take(),
                ["iam", "list-attached-user-policies"] => ok(attached),
                ["iam", "list-access-keys"] => ok("KEY1\tKEY2\n"),
                ["iam", "list-user-policies"] => ok("put-kp-pubkeys\tread-guardian-config\n"),
                [
                    "iam",
                    "delete-access-key" | "delete-user-policy" | "delete-user",
                ] => ok(""),
                _ => None,
            }
        });
        let repo = tempfile::tempdir().unwrap();
        let ask = crate::ask::scripted::Scripted::new(answers);
        let result = revoke_kp_upload_key(
            &Ctx::for_test(repo.path(), &exec, &[("KP_NAME", "testnet")]).with_ask(&ask),
        );
        (result, exec)
    }

    fn reply(success: bool, stdout: &str, stderr: &str) -> crate::exec::Output {
        crate::exec::Output {
            success,
            stdout: stdout.to_owned(),
            stderr: stderr.to_owned(),
        }
    }

    #[test]
    fn revokes_only_what_this_tooling_created() {
        let (result, exec) = revoke(
            reply(false, "", "An error occurred (NoSuchEntity)"),
            "",
            &[],
        );
        result.unwrap();
        assert!(!exec.ran(&["aws", "iam", "delete-user"]));

        let (result, _) = revoke(reply(true, "/other/\n", ""), "", &["yes"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "IAM user hashi-kp-pubkeys-testnet-upload has path /other/, not /hashi-kp-pubkeys/; refusing to delete it."
        );
        let (result, _) = revoke(reply(true, "/hashi-kp-pubkeys/\n", ""), "arn:x\n", &["yes"]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("which this tooling never adds")
        );

        let (result, exec) = revoke(reply(true, "/hashi-kp-pubkeys/\n", ""), "", &["no"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Revocation not confirmed; nothing was deleted."
        );
        assert!(!exec.ran(&["aws", "iam", "delete-access-key"]));

        let (result, exec) = revoke(reply(true, "/hashi-kp-pubkeys/\n", ""), "", &["yes"]);
        result.unwrap();
        let log = exec.log.borrow();
        let deletes: Vec<&str> = log
            .iter()
            .filter(|words| words[2].starts_with("delete-"))
            .map(|words| words[2].as_str())
            .collect();
        assert_eq!(
            deletes,
            [
                "delete-access-key",
                "delete-access-key",
                "delete-user-policy",
                "delete-user-policy",
                "delete-user"
            ]
        );
    }
}
