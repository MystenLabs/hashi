// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that write a slot's configuration and hand it to the key provisioners: `render` and `publish`.

use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;
use crate::kp_bucket::ATTESTATION_SUFFIXES;
use crate::kp_bucket::CONFIG_PREFIX;
use crate::kp_bucket::DigestScheme;
use crate::kp_bucket::IAM_PATH;
use crate::kp_bucket::KpBucket;
use crate::kp_bucket::REGION;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::holds_access_key;
use crate::kp_bucket::identity;
use crate::kp_bucket::read_policy;
use crate::next;
use crate::render::SlotRender;
use crate::render::require_fresh;
use crate::say;
use crate::stack::Slot;
use crate::steps::slot;
use crate::warn;

/// Writes the slot's configuration, then has the guardian's own tools load it as the ceremony will.
pub fn render(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "render")?;
    say(&format!(
        "Render slot {}'s guardian configuration",
        view.slot
    ));
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    let render = SlotRender::new(ctx, &stack, &view)?;
    let check = guardian_init.has_tool(ctx, "check-config")?;
    std::fs::create_dir_all(&view.dir)?;
    render.rendered.write(&view.dir)?;
    if check {
        for config in render.rendered.configs() {
            let path = view.dir.join(config);
            // The configuration lists certificates relative to its own directory.
            let checked = ctx.exec.output(
                &guardian_init
                    .cmd()
                    .args(["tools", "check-config", "--config"])
                    .arg(path.file_name().unwrap_or_default())
                    .cwd(path.parent().unwrap_or(&view.dir)),
            );
            if !checked.as_ref().is_ok_and(|output| output.success) {
                render.rendered.remove_operator_configs(&view.dir)?;
                checked.with_context(|| {
                    format!("Could not run the guardian's tools on {}.", path.display())
                })?;
                bail!(
                    "The guardian's tools refuse {}, so no step will run with it. Fix what they name, then render again.",
                    path.display()
                );
            }
        }
    } else {
        warn(
            "This guardian's build has no tools check-config, so its tools have not checked the rendered files.",
        );
    }

    let settings = &render.settings;
    println!("Guardian commit:  {}", settings.commit);
    println!("PCR0:             {}", settings.pcr0);
    println!("Log bucket:       s3://{}", settings.bucket);
    println!("Bitcoin network:  {}", settings.bitcoin_network);
    println!("Retention class:  {}", settings.retention_environment);
    let dir = view.dir.display();
    match &render.new {
        Some(new) => {
            println!(
                "KP-set rotation:  {} key provisioners, any {} sign, re-deal to {}, any {} provision",
                render.dealt.kp_count(),
                render.dealt.threshold,
                new.kp_count(),
                new.threshold
            );
            println!("For the signers:      {dir}/rotate-kp-set/guardian-init.yaml");
            println!("For the re-deal:      {dir}/rotate-kp-set/operator.yaml");
        }
        None => println!(
            "Key provisioners: {}, any {} provision",
            render.dealt.kp_count(),
            render.dealt.threshold
        ),
    }
    println!("For key provisioners: {dir}/guardian-init.yaml");
    println!("For the operator:     {dir}/operator.yaml");
    next(&match render.new {
        Some(_) => format!("publish {} rotate-kp-set", view.slot),
        None => format!("publish {}", view.slot),
    });
    Ok(())
}

/// Publishes the slot's configuration for key provisioners to the KP bucket's `_config/`, or a KP-set rotation's
/// with `rotate_kp_set`, and prints the digest they compare with the operator's post.
pub fn publish(ctx: &Ctx, arg: Option<Slot>, rotate_kp_set: bool) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "publish")?;
    let config_dir = if rotate_kp_set {
        if ctx.env.get("NEW_KP_ROSTER_DIR").is_none() {
            bail!(
                "Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in {} and render again to publish a KP-set rotation.",
                ctx.env.path().display()
            );
        }
        view.dir.join("rotate-kp-set")
    } else {
        view.dir.clone()
    };
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    require_fresh(ctx, &stack, &view)?;
    let guardian_bucket = stack.bucket()?.name;
    let kp = KpBucket::from_env(ctx)?;
    if !ctx.ask.interactive() {
        bail!("This publication is interactive and must run in a terminal.");
    }
    let config_file = config_dir.join("guardian-init.yaml");
    let config = config_file.display();

    say("Key provisioner configuration publication");
    println!(
        "This step publishes {config} and its certificates to s3://{}/{CONFIG_PREFIX}/,",
        kp.bucket
    );
    println!("and lets the key provisioners' access key read them and s3://{guardian_bucket}.");
    println!("Key provisioners fetch them with key-provisioner/scripts/download-config.sh.");

    say("Check the configuration");
    let text = std::fs::read_to_string(&config_file).unwrap_or_default();
    if text.is_empty() {
        bail!("Missing or empty file: {config}");
    }
    // Each key provisioner's copy gets its own certificate path and the shared access key.
    if text
        .lines()
        .any(|line| line.starts_with("kp_pgp_cert_path:") || line.starts_with("s3_credentials:"))
    {
        bail!("{config} sets kp_pgp_cert_path or s3_credentials. Publish a copy without them.");
    }
    if !names_bucket(&text, &guardian_bucket) {
        bail!("{config} does not name the guardian bucket {guardian_bucket}.");
    }
    let Some(commit) = current_build(&text) else {
        bail!(
            "{config} must list current_build before prev_builds, with a full commit as its git_revision."
        );
    };
    // Key provisioners run download-config.sh at the guardian's commit, so this digest must be the one it computes.
    let scheme = DigestScheme::of(&Tree::at(
        ctx,
        commit,
        "the commit the configuration names",
    )?)?;

    say("Verify the key provisioner certificates");
    let scratch = tempfile::tempdir()?;
    let publish_dir = scratch.path().join(CONFIG_PREFIX);
    std::fs::create_dir_all(publish_dir.join("certs"))?;
    std::fs::copy(&config_file, publish_dir.join("guardian-init.yaml"))?;
    let certs_dir = config_dir.join("certs");
    let mut count = 0;
    for name in cert_names(&certs_dir)? {
        if !text.contains(&format!("certs/{name}")) {
            bail!("{config} does not list certs/{name}. Remove the file, or list it.");
        }
        let cert = certs_dir.join(&name);
        let fingerprint = read(
            ctx.exec,
            &guardian_init
                .cmd()
                .args(["tools", "verify-kp-cert", "--kp-pgp-cert-path"])
                .arg(&cert),
        )
        .with_context(|| {
            format!(
                "Certificate {} did not verify, so nothing was published.",
                cert.display()
            )
        })?;
        let stem = name.trim_end_matches(".asc");
        for file in std::iter::once(name.clone()).chain(
            ATTESTATION_SUFFIXES
                .iter()
                .map(|suffix| format!("{stem}.{suffix}")),
        ) {
            std::fs::copy(certs_dir.join(&file), publish_dir.join("certs").join(&file))
                .with_context(|| format!("Could not copy {}.", certs_dir.join(&file).display()))?;
        }
        println!(
            "{}  {}",
            format_fingerprint(fingerprint.trim()),
            name.trim_end_matches("-kp-pubkey.asc")
        );
        count += 1;
    }
    if count == 0 {
        bail!("No certificates in {}.", certs_dir.display());
    }
    for listed in listed_certs(&text) {
        if !publish_dir.join(&listed).is_file() {
            bail!(
                "{config} lists {listed}, which is not in {}. Add the file, or stop listing it.",
                config_dir.display()
            );
        }
    }
    let leaked = files_holding_access_keys(&publish_dir)?;
    if !leaked.is_empty() {
        bail!(
            "Found an AWS access key ID, or could not check for one, so nothing was published: {}",
            leaked.join(" ")
        );
    }
    let digest = scheme.digest(&publish_dir)?;
    let digest_lines = scheme.lines(&digest);
    println!(
        "\nGuardian commit:      {commit}\nKey provisioners:     {count}\nConfiguration digest: {}",
        digest_lines[0]
    );
    for line in &digest_lines[1..] {
        println!("                      {line}");
    }

    say("Check the AWS account");
    let (account, arn) = identity(ctx)?;
    println!("AWS account:  {account}\nAWS identity: {arn}");
    let head_bucket = |bucket: &str| {
        read(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3api", "head-bucket", "--bucket", bucket])
                .args(["--expected-bucket-owner", &account]),
        )
    };
    head_bucket(&kp.bucket).with_context(|| {
        format!(
            "No bucket s3://{} in account {account}. Create it with: operator/scripts/create-kp-upload-bucket.sh {}",
            kp.bucket, kp.name
        )
    })?;
    head_bucket(&guardian_bucket).with_context(|| {
        format!("No guardian log bucket s3://{guardian_bucket} in account {account}.")
    })?;
    let user = ctx.exec.output(
        &Cmd::new("aws")
            .args(["iam", "get-user", "--user-name", &kp.iam_user])
            .args(["--query", "User.Path", "--output", "text"])
            .capture_stderr(),
    )?;
    if !user.success {
        bail!(
            "Could not read IAM user {}: {}",
            kp.iam_user,
            format!("{}{}", user.stdout, user.stderr).trim()
        );
    }
    if user.stdout.trim() != IAM_PATH {
        bail!(
            "IAM user {} has path {}, not {IAM_PATH}.",
            kp.iam_user,
            user.stdout.trim()
        );
    }
    confirm(
        ctx.ask,
        &format!(
            "Publish this configuration to s3://{}/{CONFIG_PREFIX}/?",
            kp.bucket
        ),
        &Unchanged {
            no_input: "No input received; nothing was published.",
            declined: "Publication not confirmed; nothing was published.",
        },
    )?;

    // A bucket made before create-kp-upload-bucket.sh denied this prefix lets the access key write it, so deny it
    // before filling it: the configuration tells every key provisioner which guardian to trust.
    say("Let the access key read the configuration");
    read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["iam", "put-user-policy", "--user-name", &kp.iam_user])
            .args(["--policy-name", "read-guardian-config", "--policy-document"])
            .arg(read_policy(&kp.bucket, &guardian_bucket)),
    )
    .with_context(|| {
        format!(
            "Could not add the read policy to {}. Nothing was published.",
            kp.iam_user
        )
    })?;
    println!(
        "IAM user {} can read s3://{}/{CONFIG_PREFIX}/ and s3://{guardian_bucket}.",
        kp.iam_user, kp.bucket
    );

    say("Publish the configuration");
    let prefix = format!("s3://{}/{CONFIG_PREFIX}/", kp.bucket);
    read(
        ctx.exec,
        &Cmd::new("aws")
            .args([
                "s3",
                "rm",
                "--recursive",
                "--only-show-errors",
                "--region",
                REGION,
            ])
            .arg(&prefix),
    )
    .with_context(|| format!("Could not clear {prefix}. Publish again."))?;
    read(
        ctx.exec,
        &Cmd::new("aws")
            .args([
                "s3",
                "cp",
                "--recursive",
                "--only-show-errors",
                "--region",
                REGION,
            ])
            .arg(format!("{}/", publish_dir.display()))
            .arg(&prefix),
    )
    .with_context(|| format!("Could not upload the configuration to {prefix}. Publish again."))?;
    println!("Published guardian-init.yaml and {count} certificates.");

    say("Publication complete");
    println!("Post the commit and the digest, so each key provisioner can compare them:");
    println!("  Guardian commit:      {commit}");
    println!("  Configuration digest: {}", digest_lines[0]);
    for line in &digest_lines[1..] {
        println!("                        {line}");
    }
    println!("Every key provisioner runs, from a hashi checkout at that commit:");
    println!("  ./key-provisioner/scripts/download-config.sh");
    println!("\nConfiguration published successfully! It lists {count} key provisioners.");
    next(if rotate_kp_set {
        "rotate-kp-set init, once the key provisioners who sign have downloaded it"
    } else {
        "the step this configuration is for, once every key provisioner has downloaded it"
    });
    Ok(())
}

/// Whether the configuration names the guardian's log bucket, exactly.
fn names_bucket(text: &str, bucket: &str) -> bool {
    text.lines().any(|line| {
        line.trim_start()
            .strip_prefix("name:")
            .is_some_and(|value| value.trim().trim_matches('"') == bucket)
    })
}

/// The commit of the first build the configuration lists, `current_build`, as `download-config.sh` reads it.
fn current_build(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let value = line
            .trim_start()
            .strip_prefix("git_revision:")?
            .trim()
            .trim_matches('"');
        crate::stack::is_hex(value, 40).then_some(value)
    })
}

/// Every `certs/<name>.asc` the configuration lists.
fn listed_certs(text: &str) -> Vec<String> {
    text.match_indices("certs/")
        .filter_map(|(start, _)| {
            let rest = &text[start + "certs/".len()..];
            let run = &rest[..rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || "._-".contains(c)))
                .unwrap_or(rest.len())];
            let end = run.rfind(".asc").filter(|end| *end > 0)?;
            Some(format!("certs/{}", &run[..end + ".asc".len()]))
        })
        .collect()
}

fn cert_names(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in
        std::fs::read_dir(dir).with_context(|| format!("No certificates in {}.", dir.display()))?
    {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if name.ends_with(".asc") && !name.starts_with('.') {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

fn files_holding_access_keys(dir: &Path) -> Result<Vec<String>> {
    let mut leaked = Vec::new();
    let mut pending = vec![dir.to_owned()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if holds_access_key(&String::from_utf8_lossy(&std::fs::read(&path)?)) {
                leaked.push(path.display().to_string());
            }
        }
    }
    Ok(leaked)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::ask::scripted::Scripted;
    use crate::exec::Exec;
    use crate::exec::fake::Fake;
    use crate::kp_bucket::DOWNLOAD_CONFIG;
    use crate::render::tests::roster_dir;
    use crate::stack::Stack;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::stack_env;
    use crate::stack::tests::stack_world;

    const FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

    /// A one-slot stack, and an AWS that accepts the publication.
    fn world() -> Fake {
        let stack = stack_world(
            json!({
                "hashi-commit": COMMIT,
                "eif-pcr0": "0c".repeat(48),
                "refill-rate-sats-per-sec": "11574",
                "max-bucket-capacity-sats": "1000000000",
            }),
            json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
            }),
        );
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            let ok = |stdout: &str| Some((true, stdout.to_owned()));
            match w.as_slice() {
                [
                    "pulumi",
                    "-C",
                    _,
                    "stack",
                    "output",
                    "s3_access_key_id",
                    "--stack",
                    _,
                ] => ok("test-access-key\n"),
                [
                    "pulumi",
                    "-C",
                    _,
                    "stack",
                    "output",
                    "s3_secret_access_key",
                    "--show-secrets",
                    "--stack",
                    _,
                ] => ok("test-secret-key\n"),
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                ["cargo", "build", ..] => ok(
                    r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#,
                ),
                ["/x/hashi-guardian-init", "tools", "verify-kp-cert", ..] => {
                    ok(&format!("{FINGERPRINT}\n"))
                }
                ["aws", "sts", "get-caller-identity", ..] => {
                    ok("123456789012\tarn:aws:iam::123456789012:user/op\n")
                }
                ["aws", "s3api", "head-bucket", ..] => ok("{}"),
                ["aws", "iam", "get-user", ..] => ok("/hashi-kp-pubkeys/\n"),
                ["aws", "iam", "put-user-policy", ..]
                | ["aws", "s3", "rm", ..]
                | ["aws", "s3", "cp", ..] => ok(""),
                _ => None,
            }
        })
    }

    /// Renders slot a as the render step would, with `script` as the guardian commit's `download-config.sh`, and
    /// returns the env file's values.
    fn rendered(repo: &Path, exec: &Fake, script: &str) -> Vec<(String, String)> {
        let tree = repo.join(".hashi/guardian-init").join(COMMIT);
        std::fs::create_dir_all(tree.join("key-provisioner/scripts")).unwrap();
        std::fs::write(
            tree.join("key-provisioner/scripts/download-config.sh"),
            script,
        )
        .unwrap();
        let roster = roster_dir(&repo.join("roster"), &["alice", "bob"], "v1");
        let mut env: Vec<(String, String)> = stack_env()
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect();
        for (key, value) in [
            ("KP_NAME", "testnet"),
            ("KP_ROSTER_DIR", roster.as_str()),
            ("KP_THRESHOLD", "2"),
            ("SUI_RPC", "https://fullnode.testnet.sui.io:443"),
            ("HASHI_PACKAGE_ID", "0x1"),
            ("HASHI_OBJECT_ID", "0x2"),
            ("BITCOIN_NETWORK", "signet"),
            ("RETENTION_ENVIRONMENT", "testnet"),
        ] {
            env.push((key.to_owned(), value.to_owned()));
        }
        let ctx = Ctx::for_test(repo, exec, &pairs(&env));
        let stack = Stack::load(&ctx).unwrap();
        let view = stack.slot(&ctx, Slot::A).unwrap();
        SlotRender::new(&ctx, &stack, &view)
            .unwrap()
            .rendered
            .write(&view.dir)
            .unwrap();
        env
    }

    fn pairs(env: &[(String, String)]) -> Vec<(&str, &str)> {
        env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn publishes_only_once_confirmed() {
        let repo = tempfile::tempdir().unwrap();
        let exec = world();
        let env = rendered(repo.path(), &exec, DOWNLOAD_CONFIG);
        let pairs = pairs(&env);

        let declined = Scripted::new(&["no"]);
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs).with_ask(&declined);
        assert_eq!(
            publish(&ctx, None, false).unwrap_err().to_string(),
            "Publication not confirmed; nothing was published."
        );
        assert!(!exec.ran(&["aws", "iam", "put-user-policy"]));
        assert!(!exec.ran(&["aws", "s3", "rm"]));

        let confirmed = Scripted::new(&["yes"]);
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs).with_ask(&confirmed);
        publish(&ctx, None, false).unwrap();
        assert_eq!(
            confirmed.prompts.borrow()[0],
            "Publish this configuration to s3://mysten-hashi-kp-pubkeys-testnet/_config/? Type y/yes to continue: "
        );
        let log = exec.log.borrow();
        let position = |prefix: &[&str]| {
            log.iter()
                .position(|words| words.iter().zip(prefix).all(|(w, p)| w == p))
                .unwrap()
        };
        // The deny on _config/ lands before anything is uploaded under it.
        assert!(position(&["aws", "iam", "put-user-policy"]) < position(&["aws", "s3", "rm"]));
        assert!(position(&["aws", "s3", "rm"]) < position(&["aws", "s3", "cp"]));
        assert_eq!(
            log[position(&["aws", "s3", "cp"])].last().unwrap(),
            "s3://mysten-hashi-kp-pubkeys-testnet/_config/"
        );
    }

    #[test]
    fn refuses_what_key_provisioners_could_not_match() {
        let exec = world();
        let repo = tempfile::tempdir().unwrap();
        let env = rendered(repo.path(), &exec, "#!/bin/bash\n# no digest here\n");
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env));
        let error = publish(&ctx, None, false).unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "download-config.sh at {COMMIT} computes the configuration digest in a way this tool does not"
            )),
            "{error}"
        );

        let repo = tempfile::tempdir().unwrap();
        let env = rendered(repo.path(), &exec, DOWNLOAD_CONFIG);
        let certs = repo.path().join(".hashi/guardian/testnet/a/certs");
        std::fs::write(certs.join("mallory-kp-pubkey.asc"), "unlisted").unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env));
        let error = publish(&ctx, None, false).unwrap_err().to_string();
        assert!(
            error.ends_with(
                "does not list certs/mallory-kp-pubkey.asc. Remove the file, or list it."
            ),
            "{error}"
        );
        assert!(
            publish(&ctx, None, true)
                .unwrap_err()
                .to_string()
                .starts_with("Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD")
        );
    }

    #[test]
    fn reads_the_configuration_as_key_provisioners_do() {
        let text = format!(
            "deployment:\n  bucket_info:\n    name: \"guardian-bucket\"\n  pcr_allowlist:\n    current_build:\n      git_revision: \"{COMMIT}\"\n    prev_builds:\n      - git_revision: \"{}\"\nkp_roster:\n  kp_pgp_cert_paths:\n    - certs/alice-kp-pubkey.asc\n    - certs/bob-kp-pubkey.asc\n",
            "1".repeat(40)
        );
        assert_eq!(current_build(&text), Some(COMMIT));
        assert!(names_bucket(&text, "guardian-bucket"));
        assert!(!names_bucket(&text, "guardian"));
        assert_eq!(
            listed_certs(&text),
            ["certs/alice-kp-pubkey.asc", "certs/bob-kp-pubkey.asc"]
        );
    }

    /// A one-slot stack whose guardian tools answer `tools --help` and `check-config` with these successes.
    fn render_world(help: bool, checked: bool) -> Fake {
        let stack = stack_world(
            json!({
                "hashi-commit": COMMIT,
                "eif-pcr0": "0c".repeat(48),
                "refill-rate-sats-per-sec": "11574",
                "max-bucket-capacity-sats": "1000000000",
            }),
            json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
            }),
        );
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "stack", "output", "s3_access_key_id", ..] => {
                    Some((true, "test-access-key\n".to_owned()))
                }
                ["pulumi", "-C", _, "stack", "output", "s3_secret_access_key", ..] => {
                    Some((true, "test-secret-key\n".to_owned()))
                }
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                ["cargo", "build", ..] => Some((
                    true,
                    r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#
                        .to_owned(),
                )),
                ["/x/hashi-guardian-init", "tools", "--help"] => {
                    Some((help, "  check-config  Check a configuration\n".to_owned()))
                }
                ["/x/hashi-guardian-init", "tools", "check-config", ..] => {
                    Some((checked, String::new()))
                }
                _ => None,
            }
        })
    }

    fn render_slot_a(exec: &Fake) -> (tempfile::TempDir, Result<()>) {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let roster = roster_dir(&repo.path().join("roster"), &["alice", "bob"], "v1");
        let mut env = stack_env();
        env.extend([
            ("KP_ROSTER_DIR", roster.as_str()),
            ("KP_THRESHOLD", "2"),
            ("SUI_RPC", "https://fullnode.testnet.sui.io:443"),
            ("HASHI_PACKAGE_ID", "0x1"),
            ("HASHI_OBJECT_ID", "0x2"),
            ("BITCOIN_NETWORK", "signet"),
            ("RETENTION_ENVIRONMENT", "testnet"),
        ]);
        let result = render(&Ctx::for_test(repo.path(), exec, &env), None);
        (repo, result)
    }

    #[test]
    fn leaves_no_operator_file_the_guardians_tools_did_not_check() {
        let (repo, result) = render_slot_a(&render_world(true, false));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("The guardian's tools refuse")
        );
        let dir = repo.path().join(".hashi/guardian/testnet/a");
        assert!(dir.join("guardian-init.yaml").is_file());
        assert!(!dir.join("operator.yaml").exists());

        // Tools that cannot run stop the step before it writes anything.
        let (repo, result) = render_slot_a(&render_world(false, true));
        assert!(result.is_err());
        assert!(!repo.path().join(".hashi/guardian/testnet/a").exists());

        let (repo, result) = render_slot_a(&render_world(true, true));
        result.unwrap();
        assert!(
            repo.path()
                .join(".hashi/guardian/testnet/a/operator.yaml")
                .is_file()
        );
    }
}
