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
use crate::kp_bucket::CONFIG_PREFIX;
use crate::kp_bucket::DigestScheme;
use crate::kp_bucket::REGION;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::holds_access_key;
use crate::kp_bucket::identity;
use crate::kp_bucket::kp_bucket;
use crate::next;
use crate::print_detail;
use crate::print_info;
use crate::print_success;
use crate::print_warning;
use crate::render::Rendered;
use crate::render::SlotRender;
use crate::stack::Slot;
use crate::steps::slot;

/// Writes the slot's configuration, then has the guardian's own tools load it as the ceremony will.
pub fn render(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg)?;
    print_info(&format!(
        "Rendering slot {}'s guardian configuration",
        view.slot
    ));
    let render = SlotRender::new(ctx, &stack, &view)?;
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    let check = guardian_init.has_tool(ctx, "check-config")?;
    std::fs::create_dir_all(&view.dir)?;
    render.rendered.write_unchecked(&view.dir)?;
    if check {
        for config in render.rendered.configs() {
            let path = view.dir.join(Rendered::written(config));
            // The configuration lists certificates relative to its own directory.
            let checked = ctx.exec.output(
                &guardian_init
                    .cmd()
                    .args(["tools", "check-config", "--config"])
                    .arg(path.file_name().unwrap_or_default())
                    .cwd(path.parent().unwrap_or(&view.dir)),
            );
            if !checked.as_ref().is_ok_and(|output| output.success) {
                render.rendered.remove_configs(&view.dir)?;
                checked.with_context(|| {
                    format!("could not run the guardian's tools on {}", path.display())
                })?;
                bail!(
                    "the guardian's tools refuse {}, so no step will run with it; fix what they name, then render again",
                    path.display()
                );
            }
        }
    } else {
        print_warning(
            "This guardian's build has no tools check-config, so its tools have not checked the rendered files.",
        );
    }
    render.rendered.place_configs(&view.dir)?;

    let settings = &render.settings;
    println!("Guardian commit:  {}", settings.commit);
    println!("PCR0:             {}", settings.pcr0);
    println!("Log bucket:       s3://{}", settings.bucket);
    println!("Bitcoin network:  {}", settings.bitcoin_network);
    println!("Retention class:  {}", settings.retention_environment);
    let dir = view.dir.display();
    println!(
        "Key provisioners: {}, any {} provision",
        render.dealt.kp_count(),
        render.dealt.threshold
    );
    println!("For key provisioners: {dir}/guardian-init.yaml");
    println!("For the operator:     {dir}/operator.yaml");
    next(&format!("publish --slot {}", view.slot));
    Ok(())
}

/// Publishes the slot's configuration for key provisioners to the KP bucket's `_config/`, and prints the digest they
/// compare with the operator's post.
pub fn publish(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    if !ctx.ask.interactive() {
        bail!("this publication is interactive and must run in a terminal");
    }
    let (stack, view) = slot(ctx, arg)?;
    let config_dir = &view.dir;
    let config_file = config_dir.join("guardian-init.yaml");
    let config = config_file.display();
    if !config_file.is_file() {
        bail!(
            "no {config}; run the render step for slot {} first",
            view.slot
        );
    }
    // What goes out is this render, which the slot's files are shown to equal, so nothing written to them in between
    // can mix in. The operator's own file is never published, so it doesn't count.
    let render = SlotRender::new(ctx, &stack, &view)?;
    let published: Vec<(&str, &[u8])> = render
        .rendered
        .files()
        .filter(|(path, _)| !path.ends_with("operator.yaml"))
        .collect();
    let stale: Vec<&str> = published
        .iter()
        .filter(|(path, bytes)| {
            std::fs::read(config_dir.join(path)).ok().as_deref() != Some(*bytes)
        })
        .map(|(path, _)| *path)
        .collect();
    if !stale.is_empty() {
        bail!(
            "out of date in {}: {}; the stack, {} or the roster changed after the render step; run it again, then publish",
            config_dir.display(),
            stale.join(", "),
            ctx.env.path().display()
        );
    }
    let guardian_bucket = stack.bucket()?.name;
    let bucket = kp_bucket(ctx)?;
    // Publishing replaces everything under its prefix.
    if bucket == guardian_bucket {
        bail!(
            "KP_BUCKET names the guardian's log bucket, s3://{bucket}; set it to the key provisioners' bucket"
        );
    }
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    // Key provisioners run download-config.sh at the guardian's commit, so this digest must be the one it computes.
    let scheme = DigestScheme::of(&tree)?;
    let guardian_init = tree.guardian_init(ctx)?;
    let commit = &render.settings.commit;

    print_info("Publishing the key provisioners' configuration");
    print_info(&format!(
        "This step publishes {config} and its certificates to s3://{bucket}/{CONFIG_PREFIX}/."
    ));
    print_detail("Key provisioners fetch them with key-provisioner/scripts/download-config.sh.");

    print_info("Verifying the key provisioner certificates");
    let scratch = tempfile::tempdir()?;
    let publish_dir = scratch.path().join(CONFIG_PREFIX);
    for (path, bytes) in &published {
        let to = publish_dir.join(path);
        std::fs::create_dir_all(to.parent().unwrap_or(&publish_dir))?;
        std::fs::write(&to, bytes).with_context(|| format!("could not write {}", to.display()))?;
    }
    let mut count = 0;
    for (path, _) in published
        .iter()
        .filter(|(path, _)| path.starts_with("certs/") && path.ends_with(".asc"))
    {
        let cert = publish_dir.join(path);
        let fingerprint = read(
            ctx.exec,
            &guardian_init
                .cmd()
                .args(["tools", "verify-kp-cert", "--kp-pgp-cert-path"])
                .arg(&cert),
        )
        .with_context(|| format!("certificate {path} did not verify, so nothing was published"))?;
        println!(
            "{}  {}",
            format_fingerprint(fingerprint.trim()),
            path.trim_start_matches("certs/")
                .trim_end_matches("-kp-pubkey.asc")
        );
        count += 1;
    }
    let leaked = files_holding_access_keys(&publish_dir)?;
    if !leaked.is_empty() {
        bail!(
            "found an AWS access key ID, or could not check for one, so nothing was published: {}",
            leaked.join(" ")
        );
    }
    let digest = scheme.digest(&publish_dir)?;
    let digest_lines = scheme.lines(&digest);
    print_detail(&format!(
        "Guardian commit:      {commit}\nKey provisioners:     {count}\nConfiguration digest: {}",
        digest_lines[0]
    ));
    for line in &digest_lines[1..] {
        print_detail(&format!("                      {line}"));
    }

    print_info("Checking the AWS account");
    let (account, arn) = identity(ctx)?;
    print_detail(&format!("AWS account:  {account}\nAWS identity: {arn}"));
    let head_bucket = |bucket: &str| {
        read(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3api", "head-bucket", "--bucket", bucket])
                .args(["--expected-bucket-owner", &account]),
        )
    };
    head_bucket(&bucket).with_context(|| {
        format!("no bucket s3://{bucket} in account {account}; check KP_BUCKET")
    })?;
    head_bucket(&guardian_bucket).with_context(|| {
        format!("no guardian log bucket s3://{guardian_bucket} in account {account}")
    })?;
    confirm(
        ctx.ask,
        &format!("Publish this configuration to s3://{bucket}/{CONFIG_PREFIX}/?"),
        &Unchanged {
            no_input: "no input received; nothing was published",
            declined: "publication not confirmed; nothing was published",
        },
    )?;

    print_info("Uploading the configuration");
    let prefix = format!("s3://{bucket}/{CONFIG_PREFIX}/");
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
    .with_context(|| format!("could not clear {prefix}; publish again"))?;
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
    .with_context(|| format!("could not upload the configuration to {prefix}; publish again"))?;
    print_success(&format!(
        "Published guardian-init.yaml and {count} certificates."
    ));

    print_info("Publication complete");
    print_info("Post the commit and the digest, so each key provisioner can compare them:");
    println!("  Guardian commit:      {commit}");
    println!("  Configuration digest: {}", digest_lines[0]);
    for line in &digest_lines[1..] {
        println!("                        {line}");
    }
    if scheme == DigestScheme::Legacy {
        print_warning(
            "This digest covers guardian-init.yaml alone, so post the fingerprints above too, for each key provisioner to compare with what the download prints.",
        );
    }
    print_info("Every key provisioner runs, from a hashi checkout at that commit:");
    print_detail("  ./key-provisioner/scripts/download-config.sh");
    print_success(&format!(
        "Configuration published successfully! It lists {count} key provisioners."
    ));
    next("the step this configuration is for, once every key provisioner has downloaded it");
    Ok(())
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

    fn world() -> Fake {
        world_uploading(std::rc::Rc::default())
    }

    /// A one-slot stack, and an AWS that accepts the publication and records the files each upload sends.
    fn world_uploading(uploaded: std::rc::Rc<std::cell::RefCell<Vec<String>>>) -> Fake {
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
                "s3_access_key_id": "test-access-key",
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
                ["aws", "s3", "cp", "--recursive", .., source, _] => {
                    let root = Path::new(source.trim_end_matches('/'));
                    let mut files = Vec::new();
                    let mut pending = vec![root.to_owned()];
                    while let Some(dir) = pending.pop() {
                        for entry in std::fs::read_dir(&dir).ok()? {
                            let path = entry.ok()?.path();
                            if path.is_dir() {
                                pending.push(path);
                            } else {
                                files.push(path.strip_prefix(root).ok()?.display().to_string());
                            }
                        }
                    }
                    files.sort();
                    *uploaded.borrow_mut() = files;
                    ok("")
                }
                ["aws", "s3", "rm", ..] => ok(""),
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
            ("KP_BUCKET", "kp-bucket"),
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
            publish(&ctx, None).unwrap_err().to_string(),
            "publication not confirmed; nothing was published"
        );
        assert!(!exec.ran(&["aws", "s3", "rm"]));

        let confirmed = Scripted::new(&["yes"]);
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs).with_ask(&confirmed);
        publish(&ctx, None).unwrap();
        assert_eq!(
            confirmed.prompts.borrow()[0],
            "Publish this configuration to s3://kp-bucket/_config/? [y/N] "
        );
        let log = exec.log.borrow();
        let position = |prefix: &[&str]| {
            log.iter()
                .position(|words| words.iter().zip(prefix).all(|(w, p)| w == p))
                .unwrap()
        };
        assert!(position(&["aws", "s3", "rm"]) < position(&["aws", "s3", "cp"]));
        assert_eq!(
            log[position(&["aws", "s3", "cp"])].last().unwrap(),
            "s3://kp-bucket/_config/"
        );
    }

    #[test]
    fn refuses_what_key_provisioners_could_not_match() {
        let exec = world();
        let repo = tempfile::tempdir().unwrap();
        let env = rendered(repo.path(), &exec, "#!/bin/bash\n# no digest here\n");
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env));
        let error = publish(&ctx, None).unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "download-config.sh at {COMMIT} computes the configuration digest in a way this tool does not"
            )),
            "{error}"
        );

        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env))
            .with_ask(&crate::ask::scripted::NoTerminal);
        assert_eq!(
            publish(&ctx, None).unwrap_err().to_string(),
            "this publication is interactive and must run in a terminal"
        );

        let mut log_bucket = env.clone();
        log_bucket.retain(|(key, _)| key != "KP_BUCKET");
        log_bucket.push(("KP_BUCKET".to_owned(), "guardian-bucket".to_owned()));
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&log_bucket));
        assert!(
            publish(&ctx, None)
                .unwrap_err()
                .to_string()
                .starts_with("KP_BUCKET names the guardian's log bucket")
        );
        assert!(!exec.ran(&["aws", "s3"]));
    }

    #[test]
    fn publishes_the_render_the_slots_files_match_and_nothing_else() {
        let uploaded = std::rc::Rc::default();
        let exec = world_uploading(std::rc::Rc::clone(&uploaded));
        let repo = tempfile::tempdir().unwrap();
        let env = rendered(repo.path(), &exec, DOWNLOAD_CONFIG);
        let dir = repo.path().join(".hashi/guardian/testnet/a");
        // A file the render didn't write isn't published, and the operator's own file doesn't count.
        std::fs::write(dir.join("certs/mallory-kp-pubkey.asc"), "unlisted").unwrap();
        std::fs::write(dir.join("operator.yaml"), "edited").unwrap();
        let confirmed = Scripted::new(&["yes"]);
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env)).with_ask(&confirmed);
        publish(&ctx, None).unwrap();
        let uploaded = uploaded.borrow();
        assert!(uploaded.contains(&"guardian-init.yaml".to_owned()));
        assert!(uploaded.contains(&"certs/alice-kp-pubkey.asc".to_owned()));
        assert!(
            uploaded
                .iter()
                .all(|path| !path.contains("operator") && !path.contains("mallory")),
            "{uploaded:?}"
        );

        std::fs::write(dir.join("certs/alice-kp-pubkey.asc"), "changed").unwrap();
        let exec = world();
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env)).with_ask(&confirmed);
        assert!(
            publish(&ctx, None)
                .unwrap_err()
                .to_string()
                .contains(": certs/alice-kp-pubkey.asc; the stack,")
        );
        assert!(!exec.ran(&["aws"]));
    }

    /// A one-slot stack whose guardian tools print `help`, or fail on `tools --help` without one, and whose
    /// `check-config` succeeds or not.
    fn render_world(help: Option<&'static str>, checked: bool) -> Fake {
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
                "s3_access_key_id": "test-access-key",
            }),
        );
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
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
                    Some((help.is_some(), help.unwrap_or_default().to_owned()))
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

    const CHECKS: &str = "  check-config  Check a configuration\n";

    #[test]
    fn leaves_no_configuration_the_guardians_tools_did_not_check() {
        let (repo, result) = render_slot_a(&render_world(Some(CHECKS), false));
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("the guardian's tools refuse")
        );
        let dir = repo.path().join(".hashi/guardian/testnet/a");
        for config in ["guardian-init.yaml", "operator.yaml"] {
            assert!(!dir.join(config).exists(), "{config}");
            assert!(
                !dir.join(format!("{config}.unchecked")).exists(),
                "{config}"
            );
        }

        // Tools that cannot run stop the step before it writes anything.
        let (repo, result) = render_slot_a(&render_world(None, true));
        assert!(result.is_err());
        assert!(!repo.path().join(".hashi/guardian/testnet/a").exists());

        let (repo, result) = render_slot_a(&render_world(Some(CHECKS), true));
        result.unwrap();
        assert!(
            repo.path()
                .join(".hashi/guardian/testnet/a/operator.yaml")
                .is_file()
        );

        // A build without the check places the files with only a warning.
        let (repo, result) = render_slot_a(&render_world(Some(""), true));
        result.unwrap();
        let dir = repo.path().join(".hashi/guardian/testnet/a");
        assert!(dir.join("guardian-init.yaml").is_file());
        assert!(dir.join("operator.yaml").is_file());
    }
}
