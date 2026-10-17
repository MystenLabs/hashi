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
use crate::guardian::require_reached;
use crate::kp_bucket::CONFIG_PREFIX;
use crate::kp_bucket::DigestScheme;
use crate::kp_bucket::REGION;
use crate::kp_bucket::format_fingerprint;
use crate::kp_bucket::holds_access_key;
use crate::kp_bucket::identity;
use crate::kp_bucket::kp_bucket;
use crate::next;
use crate::render::Rendered;
use crate::render::SlotRender;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::steps::rotate::require_keeps_serving;
use crate::steps::rotate::require_lists_log_builds;
use crate::steps::rotate_kp_set::re_deal_step;
use crate::steps::slot;
use crate::warn;

/// Writes the slot's configuration, then has the guardian's own tools load it as the ceremony will.
pub fn render(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "render")?;
    require_re_deal_standby(ctx, &view)?;
    say(&format!(
        "Render slot {}'s guardian configuration",
        view.slot
    ));
    let render = SlotRender::new(ctx, &stack, &view)?;
    if view.slot != stack.active()? {
        require_keeps_serving(ctx, &stack, &view, &render.settings)?;
    } else {
        require_lists_log_builds(ctx, &stack, &view, &render.settings, Vec::new())?;
    }
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
    render.rendered.place_configs(&view.dir)?;

    let settings = &render.settings;
    println!("Guardian commit:  {}", settings.commit);
    println!("PCR0:             {}", settings.pcr0);
    for build in &settings.prev_builds {
        println!("Earlier build:    {}, PCR0 {}", build.commit, build.pcr0);
    }
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
    if !ctx.ask.interactive() {
        bail!("This publication is interactive and must run in a terminal.");
    }
    let (stack, view) = slot(ctx, arg, "publish")?;
    require_re_deal_standby(ctx, &view)?;
    let prefix = if rotate_kp_set {
        if ctx.env.get("NEW_KP_ROSTER_DIR").is_none() {
            bail!(
                "Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in {} and render again to publish a KP-set rotation.",
                ctx.env.path().display()
            );
        }
        "rotate-kp-set/"
    } else {
        ""
    };
    let config_dir = view.dir.join(prefix);
    let config_file = config_dir.join("guardian-init.yaml");
    let config = config_file.display();
    if !config_file.is_file() {
        bail!(
            "No {config}. Run the render step for slot {} first.",
            view.slot
        );
    }
    // What goes out is this render, which the slot's files are shown to equal, so nothing written to them in between
    // can mix in. The operator's own files are never published, so they don't count.
    let render = SlotRender::new(ctx, &stack, &view)?;
    let published = published(&render.rendered, rotate_kp_set);
    let stale: Vec<&str> = published
        .iter()
        .filter(|(path, bytes)| {
            std::fs::read(config_dir.join(path)).ok().as_deref() != Some(*bytes)
        })
        .map(|(path, _)| *path)
        .collect();
    if !stale.is_empty() {
        bail!(
            "Out of date in {}: {}. The stack, {} or the roster changed after the render step. Run it again, then publish.",
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
            "KP_BUCKET names the guardian's log bucket, s3://{bucket}. Set it to the key provisioners' bucket."
        );
    }
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    // A re-deal's signers sign before `submit`, and the new set confirms once its proposal is out.
    let re_deal_stage = || -> Result<()> {
        if ctx.env.get("NEW_KP_ROSTER_DIR").is_none() {
            return Ok(());
        }
        let slot = view.slot;
        let lifecycle = require_reached(ctx, &stack, &view, &tree)?.info.lifecycle;
        let next = re_deal_step(&lifecycle, slot);
        if rotate_kp_set && !lifecycle.is("none") && !lifecycle.is("ceremony/OPERATOR_INITIALIZED")
        {
            bail!(
                "Slot {slot}'s guardian is {lifecycle}. The signers' configuration goes out before rotate-kp-set {slot} submit. Next: {next}."
            );
        }
        if !rotate_kp_set && !lifecycle.is("ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS") {
            bail!(
                "Slot {slot}'s guardian is {lifecycle}. During a re-deal, the new set's configuration goes out once rotate-kp-set {slot} submit logs `ceremony proposal published`. Next: {next}."
            );
        }
        Ok(())
    };
    re_deal_stage()?;
    // Key provisioners run download-config.sh at the guardian's commit, so this digest must be the one it computes.
    let scheme = DigestScheme::of(&tree)?;
    let guardian_init = tree.guardian_init(ctx)?;
    let commit = &render.settings.commit;

    say("Key provisioner configuration publication");
    println!(
        "This step publishes {config} and its certificates to s3://{bucket}/{CONFIG_PREFIX}/."
    );
    println!("Key provisioners fetch them with key-provisioner/scripts/download-config.sh.");

    say("Verify the key provisioner certificates");
    let scratch = tempfile::tempdir()?;
    let publish_dir = scratch.path().join(CONFIG_PREFIX);
    for (path, bytes) in &published {
        let to = publish_dir.join(path);
        std::fs::create_dir_all(to.parent().unwrap_or(&publish_dir))?;
        std::fs::write(&to, bytes).with_context(|| format!("Could not write {}.", to.display()))?;
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
        .with_context(|| format!("Certificate {path} did not verify, so nothing was published."))?;
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
    head_bucket(&bucket).with_context(|| {
        format!("No bucket s3://{bucket} in account {account}. Check KP_BUCKET.")
    })?;
    head_bucket(&guardian_bucket).with_context(|| {
        format!("No guardian log bucket s3://{guardian_bucket} in account {account}.")
    })?;
    confirm(
        ctx.ask,
        &format!("Publish this configuration to s3://{bucket}/{CONFIG_PREFIX}/?"),
        &Unchanged {
            no_input: "No input received; nothing was published.",
            declined: "Publication not confirmed; nothing was published.",
        },
    )?;
    // The question can wait any time, while another terminal moves a re-deal on.
    re_deal_stage()?;

    say("Publish the configuration");
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
    if scheme == DigestScheme::Legacy {
        println!(
            "This digest covers guardian-init.yaml alone, so post the fingerprints above too, for each key provisioner to compare with what the download prints."
        );
    }
    println!("Every key provisioner runs, from a hashi checkout at that commit:");
    println!("  ./key-provisioner/scripts/download-config.sh");
    println!("\nConfiguration published successfully! It lists {count} key provisioners.");
    next(&if rotate_kp_set {
        format!(
            "rotate-kp-set {} init, once the key provisioners who sign have downloaded it",
            view.slot
        )
    } else {
        "the step this configuration is for, once every key provisioner has downloaded it"
            .to_owned()
    });
    Ok(())
}

/// Stops while `NEW_KP_ROSTER_DIR` is set unless the slot is the standby the KP-set rotation re-deals on: any other slot
/// would render the new set, which holds no shares until the re-deal completes.
fn require_re_deal_standby(ctx: &Ctx, view: &SlotView) -> Result<()> {
    if ctx.env.get("NEW_KP_ROSTER_DIR").is_some() && view.role != Role::Standby {
        bail!(
            "{} sets NEW_KP_ROSTER_DIR for a KP-set rotation, which re-deals on a standby, and slot {} is the {}. Render and publish only the standby until the re-deal completes.",
            ctx.env.path().display(),
            view.slot,
            view.role
        );
    }
    Ok(())
}

/// What `publish` sends, by its path under the KP bucket's prefix: the slot's own files, or with `rotate_kp_set` the
/// re-deal's. The operator's files never go out.
fn published(rendered: &Rendered, rotate_kp_set: bool) -> Vec<(&str, &[u8])> {
    let prefix = if rotate_kp_set { "rotate-kp-set/" } else { "" };
    rendered
        .files()
        .filter_map(|(path, bytes)| {
            let path = path.strip_prefix(prefix)?;
            let own = rotate_kp_set || !path.starts_with("rotate-kp-set/");
            (own && !path.ends_with("operator.yaml")).then_some((path, bytes))
        })
        .collect()
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
            publish(&ctx, None, false).unwrap_err().to_string(),
            "Publication not confirmed; nothing was published."
        );
        assert!(!exec.ran(&["aws", "s3", "rm"]));

        let confirmed = Scripted::new(&["yes"]);
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs).with_ask(&confirmed);
        publish(&ctx, None, false).unwrap();
        assert_eq!(
            confirmed.prompts.borrow()[0],
            "Publish this configuration to s3://kp-bucket/_config/? Type y/yes to continue: "
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
        let interactive = Ctx::for_test(repo.path(), &exec, &pairs(&env));
        let error = publish(&interactive, None, false).unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "download-config.sh at {COMMIT} computes the configuration digest in a way this tool does not"
            )),
            "{error}"
        );

        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&env))
            .with_ask(&crate::ask::scripted::NoTerminal);
        assert_eq!(
            publish(&ctx, None, false).unwrap_err().to_string(),
            "This publication is interactive and must run in a terminal."
        );
        assert!(
            publish(&interactive, None, true)
                .unwrap_err()
                .to_string()
                .starts_with("Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD")
        );

        let mut log_bucket = env.clone();
        log_bucket.retain(|(key, _)| key != "KP_BUCKET");
        log_bucket.push(("KP_BUCKET".to_owned(), "guardian-bucket".to_owned()));
        let ctx = Ctx::for_test(repo.path(), &exec, &pairs(&log_bucket));
        assert!(
            publish(&ctx, None, false)
                .unwrap_err()
                .to_string()
                .starts_with("KP_BUCKET names the guardian's log bucket")
        );
        assert!(!exec.ran(&["aws", "s3"]));
    }

    #[test]
    fn publishes_each_re_deal_configuration_with_its_own_certificates() {
        use crate::render::Roster;
        let scratch = tempfile::tempdir().unwrap();
        let dealt = Roster::load(
            &roster_dir(&scratch.path().join("dealt"), &["alice", "bob"], "v1"),
            2,
        )
        .unwrap();
        let new = Roster::load(
            &roster_dir(&scratch.path().join("new"), &["alice", "carol"], "v1"),
            2,
        )
        .unwrap();
        let rendered =
            Rendered::new(&crate::render::tests::settings(), &dealt, Some(&new)).unwrap();
        let paths = |rotate_kp_set| -> Vec<String> {
            published(&rendered, rotate_kp_set)
                .into_iter()
                .map(|(path, _)| path.to_owned())
                .collect()
        };
        // The signers' configuration lists both sets, so every certificate in either goes with it.
        let signers = paths(true);
        for id in ["alice", "bob", "carol"] {
            assert!(
                signers.contains(&format!("certs/{id}-kp-pubkey.asc")),
                "{id}"
            );
        }
        // The new set's lists only that set.
        let new_set = paths(false);
        assert!(new_set.contains(&"certs/carol-kp-pubkey.asc".to_owned()));
        assert!(!new_set.contains(&"certs/bob-kp-pubkey.asc".to_owned()));
        for paths in [signers, new_set] {
            assert!(paths.contains(&"guardian-init.yaml".to_owned()));
            assert!(
                paths
                    .iter()
                    .all(|path| !path.contains("operator") && !path.starts_with("rotate-kp-set/")),
                "{paths:?}"
            );
        }
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
        publish(&ctx, None, false).unwrap();
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
            publish(&ctx, None, false)
                .unwrap_err()
                .to_string()
                .contains(": certs/alice-kp-pubkey.asc. The stack,")
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
                // A first deployment's log holds no session yet.
                ["aws", "s3api", "list-objects-v2", .., "--prefix", "init/", "--query", _, "--output", "json"] => {
                    Some((true, "[]\n".to_owned()))
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
                .starts_with("The guardian's tools refuse")
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
