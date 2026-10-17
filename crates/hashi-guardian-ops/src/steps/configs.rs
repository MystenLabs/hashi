// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The step that writes a slot's configuration for the operator and the key provisioners: `render`.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::commit::Tree;
use crate::render::Rendered;
use crate::render::SlotRender;
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::exec::Cmd;
    use crate::exec::Exec;
    use crate::exec::fake::Fake;
    use crate::render::tests::roster_dir;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::stack_env;
    use crate::stack::tests::stack_world;

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
