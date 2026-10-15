// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian's infrastructure: `measure` its build, `deploy` the enclave stack and roll the `proxy`.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::exec::Cmd;
use crate::exec::read;
use crate::github;
use crate::guardian::proxy_health;
use crate::next;
use crate::plan::preview;
use crate::plan::up;
use crate::say;
use crate::stack::Slot;
use crate::stack::Stack;
use crate::stack::pulumi;
use crate::steps::slot;
use crate::warn;

/// Has hashi's guardian-enclave workflow measure the slot's commit on two runners, or checks run `run_id`, and stops
/// unless both agree on the PCR0 the stack configures.
pub fn measure(ctx: &Ctx, arg: Option<Slot>, run_id: Option<String>) -> Result<()> {
    const REPO: &str = "MystenLabs/hashi";
    let (_, view) = slot(ctx, arg, "measure")?;
    say(&format!(
        "Measure slot {}'s guardian build at {}",
        view.slot, view.commit
    ));
    let run_id = match run_id {
        Some(run_id) => run_id,
        None => {
            github::require_run_urls(ctx)?;
            github::dispatch(
                ctx,
                REPO,
                "guardian-enclave.yml",
                "main",
                &[("git_revision", &view.commit)],
            )?
        }
    };
    if run_id.is_empty() || !run_id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Could not tell which run measures the build: {run_id}");
    }
    println!("Measurement run: https://github.com/{REPO}/actions/runs/{run_id}");
    github::watch(ctx, REPO, &run_id).context("The measurement run did not succeed.")?;
    // The run builds whatever commit and features it was given, so check it built this one on both runners.
    let log = read(
        ctx.exec,
        &Cmd::new("gh").args(["run", "view", &run_id, "--repo", REPO, "--log"]),
    )
    .with_context(|| format!("Could not read the log of run {run_id}."))?;
    github::require_canonical_build(&log, &run_id, &view.commit)?;
    let downloads = tempfile::tempdir()?;
    read(
        ctx.exec,
        &Cmd::new("gh")
            .args(["run", "download", &run_id, "--repo", REPO])
            .args(["--pattern", "nitro-pcrs-*", "--dir"])
            .arg(downloads.path()),
    )
    .with_context(|| format!("Could not download the measurements of run {run_id}."))?;
    let mut pcrs = Vec::new();
    for entry in std::fs::read_dir(downloads.path())? {
        let path = entry?.path().join("nitro.pcrs");
        if path.is_file() {
            pcrs.push(std::fs::read_to_string(path)?);
        }
    }
    let measured = github::agreed_pcr0(&pcrs)?;
    println!("PCR0: {measured}");
    // The watch takes minutes, during which the operator may set the key it compares.
    let stack = Stack::load(ctx)?;
    let configured = stack.config(&view.pcr0_key);
    if configured != Some(measured.as_str()) {
        bail!(
            "Stack {} has {} {}. Set it to the PCR0 above in its Pulumi.<stack>.yaml.",
            stack.name,
            view.pcr0_key,
            configured.unwrap_or("unset")
        );
    }
    println!(
        "It is the {} stack {} configures.",
        view.pcr0_key, stack.name
    );
    next(&format!(
        "deploy, or arm {} next to a serving guardian",
        view.slot
    ));
    Ok(())
}

/// Builds the proxy at the active slot's commit and applies the proxy stack, through sui-operations' proxy workflow.
pub fn proxy(ctx: &Ctx) -> Result<()> {
    const REPO: &str = "MystenLabs/sui-operations";
    let stack = Stack::load(ctx)?;
    // The proxy serves nodes for the active slot, so it runs that slot's build.
    let active = match stack.output("active_slot").or(stack.config("active-slot")) {
        Some("b") => Slot::B,
        _ => Slot::A,
    };
    let view = stack.slot(ctx, active)?;
    say(&format!("Roll the guardian proxy to {}", view.commit));
    let url = ctx.env.proxy_url()?.url;
    github::require_run_urls(ctx)?;
    // The workflow builds the image and applies the proxy stack from the sui-operations ref it runs on.
    let sui_operations_ref = ctx.env.get("SUI_OPERATIONS_REF").unwrap_or("main");
    println!("Proxy stack configuration: sui-operations {sui_operations_ref}");
    warn(
        "Rolling a proxy that is serving takes the guardian's address down while it restarts, and drops the shares key provisioners have sent in a provisioning round that has not finished.",
    );
    confirm(
        ctx.ask,
        &format!("Roll the proxy of {}?", stack.short_name()),
        &Unchanged {
            no_input: "No input received; nothing was rolled.",
            declined: "Not confirmed; nothing was rolled.",
        },
    )?;
    let run_id = github::dispatch(
        ctx,
        REPO,
        "hashi-guardian-proxy-deploy.yaml",
        sui_operations_ref,
        &[("env", stack.short_name()), ("hashi_commit", &view.commit)],
    )?;
    println!("Proxy deploy run: https://github.com/{REPO}/actions/runs/{run_id}");
    github::watch(ctx, REPO, &run_id).context("The proxy deploy did not succeed.")?;
    proxy_health(ctx)
        .with_context(|| format!("The proxy deployed but {url}/health does not answer."))?;
    println!("The proxy answers at {url}.");
    next(&format!(
        "tunnel {}, left running in its own terminal; then info {}",
        view.slot, view.slot
    ));
    Ok(())
}

/// Applies the whole enclave stack. An untargeted up re-renders every slot it plans, so it refuses a stack with two
/// slots, and has the operator name every guardian instance it could destroy.
pub fn deploy(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    say(&format!("Deploy the guardian enclave stack {}", stack.name));
    if stack.slots()?.len() > 1 {
        bail!(
            "Stack {} has two guardian slots. The deploy step runs an untargeted pulumi up, which can replace either guardian: use arm, switchover and teardown, as operator/rotate.md describes.",
            stack.name
        );
    }
    let plan = preview(ctx, &stack.dir, &stack.name, None)?;
    let changed: Vec<_> = plan.steps.iter().filter(|step| step.op != "same").collect();
    for step in &changed {
        let parts: Vec<&str> = step.urn.split("::").collect();
        println!(
            "  {}  {}",
            step.op,
            parts[parts.len().saturating_sub(2)..].join("  ")
        );
    }
    println!(
        "{}",
        plan.change_summary
            .iter()
            .map(|(op, count)| format!("{count} {op}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if changed.is_empty() {
        println!("Nothing to change.");
        return Ok(());
    }

    // The plan leaves out an instance it deletes because the log bucket it depends on is replaced, so any change is
    // taken to risk every instance the stack has. An enclave holds the only live copy of its key, and naming each
    // instance is the consent to lose it.
    let existing = instance_ids(ctx, &stack)
        .with_context(|| format!("Could not read the instances of stack {}.", stack.name))?;
    if existing.is_empty() {
        confirm(
            ctx.ask,
            &format!("Apply this plan to {}?", stack.name),
            &NOTHING_CHANGED,
        )?;
    } else {
        warn(
            "This plan can destroy the guardian instances below. A destroyed guardian's key is gone from memory for good: it needs every step from provisioning again, or from the ceremony if the log bucket changes too.",
        );
        for id in &existing {
            confirm_typed(ctx.ask, id, "to destroy that guardian", &NOTHING_CHANGED)?;
        }
    }
    let applied = up(ctx, &stack.dir, &stack.name, None)?;
    let outcome = if applied {
        "Deployed, but"
    } else {
        "The deploy did not finish, and"
    };
    // Rotation state describes earlier instances, so it is stale once none of them is left. A deploy that fails
    // partway can already have destroyed them, so this runs either way.
    let remaining = instance_ids(ctx, &stack).with_context(|| {
        format!(
            "{outcome} could not read the instances of stack {}.",
            stack.name
        )
    })?;
    if !existing.iter().any(|id| remaining.contains(id)) {
        let tags = stack.rotation_tags(ctx).with_context(|| {
            format!("{outcome} could not list the stack's rotation tags. Clear them before the next rotation.")
        })?;
        for tag in tags {
            read(
                ctx.exec,
                &pulumi(&stack.dir).args(["stack", "tag", "rm", &tag, "--stack", &stack.name]),
            )
            .with_context(|| {
                format!("{outcome} could not clear {tag}. Clear it before the next rotation.")
            })?;
        }
    }
    if !applied {
        bail!("The deploy did not finish. Preview the stack before running this step again.");
    }
    println!(
        "\nDeployed. The host builds the enclave image at boot; follow it with the host step."
    );
    next("host");
    Ok(())
}

fn instance_ids(ctx: &Ctx, stack: &Stack) -> Result<Vec<String>> {
    Ok(stack
        .instances(ctx)?
        .into_iter()
        .filter_map(|instance| instance.id)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use serde_json::json;

    use super::*;
    use crate::ask::scripted::Scripted;
    use crate::exec::Cmd;
    use crate::exec::Exec;
    use crate::exec::fake::Fake;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::stack_env;
    use crate::stack::tests::stack_world;

    const URN_A: &str = "urn:pulumi:testnet::hashi-guardian-enclave::aws:ec2/instance:Instance::hashi-guardian-enclave-a";

    struct State {
        instances: Vec<&'static str>,
        tags: Vec<&'static str>,
    }

    /// A one-slot stack planning `plan`, whose up leaves `after` and succeeds or not.
    fn world(
        two_slots: bool,
        before: &[&'static str],
        plan: &[(&'static str, &'static str)],
        after: &[&'static str],
        up_succeeds: bool,
    ) -> (Fake, Rc<RefCell<State>>) {
        let config = if two_slots {
            json!({ "hashi-commit": COMMIT, "hashi-commit-b": COMMIT, "slot-b-enabled": "true" })
        } else {
            json!({ "hashi-commit": COMMIT })
        };
        let stack = stack_world(config, json!({}));
        let state = Rc::new(RefCell::new(State {
            instances: before.to_vec(),
            tags: vec!["rotation:active-slot"],
        }));
        // The enclave stack references no other stack, so its previews hold no read step.
        let mut steps: Vec<serde_json::Value> = plan
            .iter()
            .map(|(op, urn)| json!({ "op": op, "urn": urn }))
            .collect();
        steps.push(json!({ "op": "same", "urn": "urn:pulumi:testnet::hashi-guardian-enclave::pulumi:pulumi:Stack::hashi-guardian-enclave-testnet" }));
        let plan = json!({ "steps": steps, "changeSummary": { "same": 15 } }).to_string();
        let after = after.to_vec();
        let shared = state.clone();
        let exec = Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match &w[3..] {
                ["preview", "--stack", _, "--json"] => Some((true, plan.clone())),
                ["up", "--stack", _, "--yes"] => {
                    shared.borrow_mut().instances = after.clone();
                    Some((up_succeeds, String::new()))
                }
                ["stack", "export", "--stack", _] => {
                    let resources: Vec<_> = shared
                        .borrow()
                        .instances
                        .iter()
                        .map(|id| json!({ "type": "aws:ec2/instance:Instance", "urn": URN_A, "id": id }))
                        .collect();
                    Some((
                        true,
                        json!({ "deployment": { "manifest": { "version": "v3.148.0" }, "resources": resources } })
                            .to_string(),
                    ))
                }
                ["stack", "tag", "ls", "--stack", _, "--json"] => {
                    let tags: serde_json::Map<String, serde_json::Value> = shared
                        .borrow()
                        .tags
                        .iter()
                        .map(|tag| ((*tag).to_owned(), json!("x")))
                        .collect();
                    Some((true, serde_json::Value::Object(tags).to_string()))
                }
                ["stack", "tag", "rm", tag, "--stack", _] => {
                    shared.borrow_mut().tags.retain(|kept| kept != tag);
                    Some((true, String::new()))
                }
                _ => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
            }
        });
        (exec, state)
    }

    fn run(exec: &Fake, answers: &[&str]) -> (Result<()>, Vec<String>) {
        let repo = tempfile::tempdir().unwrap();
        let ask = Scripted::new(answers);
        let ctx = Ctx::for_test(repo.path(), exec, &stack_env()).with_ask(&ask);
        let result = deploy(&ctx);
        let prompts = ask.prompts.borrow().clone();
        (result, prompts)
    }

    #[test]
    fn refuses_a_stack_with_two_slots() {
        let (exec, _) = world(true, &[], &[("create", URN_A)], &[], true);
        let (result, _) = run(&exec, &[]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("Stack mysten/testnet has two guardian slots.")
        );
        assert!(!exec.ran(&["pulumi", "-C", "/ops/hashi-guardian-enclave", "preview"]));
    }

    #[test]
    fn changes_nothing_when_nothing_changes() {
        let (exec, _) = world(false, &["i-0aaa"], &[], &["i-0aaa"], true);
        let (result, prompts) = run(&exec, &[]);
        result.unwrap();
        assert!(prompts.is_empty());
        assert!(!exec.ran(&["pulumi", "-C", "/ops/hashi-guardian-enclave", "up"]));
    }

    #[test]
    fn has_the_operator_name_every_instance_it_could_destroy() {
        let (exec, _) = world(
            false,
            &["i-0aaa"],
            &[("update", "urn:x::bucket")],
            &["i-0aaa"],
            true,
        );
        let (result, prompts) = run(&exec, &["i-0aab"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "Not confirmed; nothing was changed."
        );
        assert_eq!(prompts, ["Type i-0aaa to destroy that guardian: "]);
        assert!(!exec.ran(&["pulumi", "-C", "/ops/hashi-guardian-enclave", "up"]));

        let (exec, state) = world(
            false,
            &["i-0aaa"],
            &[("update", "urn:x::bucket")],
            &["i-0aaa"],
            true,
        );
        let (result, _) = run(&exec, &["i-0aaa"]);
        result.unwrap();
        // The guardian survived, so its rotation state still describes it.
        assert_eq!(state.borrow().tags, ["rotation:active-slot"]);
    }

    #[test]
    fn asks_for_yes_on_a_first_deployment() {
        let (exec, state) = world(false, &[], &[("create", URN_A)], &["i-0new"], true);
        let (result, prompts) = run(&exec, &["yes"]);
        result.unwrap();
        assert_eq!(
            prompts,
            ["Apply this plan to mysten/testnet? Type y/yes to continue: "]
        );
        assert!(state.borrow().tags.is_empty());
    }

    #[test]
    fn clears_stale_rotation_state_even_when_the_deploy_fails() {
        let (exec, state) = world(false, &["i-0aaa"], &[("replace", URN_A)], &[], false);
        let (result, _) = run(&exec, &["i-0aaa"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "The deploy did not finish. Preview the stack before running this step again."
        );
        assert!(state.borrow().tags.is_empty());
    }
}
