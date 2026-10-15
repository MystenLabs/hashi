// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A guardian's first deployment: `deploy`.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::exec::read;
use crate::next;
use crate::plan::preview;
use crate::plan::up;
use crate::say;
use crate::stack::Stack;
use crate::stack::pulumi;
use crate::warn;

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
