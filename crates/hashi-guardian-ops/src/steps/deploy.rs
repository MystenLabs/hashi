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
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;
use crate::github;
use crate::guardian::proxy_health;
use crate::guardian::relay_info;
use crate::next;
use crate::plan::Plan;
use crate::plan::preview;
use crate::plan::require_pulumi_version;
use crate::plan::up;
use crate::print_detail;
use crate::print_info;
use crate::print_success;
use crate::print_warning;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::stack::pulumi;
use crate::steps::slot;

/// Has hashi's guardian-enclave workflow measure the slot's commit on two runners, or checks run `run_id`, and stops
/// unless both agree on the PCR0 the stack configures.
pub fn measure(ctx: &Ctx, arg: Option<Slot>, run_id: Option<String>) -> Result<()> {
    const REPO: &str = "MystenLabs/hashi";
    let (stack, view) = slot(ctx, arg)?;
    print_info(&format!(
        "Measuring slot {}'s guardian build at {}",
        view.slot, view.commit
    ));
    let suffix = view.slot.suffix();
    let featureless = |stack: &Stack| -> Result<()> {
        if stack.config(&format!("eif-features{suffix}")).is_some() {
            bail!(
                "stack {} sets eif-features{suffix}, so slot {} builds an image this workflow's real build doesn't measure",
                stack.name,
                view.slot
            );
        }
        Ok(())
    };
    featureless(&stack)?;
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
        bail!("could not tell which run measures the build: {run_id}");
    }
    print_info(&format!(
        "Measurement run: https://github.com/{REPO}/actions/runs/{run_id}"
    ));
    // Only a dispatch builds the inputs it is given; other runs check reproducibility with canonical ones.
    let run = github::run(ctx, REPO, &run_id)?;
    if run.event != "workflow_dispatch" || run.workflow_name != "Guardian Enclave Build" {
        bail!(
            "run {run_id} is a {} run of {}, not a dispatched Guardian Enclave Build, so it measures no deployment",
            run.event,
            run.workflow_name
        );
    }
    github::watch(ctx, REPO, &run_id)?;
    // The run builds whatever commit and features it was given, so check it built this one on both runners.
    let log = read(
        ctx.exec,
        &Cmd::new("gh").args(["run", "view", &run_id, "--repo", REPO, "--log"]),
    )
    .with_context(|| format!("could not read the log of run {run_id}"))?;
    github::require_canonical_build(&log, &run_id, &view.commit)?;
    let downloads = tempfile::tempdir()?;
    read(
        ctx.exec,
        &Cmd::new("gh")
            .args(["run", "download", &run_id, "--repo", REPO])
            .args(["--pattern", "nitro-pcrs-*", "--dir"])
            .arg(downloads.path()),
    )
    .with_context(|| format!("could not download the measurements of run {run_id}"))?;
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
    featureless(&stack)?;
    let now = stack.slot(ctx, view.slot)?;
    if now.commit != view.commit {
        bail!(
            "stack {}'s hashi-commit{suffix} changed to {} while run {run_id} measured {}; measure that one",
            stack.name,
            now.commit,
            view.commit
        );
    }
    let configured = stack.config(&view.pcr0_key);
    if configured != Some(measured.as_str()) {
        bail!(
            "stack {} has {} {}; set it to the PCR0 above in its Pulumi.<stack>.yaml",
            stack.name,
            view.pcr0_key,
            configured.unwrap_or("unset")
        );
    }
    print_success(&format!(
        "It is the {} stack {} configures.",
        view.pcr0_key, stack.name
    ));
    if view.instance.is_none() && stack.slots()?.len() == 1 {
        next("deploy");
    }
    Ok(())
}

/// Builds the proxy at the active slot's commit and applies the proxy stack, through the workflow
/// `GUARDIAN_PROXY_WORKFLOW` names.
pub fn proxy(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    let view = deployed_active(ctx, &stack)?;
    print_info(&format!("Rolling the guardian proxy to {}", view.commit));
    let url = ctx.env.proxy_url()?.url;
    let (workflow, git_ref) = github::proxy_workflow(ctx)?;
    github::require_run_urls(ctx)?;
    // The workflow builds the image and applies the proxy stack from the ref it runs at.
    print_info(&format!("Proxy workflow: {workflow}@{git_ref}"));
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    require_no_kp_round(ctx, &tree)?;
    print_warning(
        "Rolling a proxy that is serving takes the guardian's address down while it restarts, and drops the shares key provisioners have sent in a provisioning round that has not finished.",
    );
    confirm(
        ctx.ask,
        &format!("Roll the proxy of {}?", stack.short_name()),
        &Unchanged {
            no_input: "no input received; nothing was rolled",
            declined: "not confirmed; nothing was rolled",
        },
    )?;
    // The question can wait any time, while a deploy or a switchover moves the active slot's guardian.
    let now = deployed_active(ctx, &Stack::load(ctx)?)?;
    if now.slot != view.slot || now.commit != view.commit {
        bail!(
            "stack {}'s active slot or its commit changed while this step waited for you; nothing was rolled: run this step again",
            stack.name
        );
    }
    require_no_kp_round(ctx, &tree)?;
    let run_id = github::dispatch(
        ctx,
        &workflow.repo,
        &workflow.file,
        &git_ref,
        &[("env", stack.short_name()), ("hashi_commit", &view.commit)],
    )?;
    print_info(&format!(
        "Proxy deploy run: https://github.com/{}/actions/runs/{run_id}",
        workflow.repo
    ));
    github::watch(ctx, &workflow.repo, &run_id).context(
        "check the proxy deploy before going on; running this step again restarts the proxy again",
    )?;
    proxy_health(ctx)
        .with_context(|| format!("the proxy deployed but {url}/health does not answer"))?;
    print_success(&format!("The proxy answers at {url}."));
    next(&format!(
        "tunnel --slot {}, left running in its own terminal; then info --slot {}",
        view.slot, view.slot
    ));
    Ok(())
}

/// The active slot, once the stack has deployed the commit it configures: the proxy decodes that guardian, so it runs
/// the build that guardian was deployed from.
fn deployed_active(ctx: &Ctx, stack: &Stack) -> Result<SlotView> {
    let view = stack.slot(ctx, stack.active()?)?;
    view.require_deployed(ctx, stack)?;
    Ok(view)
}

/// Stops while the relay's guardian is in a key provisioner round, whose shares a roll drops. A relay that doesn't
/// answer is left to the warning: rolling the proxy may be what brings it back.
fn require_no_kp_round(ctx: &Ctx, tree: &Tree) -> Result<()> {
    match relay_info(ctx, tree) {
        Ok(relay) if relay.lifecycle.in_kp_round() => bail!(
            "the guardian the relay serves is in a key provisioner round ({}); roll the proxy once that round has finished",
            relay.lifecycle
        ),
        Ok(_) => Ok(()),
        Err(error) => {
            print_warning(&format!(
                "Could not read the guardian the relay serves, so this step can't tell whether a key provisioner round is open: {error:#}"
            ));
            Ok(())
        }
    }
}

/// Applies the whole enclave stack. An untargeted up re-renders every slot it plans, so it refuses a stack with two
/// slots, and has the operator name every guardian instance it could destroy.
pub fn deploy(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    print_info(&format!(
        "Deploying the guardian enclave stack {}",
        stack.name
    ));
    if stack.slots()?.len() > 1 {
        bail!(
            "stack {} has two guardian slots; the deploy step runs an untargeted pulumi up, which can replace either guardian",
            stack.name
        );
    }
    require_pulumi_version(ctx)?;
    let plan = preview(ctx, &stack.dir, &stack.name)?;
    let changed = changes(&plan);
    for (op, urn) in &changed {
        let parts: Vec<&str> = urn.split("::").collect();
        print_detail(&format!(
            "  {op}  {}",
            parts[parts.len().saturating_sub(2)..].join("  ")
        ));
    }
    print_detail(
        &plan
            .change_summary
            .iter()
            .map(|(op, count)| format!("{count} {op}"))
            .collect::<Vec<_>>()
            .join(", "),
    );
    if changed.is_empty() {
        print_info("Nothing to change.");
        return Ok(());
    }

    // The plan leaves out an instance it deletes because the log bucket it depends on is replaced, so any change is
    // taken to risk every instance the stack has. An enclave holds the only live copy of its key, and naming each
    // instance is the consent to lose it.
    let existing = instance_ids(ctx, &stack)
        .with_context(|| format!("could not read the instances of stack {}", stack.name))?;
    if existing.is_empty() {
        confirm(
            ctx.ask,
            &format!("Apply this plan to {}?", stack.name),
            &NOTHING_CHANGED,
        )?;
    } else {
        print_warning(
            "This plan can destroy the guardian instances below. A destroyed guardian's key is gone from memory for good: it needs every step from provisioning again, or from the ceremony if the log bucket changes too.",
        );
        for id in &existing {
            confirm_typed(ctx.ask, id, "to destroy that guardian", &NOTHING_CHANGED)?;
        }
    }
    // The prompts can wait any time, and the up plans again from scratch, so the consent must still describe it.
    let reloaded = Stack::load(ctx)?;
    if reloaded.slots()?.len() > 1
        || changes(&preview(ctx, &reloaded.dir, &reloaded.name)?) != changed
    {
        bail!(
            "stack {}'s configuration or plan changed while this step waited for you; nothing was changed: run this step again",
            stack.name
        );
    }
    let now = instance_ids(ctx, &stack)
        .with_context(|| format!("could not read the instances of stack {}", stack.name))?;
    if now != existing {
        bail!(
            "stack {}'s instances changed while this step waited for you: {} then, {} now; nothing was changed: run this step again",
            stack.name,
            existing.join(" "),
            now.join(" ")
        );
    }
    let applied = up(ctx, &stack.dir, &stack.name)?;
    let outcome = if applied {
        "deployed, but"
    } else {
        "the deploy did not finish, and"
    };
    // Rotation state describes earlier instances, so it is stale once none of them is left. A deploy that fails
    // partway can already have destroyed them, so this runs either way.
    let remaining = instance_ids(ctx, &stack).with_context(|| {
        format!(
            "{outcome} could not read the instances of stack {}",
            stack.name
        )
    })?;
    if !existing.iter().any(|id| remaining.contains(id)) {
        let tags = stack.rotation_tags(ctx).with_context(|| {
            format!("{outcome} could not list the stack's rotation tags; clear them before the next rotation")
        })?;
        for tag in tags {
            read(
                ctx.exec,
                &pulumi(&stack.dir).args(["stack", "tag", "rm", &tag, "--stack", &stack.name]),
            )
            .with_context(|| {
                format!("{outcome} could not clear {tag}; clear it before the next rotation")
            })?;
        }
    }
    if !applied {
        bail!("the deploy did not finish; preview the stack before running this step again");
    }
    print_success(
        "Deployed. The host builds the enclave image at boot; follow it with the host step.",
    );
    next("host");
    Ok(())
}

/// A plan's changes, by operation and URN, sorted: Pulumi can list one plan's steps in another order.
fn changes(plan: &Plan) -> Vec<(String, String)> {
    let mut changes: Vec<(String, String)> = plan
        .steps
        .iter()
        .filter(|step| step.op != "same")
        .map(|step| (step.op.clone(), step.urn.clone()))
        .collect();
    changes.sort();
    changes
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
    use crate::stack::tests::user_data;

    const URN_A: &str = "urn:pulumi:testnet::enclave::aws:ec2/instance:Instance::guardian-a";

    struct State {
        instances: Vec<&'static str>,
        tags: Vec<&'static str>,
        /// Whether someone arms a standby while the step waits for its prompts.
        armed_meanwhile: bool,
        exports: usize,
        /// Whether the next preview also creates a standby, as a yaml edit made while the prompts wait would.
        drifts_meanwhile: bool,
        previews: usize,
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
            armed_meanwhile: false,
            exports: 0,
            drifts_meanwhile: false,
            previews: 0,
        }));
        // The enclave stack references no other stack, so its previews hold no read step.
        let mut steps: Vec<serde_json::Value> = plan
            .iter()
            .map(|(op, urn)| json!({ "op": op, "urn": urn }))
            .collect();
        steps.push(json!({ "op": "same", "urn": "urn:pulumi:testnet::enclave::pulumi:pulumi:Stack::enclave-testnet" }));
        let plan = json!({ "steps": steps, "changeSummary": { "same": 15 } }).to_string();
        steps.push(json!({ "op": "create", "urn": "urn:pulumi:testnet::enclave::aws:ec2/instance:Instance::guardian-b" }));
        let drifted_plan = json!({ "steps": steps, "changeSummary": { "same": 15 } }).to_string();
        let after = after.to_vec();
        let shared = state.clone();
        let exec = Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            if w == ["pulumi", "version"] {
                return Some((true, "v3.0.0\n".to_owned()));
            }
            match &w[3..] {
                ["preview", "--stack", _, "--json"] => {
                    let mut seen = shared.borrow_mut();
                    seen.previews += 1;
                    let drifted = seen.drifts_meanwhile && seen.previews > 1;
                    Some((true, if drifted { &drifted_plan } else { &plan }.clone()))
                }
                ["up", "--stack", _, "--yes"] => {
                    shared.borrow_mut().instances = after.clone();
                    Some((up_succeeds, String::new()))
                }
                ["stack", "export", "--stack", _] => {
                    let mut seen = shared.borrow_mut();
                    seen.exports += 1;
                    if seen.armed_meanwhile && seen.exports == 2 {
                        seen.instances.push("i-0bbb");
                    }
                    drop(seen);
                    let resources: Vec<_> = shared
                        .borrow()
                        .instances
                        .iter()
                        .map(|id| json!({ "type": "aws:ec2/instance:Instance", "urn": URN_A, "id": id }))
                        .collect();
                    Some((
                        true,
                        json!({ "deployment": { "manifest": { "version": "v3.0.0" }, "resources": resources } })
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

    /// Whether the step ran `pulumi -C <dir> <subcommand>`.
    fn pulumi_ran(exec: &Fake, subcommand: &str) -> bool {
        exec.log.borrow().iter().any(|words| {
            words[0] == "pulumi" && words.get(3).map(String::as_str) == Some(subcommand)
        })
    }

    #[test]
    fn refuses_a_stack_with_two_slots() {
        let (exec, _) = world(true, &[], &[("create", URN_A)], &[], true);
        let (result, _) = run(&exec, &[]);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .starts_with("stack org/testnet has two guardian slots;")
        );
        assert!(!pulumi_ran(&exec, "preview"));
    }

    #[test]
    fn changes_nothing_when_nothing_changes() {
        let (exec, _) = world(false, &["i-0aaa"], &[], &["i-0aaa"], true);
        let (result, prompts) = run(&exec, &[]);
        result.unwrap();
        assert!(prompts.is_empty());
        assert!(!pulumi_ran(&exec, "up"));
    }

    #[test]
    fn deploys_only_with_the_pinned_pulumi() {
        let (exec, _) = world(false, &[], &[("create", URN_A)], &["i-0new"], true);
        let repo = tempfile::tempdir().unwrap();
        let deployed = |pin: Option<&str>| {
            let mut env: Vec<(&str, &str)> = stack_env()
                .into_iter()
                .filter(|(key, _)| *key != "PULUMI_VERSION")
                .collect();
            env.extend(pin.map(|pin| ("PULUMI_VERSION", pin)));
            let ask = Scripted::new(&["no"]);
            deploy(&Ctx::for_test(repo.path(), &exec, &env).with_ask(&ask))
                .map_err(|error| error.to_string())
        };
        assert_eq!(
            deployed(Some("3.1.0")).unwrap_err(),
            "this is Pulumi v3.0.0, but PULUMI_VERSION is v3.1.0; put Pulumi v3.1.0 first on your PATH"
        );
        assert_eq!(
            deployed(None).unwrap_err(),
            "testnet.env does not set PULUMI_VERSION"
        );
        assert!(!pulumi_ran(&exec, "preview"));
        // The pin may name the version as `pulumi version` prints it.
        assert_eq!(
            deployed(Some("v3.0.0")).unwrap_err(),
            "not confirmed; nothing was changed"
        );
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
            "not confirmed; nothing was changed"
        );
        assert_eq!(prompts, ["Type i-0aaa to destroy that guardian: "]);
        assert!(!pulumi_ran(&exec, "up"));

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
    fn applies_nothing_once_the_plan_changed_under_its_prompts() {
        let (exec, state) = world(
            false,
            &["i-0aaa"],
            &[("update", "urn:x::bucket")],
            &["i-0aaa"],
            true,
        );
        state.borrow_mut().drifts_meanwhile = true;
        let (result, _) = run(&exec, &["i-0aaa"]);
        assert!(result.unwrap_err().to_string().starts_with(
            "stack org/testnet's configuration or plan changed while this step waited for you"
        ));
        assert!(!pulumi_ran(&exec, "up"));
    }

    #[test]
    fn applies_nothing_once_the_stack_changed_under_its_prompts() {
        let (exec, state) = world(
            false,
            &["i-0aaa"],
            &[("update", "urn:x::bucket")],
            &["i-0aaa"],
            true,
        );
        state.borrow_mut().armed_meanwhile = true;
        let (result, _) = run(&exec, &["i-0aaa"]);
        assert!(
            result.unwrap_err().to_string().starts_with(
                "stack org/testnet's instances changed while this step waited for you"
            )
        );
        assert!(!pulumi_ran(&exec, "up"));
    }

    /// A slot whose build a run measured, as GitHub reports it. With `featured_meanwhile`, the stack sets eif-features
    /// once the step has read it once.
    fn measurement_world(
        config: serde_json::Value,
        event: &'static str,
        watched: bool,
        featured_meanwhile: bool,
    ) -> Fake {
        let stack = stack_world(config.clone(), json!({}));
        let mut later = config;
        later["eif-features"] = "non-enclave-dev".into();
        let featured = stack_world(later, json!({}));
        let configs = std::cell::Cell::new(0);
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            let ok = |stdout: &str| Some((true, stdout.to_owned()));
            match w.as_slice() {
                ["gh", "run", "view", _, "--repo", _, "--json", _] => ok(&json!({
                    "event": event,
                    "workflowName": "Guardian Enclave Build",
                    "conclusion": if watched { "success" } else { "failure" },
                })
                .to_string()),
                ["gh", "run", "watch", ..] => Some((watched, String::new())),
                ["gh", "run", "view", _, "--repo", _, "--log"] => ok(&format!(
                    "a\tgit checkout --progress --force {COMMIT}\nb\tgit checkout --progress --force {COMMIT}\na\tFEATURES: \nb\tFEATURES: \n"
                )),
                ["gh", "run", "download", .., "--dir", dir] => {
                    for runner in ["ubuntu-latest", "ubuntu-22.04"] {
                        let path = std::path::Path::new(dir).join(format!("nitro-pcrs-{runner}"));
                        std::fs::create_dir_all(&path).ok()?;
                        std::fs::write(
                            path.join("nitro.pcrs"),
                            format!("{} PCR0\n", "0c".repeat(48)),
                        )
                        .ok()?;
                    }
                    ok("")
                }
                ["pulumi", "-C", _, "config", ..] => {
                    configs.set(configs.get() + 1);
                    let world = if featured_meanwhile && configs.get() > 1 {
                        &featured
                    } else {
                        &stack
                    };
                    world
                        .output(&Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                _ => None,
            }
        })
    }

    fn measured(exec: &Fake) -> Result<()> {
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), exec, &stack_env());
        measure(&ctx, Some(Slot::A), Some("123".to_owned()))
    }

    #[test]
    fn measures_only_a_dispatched_real_build_of_the_slots_commit() {
        let config = json!({ "hashi-commit": COMMIT, "eif-pcr0": "0c".repeat(48) });
        measured(&measurement_world(
            config.clone(),
            "workflow_dispatch",
            true,
            false,
        ))
        .unwrap();
        assert!(
            measured(&measurement_world(config.clone(), "push", true, false))
                .unwrap_err()
                .to_string()
                .starts_with("run 123 is a push run of Guardian Enclave Build")
        );
        assert_eq!(
            measured(&measurement_world(
                config.clone(),
                "workflow_dispatch",
                false,
                false
            ))
            .unwrap_err()
            .to_string(),
            "run https://github.com/MystenLabs/hashi/actions/runs/123 ended in failure"
        );
        let featured = json!({ "hashi-commit": COMMIT, "eif-features": "non-enclave-dev" });
        let exec = measurement_world(featured, "workflow_dispatch", true, false);
        assert!(
            measured(&exec)
                .unwrap_err()
                .to_string()
                .starts_with("stack org/testnet sets eif-features")
        );
        assert!(!exec.ran(&["gh"]));
        // The watch takes minutes, during which the slot can stop being the build the run measured.
        let exec = measurement_world(config, "workflow_dispatch", true, true);
        assert!(
            measured(&exec)
                .unwrap_err()
                .to_string()
                .starts_with("stack org/testnet sets eif-features")
        );
    }

    const ELSEWHERE: &str = "c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4";

    /// A stack whose slot a's host was launched to build `launched[n]` as of its `n`th read, and the last one after
    /// those, a relay whose guardian is `relayed`, and a proxy workflow that succeeds.
    fn proxy_world(launched: &'static [&'static str], relayed: &'static str) -> Fake {
        let stack = stack_world(json!({ "hashi-commit": COMMIT }), json!({}));
        let reads = std::cell::Cell::new(0);
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            let ok = |stdout: &str| Some((true, stdout.to_owned()));
            match w.as_slice() {
                ["pulumi", "-C", _, "stack", "output", "--json", ..] => ok(&json!({
                    "active_slot": "a",
                    "enclave_instance_id": "i-0aaa",
                    "s3_bucket_name": "guardian-bucket",
                    "s3_bucket_region": "us-west-2",
                })
                .to_string()),
                ["aws", "ec2", "describe-instance-attribute", ..] => {
                    let read = reads.get();
                    reads.set(read + 1);
                    ok(&user_data(launched[read.min(launched.len() - 1)]))
                }
                [
                    "grpcurl",
                    ..,
                    "sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo",
                ] => ok(&json!({
                    "signedInfo": {
                        "data": crate::guardian::tests::info_json(&"aa".repeat(32), None, relayed)
                    }
                })
                .to_string()),
                ["gh", "--version"] => ok("gh version 2.87.0 (2026-01-01)\n"),
                ["gh", "workflow", "run", ..] => {
                    ok("https://github.com/org/infra/actions/runs/456\n")
                }
                ["gh", "run", "watch", "456", ..] => ok(""),
                ["curl", .., url] if url.ends_with("/health") => ok(""),
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                _ => None,
            }
        })
    }

    /// Rolls the proxy with the operator answering `answers`, from a checkout holding slot a's commit.
    fn rolled(exec: &Fake, answers: &[&str]) -> Result<()> {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let mut env = stack_env();
        env.push((
            "GUARDIAN_PROXY_WORKFLOW",
            "org/infra/.github/workflows/guardian-proxy.yaml@main",
        ));
        let ask = Scripted::new(answers);
        proxy(&Ctx::for_test(repo.path(), exec, &env).with_ask(&ask))
    }

    #[test]
    fn rolls_the_proxy_only_to_the_guardian_the_stack_deployed() {
        let exec = proxy_world(&[ELSEWHERE], "withdraw/ACTIVATED");
        assert_eq!(
            rolled(&exec, &["yes"]).unwrap_err().to_string(),
            format!(
                "stack org/testnet configures commit {COMMIT} for slot a, but its host i-0aaa was launched to build another commit; set it back, or deploy it, first"
            )
        );
        // A deploy that lands while the question waits.
        let exec = proxy_world(&[COMMIT, ELSEWHERE], "withdraw/ACTIVATED");
        assert!(rolled(&exec, &["yes"]).is_err());
        assert!(!exec.ran(&["gh", "workflow", "run"]));
    }

    #[test]
    fn rolls_no_proxy_during_a_key_provisioner_round() {
        let exec = proxy_world(&[COMMIT], "withdraw/OPERATOR_INITIALIZED");
        assert_eq!(
            rolled(&exec, &["yes"]).unwrap_err().to_string(),
            "the guardian the relay serves is in a key provisioner round (withdraw/OPERATOR_INITIALIZED); roll the proxy once that round has finished"
        );
        assert!(!exec.ran(&["gh", "workflow", "run"]));
    }

    #[test]
    fn dispatches_the_proxy_workflow_the_env_names() {
        let exec = proxy_world(&[COMMIT], "withdraw/ACTIVATED");
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let ask = Scripted::new(&["yes"]);
        let mut env = stack_env();
        let unset = Ctx::for_test(repo.path(), &exec, &env).with_ask(&ask);
        assert_eq!(
            proxy(&unset).unwrap_err().to_string(),
            "testnet.env does not set GUARDIAN_PROXY_WORKFLOW"
        );
        assert!(ask.prompts.borrow().is_empty());

        env.push((
            "GUARDIAN_PROXY_WORKFLOW",
            "org/infra/.github/workflows/guardian-proxy.yaml@main",
        ));
        let ctx = Ctx::for_test(repo.path(), &exec, &env).with_ask(&ask);
        proxy(&ctx).unwrap();
        assert!(exec.ran(&[
            "gh",
            "workflow",
            "run",
            "guardian-proxy.yaml",
            "--repo",
            "org/infra",
            "--ref",
            "main",
            "-f",
            "env=testnet",
            "-f",
            &format!("hashi_commit={COMMIT}"),
        ]));
        assert!(exec.ran(&["gh", "run", "watch", "456", "--repo", "org/infra"]));
    }

    #[test]
    fn asks_for_yes_on_a_first_deployment() {
        let (exec, state) = world(false, &[], &[("create", URN_A)], &["i-0new"], true);
        let (result, prompts) = run(&exec, &["yes"]);
        result.unwrap();
        assert_eq!(prompts, ["Apply this plan to org/testnet? [y/N] "]);
        assert!(state.borrow().tags.is_empty());
    }

    #[test]
    fn clears_stale_rotation_state_even_when_the_deploy_fails() {
        let (exec, state) = world(false, &["i-0aaa"], &[("replace", URN_A)], &[], false);
        let (result, _) = run(&exec, &["i-0aaa"]);
        assert_eq!(
            result.unwrap_err().to_string(),
            "the deploy did not finish; preview the stack before running this step again"
        );
        assert!(state.borrow().tags.is_empty());
    }
}
