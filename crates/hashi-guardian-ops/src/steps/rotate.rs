// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A standby guardian in the stack's other slot: `arm` it, `proxy-update` so the relay reaches it, and `teardown`.
//! Every step re-reads the stack, the hosts and the proxy, applies only a targeted plan of exactly the expected shape,
//! and can run again to resume.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::commit::Tree;
use crate::github::require_no_guardian_runs;
use crate::guardian::Lifecycle;
use crate::guardian::serving_info;
use crate::guardian::slot_info;
use crate::host;
use crate::next;
use crate::plan::Change;
use crate::plan::preview;
use crate::plan::preview_slot;
use crate::plan::require_pulumi_version;
use crate::plan::up_slot;
use crate::plan::urn_type;
use crate::proxy::update_proxy;
use crate::say;
use crate::stack::INSTANCE;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::steps::slot;
use crate::warn;

const GUARDIAN_UNIT_STATE: &str = "if systemctl is-enabled --quiet hashi-guardian-enclave.service || systemctl is-active --quiet hashi-guardian-enclave.service; then echo GUARDIAN_RUNNING; else echo GUARDIAN_STOPPED; fi";

fn tree(ctx: &Ctx, view: &SlotView) -> Result<Tree> {
    Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )
}

/// What a host says of its guardian unit: `GUARDIAN_RUNNING` while it is enabled or active, either of which can start
/// a session, and `GUARDIAN_STOPPED` otherwise.
fn guardian_unit_state(ctx: &Ctx, region: &str, instance: &str) -> Result<String> {
    let state = host::run(ctx, region, instance, &[GUARDIAN_UNIT_STATE])?;
    if !state.success {
        bail!("{}", state.text.trim());
    }
    Ok(state.text)
}

/// Creates a standby guardian host in `slot`, next to the serving one in the other slot.
pub fn arm(ctx: &Ctx, slot: Slot) -> Result<()> {
    let (stack, arming) = arm_checks(ctx, slot, true)?;
    let changes = preview_slot(ctx, &stack, &arming.urn)?;
    if changes != [Change::new("create", &arming.urn)] {
        bail!(
            "Arming slot {slot} must create its instance and change nothing else, but this plan does not. Nothing was changed."
        );
    }
    confirm(
        ctx.ask,
        &format!("Create slot {slot}'s guardian host?"),
        &NOTHING_CHANGED,
    )?;
    // The question can wait any time, while the stack's configuration, its plan or the serving guardian changes.
    let (stack, now) = arm_checks(ctx, slot, false)?;
    if now != arming
        || preview(ctx, &stack.dir, &stack.name, Some(&arming.urn))?.changes() != changes
    {
        bail!(
            "Slot {slot}'s plan changed while this step waited for you. Nothing was changed: run this step again."
        );
    }
    require_no_guardian_runs(ctx)?;
    let Arming {
        active,
        serving,
        urn,
    } = arming;
    up_slot(ctx, &stack, &urn)?;
    let after = Stack::load(ctx)?;
    if after.output("enclave_instance_id") != Some(serving.as_str()) || after.active()? != active {
        bail!(
            "Stack {} no longer shows slot {active}'s guardian {serving} as active. Check its outputs before going on.",
            stack.name
        );
    }
    let Some(standby) = after.output("standby_instance_id") else {
        bail!(
            "Stack {} lists no standby after arming slot {slot}. Check its outputs.",
            stack.name
        );
    };
    // Only the program knew which instance it would create, so check it is the standby the outputs name.
    if after.instance_urn(ctx, standby)?.as_deref() != Some(urn.as_str()) {
        bail!(
            "Stack {}'s standby {standby} is not the instance arming slot {slot} created, {urn}. Check the stack before going on.",
            stack.name
        );
    }
    println!(
        "\nArmed slot {slot} on {standby}. The host builds the enclave image at boot; follow it with: host {slot}. Then run proxy-update, so the relay reaches it."
    );
    next(&format!(
        "host {slot}, until its boot completes; then proxy-update"
    ));
    Ok(())
}

/// What arming a slot rests on: the serving guardian beside it, and the one instance the stack would create for it.
#[derive(PartialEq)]
struct Arming {
    active: Slot,
    serving: String,
    urn: String,
}

/// Checks the stack, the serving guardian and the workflows for arming `slot`, and finds the instance it would create.
fn arm_checks(ctx: &Ctx, slot: Slot, announce: bool) -> Result<(Stack, Arming)> {
    let stack = Stack::load(ctx)?;
    let view = stack.slot(ctx, slot)?;
    stack.bucket()?;
    let active = stack.active()?;
    let serving = stack.output("enclave_instance_id");
    if announce {
        say(&format!("Arm slot {slot} next to slot {active}'s guardian"));
    }
    if view.role != Role::Absent {
        bail!("Slot {slot} already runs a guardian, as the {}.", view.role);
    }
    require_pulumi_version(ctx)?;
    require_no_guardian_runs(ctx)?;
    let Some(serving) = serving.filter(|_| active != slot) else {
        bail!(
            "Slot {slot} is the stack's active slot. arm adds a standby next to a serving guardian."
        );
    };
    if !stack.slot_enabled(slot)? {
        bail!(
            "Enable slot {slot} first: set slot-{slot}-enabled to \"true\" in stack {}'s Pulumi.<stack>.yaml.",
            stack.name
        );
    }
    let configured_active = stack.config("active-slot").unwrap_or("a");
    if configured_active != active.to_string() {
        bail!(
            "Stack {} configures active-slot {configured_active}, but slot {active} is active. Set it back before arming.",
            stack.name
        );
    }
    // Both slots write one log, whose readers must allowlist every build that wrote it, and a slot's configurations
    // allowlist only its own build.
    let (suffix, active_suffix) = (slot.suffix(), active.suffix());
    let build = |suffix: &str| {
        (
            stack.config(&format!("hashi-commit{suffix}")),
            stack.config(&format!("eif-pcr0{suffix}")),
        )
    };
    if build(suffix) != build(active_suffix) {
        bail!(
            "Slot {slot}'s hashi-commit{suffix} and eif-pcr0{suffix} name another build than slot {active}'s, and this step arms a standby only on the serving guardian's build. Change them only if that build never wrote the stack's log: renders allowlist it through them."
        );
    }
    for key in ["eif-features", "eif-ceremony-mode"] {
        if stack.config(&format!("{key}{suffix}")).is_some()
            || stack.config(&format!("{key}{active_suffix}")).is_some()
        {
            bail!(
                "Stack {} sets {key} for a slot. A real guardian builds with neither: unset it.",
                stack.name
            );
        }
    }
    let tags = stack.rotation_tags(ctx)?;
    if !tags.is_empty() {
        bail!(
            "Stack {} has rotation tags, which hold rotation state apart from its configuration: {}. This flow keeps it in Pulumi.<stack>.yaml, so clear them once you know the yaml says the same.",
            stack.name,
            tags.join(", ")
        );
    }
    serving_info(ctx).context("Arm a standby only next to a serving guardian.")?;
    let urn = instance_to_create(ctx, &stack, slot)?;
    let serving = serving.to_owned();
    Ok((
        stack,
        Arming {
            active,
            serving,
            urn,
        },
    ))
}

/// The URN of the instance the stack would create for `slot`: the one instance an untargeted plan creates, since only
/// the program knows its name. Anything else that plan creates is refused, as the targeted plan arming applies leaves
/// it out, though the new host may need it.
fn instance_to_create(ctx: &Ctx, stack: &Stack, slot: Slot) -> Result<String> {
    let plan = preview(ctx, &stack.dir, &stack.name, None)?;
    let (instances, others): (Vec<&str>, Vec<&str>) = plan
        .creates()
        .into_iter()
        .partition(|urn| urn_type(urn) == Some(INSTANCE));
    let [urn] = instances[..] else {
        bail!(
            "Stack {}'s plan creates {} guardian instances, not slot {slot}'s one: {}",
            stack.name,
            instances.len(),
            instances.join(" ")
        );
    };
    if !others.is_empty() {
        bail!(
            "Stack {} also plans to create resources that arming slot {slot} would leave out. Create them first, from {}: pulumi up --stack {} {}",
            stack.name,
            stack.dir,
            stack.name,
            others
                .iter()
                .map(|other| format!("--target {other}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    Ok(urn.to_owned())
}

/// Applies the proxy stack so the proxy follows the enclave stack's slots.
pub fn proxy_update(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    say(&format!(
        "Update the proxy of stack {} to follow its guardian slots",
        stack.name
    ));
    require_no_guardian_runs(ctx)?;
    let view = stack.slot(ctx, stack.active()?)?;
    update_proxy(ctx, &stack, &tree(ctx, &view)?)?;
    println!("The proxy answers at {}.", ctx.env.proxy_url()?.url);
    Ok(())
}

/// Destroys a standby slot's host, abandoning a standby that never served.
pub fn teardown(ctx: &Ctx, slot_arg: Slot) -> Result<()> {
    let (stack, view) = slot(ctx, Some(slot_arg), "teardown")?;
    stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    let slot = view.slot;
    say(&format!("Tear down slot {slot}'s guardian host {instance}"));
    if view.role != Role::Standby {
        bail!("Slot {slot} runs the active guardian. Only a standby can be torn down.");
    }
    require_pulumi_version(ctx)?;
    require_no_guardian_runs(ctx)?;
    if stack.slot_enabled(slot)? {
        bail!(
            "Disable slot {slot} first: set slot-{slot}-enabled to \"false\" in stack {}'s Pulumi.<stack>.yaml, and commit it.",
            stack.name
        );
    }
    let active = stack.active()?;
    let configured_active = stack.config("active-slot").unwrap_or("a");
    if configured_active != active.to_string() {
        bail!(
            "Stack {} configures active-slot {configured_active}, but slot {active} is active.",
            stack.name
        );
    }
    serving_info(ctx).context("Tear nothing down until a guardian serves.")?;
    let Some(host) = stack
        .instances(ctx)?
        .into_iter()
        .find(|resource| resource.id.as_deref() == Some(instance))
    else {
        bail!(
            "Could not find slot {slot}'s instance {instance} in stack {}'s state.",
            stack.name
        );
    };
    // EC2 and SSM are asked in the host's own region and account, which its ARN names.
    let arn: Vec<&str> = host
        .outputs
        .as_ref()
        .and_then(|outputs| outputs.get("arn")?.as_str())
        .unwrap_or_default()
        .split(':')
        .collect();
    let (region, account) = (
        arn.get(3).copied().unwrap_or_default(),
        arn.get(4).copied().unwrap_or_default(),
    );
    // What the guardian on the host is, if anything: `None` once it can't serve again.
    let guardian = || -> Result<Option<Lifecycle>> {
        // EC2 is asked first: SSM can't reach a host it has stopped or ended, which a teardown cut off partway leaves.
        match host::instance_state(ctx, region, instance, account)?.as_deref() {
            None | Some("stopping" | "stopped" | "shutting-down" | "terminated") => {
                return Ok(None);
            }
            _ => {}
        }
        let state = guardian_unit_state(ctx, region, instance)
            .with_context(|| format!("Could not read slot {slot}'s host."))?;
        if state.contains("GUARDIAN_STOPPED") {
            return Ok(None);
        }
        let lifecycle = slot_info(ctx, &tree(ctx, &view)?, &view)?.lifecycle;
        if lifecycle.is("withdraw/ACTIVATED") {
            bail!("Slot {slot}'s guardian on {instance} is activated and still runs.");
        }
        Ok(Some(lifecycle))
    };
    let found = guardian()?;
    match &found {
        None => println!("No guardian runs on slot {slot}'s host {instance}."),
        Some(lifecycle) => warn(&format!(
            "Slot {slot}'s guardian still runs ({lifecycle}). Tearing it down abandons it: what was provisioned or dealt to it is lost."
        )),
    }
    let changes = preview_slot(ctx, &stack, &host.urn)?;
    if changes != [Change::new("delete", &host.urn)] {
        bail!(
            "Tearing down slot {slot} must delete its instance and change nothing else, but this plan does not. Nothing was changed."
        );
    }
    confirm_typed(
        ctx.ask,
        instance,
        &format!("to destroy slot {slot}'s host"),
        &NOTHING_CHANGED,
    )?;
    // The question can wait any time, while the stack's configuration, either guardian or the plan changes.
    serving_info(ctx).context("Tear nothing down until a guardian serves.")?;
    let now = Stack::load(ctx)?;
    if now.slot_enabled(slot)?
        || now.active()? != active
        || now.config("active-slot").unwrap_or("a") != configured_active
        || now.instance(slot)? != Some(instance)
        || guardian()? != found
        || preview(ctx, &now.dir, &now.name, Some(&host.urn))?.changes() != changes
    {
        bail!(
            "Slot {slot}'s guardian, configuration or plan changed while this step waited for you. Nothing was changed: run this step again."
        );
    }
    require_no_guardian_runs(ctx)?;
    up_slot(ctx, &now, &host.urn)?;
    let after = Stack::load(ctx)?;
    if after.output("standby_instance_id").is_some() || after.active()? != active {
        bail!(
            "Stack {}'s outputs do not show slot {active} alone. Check them before going on.",
            stack.name
        );
    }
    println!("\nTore down slot {slot}. Run proxy-update, so the relay stops pointing at it.");
    next("proxy-update");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::world;
    use crate::world::Run;

    impl Run {
        fn set(&self, key: &str, value: &str) {
            self.state
                .borrow_mut()
                .config
                .insert(key.to_owned(), value.to_owned());
        }

        fn instance(&self, slot: &str) -> String {
            self.state.borrow().deployed[slot].clone()
        }

        fn lifecycle(&self, slot: &str, lifecycle: &str) {
            let instance = self.instance(slot);
            self.state
                .borrow_mut()
                .hosts
                .get_mut(&instance)
                .unwrap()
                .session
                .lifecycle = lifecycle.to_owned();
        }

        /// Arms slot b, points the relay at it and has the key provisioners provision it.
        fn armed_and_provisioned(&self) {
            self.step(&["yes"], |ctx| arm(ctx, Slot::B)).0.unwrap();
            self.step(&["yes"], proxy_update).0.unwrap();
            world::provision(&self.state, Slot::B);
            self.render(Slot::B);
        }
    }

    fn ok(result: (Result<()>, Vec<String>)) -> Vec<String> {
        result.0.unwrap();
        result.1
    }

    fn error(result: (Result<()>, Vec<String>)) -> String {
        result.0.unwrap_err().to_string()
    }

    #[test]
    fn arms_only_next_to_a_serving_guardian() {
        let run = Run::new();
        assert_eq!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::A))),
            "Slot a already runs a guardian, as the active."
        );
        run.set("slot-b-enabled", "false");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with("Enable slot b first")
        );
        run.set("slot-b-enabled", "true");
        run.set("eif-features-b", "non-enclave-dev");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .contains("sets eif-features for a slot")
        );
        run.state.borrow_mut().config.remove("eif-features-b");
        run.set("hashi-commit-b", &"1".repeat(40));
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "Slot b's hashi-commit-b and eif-pcr0-b name another build than slot a's, and"
            )
        );
        run.set("hashi-commit-b", world::COMMIT);
        // A resource the host needs but doesn't depend on in the plan stays out of a targeted one.
        let alarm = "urn:pulumi:testnet::enclave::aws:cloudwatch/metricAlarm:MetricAlarm::alarm";
        run.state.borrow_mut().other_creates = vec![alarm.to_owned()];
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .ends_with(&format!("pulumi up --stack org/testnet --target {alarm}"))
        );
        run.state.borrow_mut().other_creates.clear();
        // Rotation state kept apart from the yaml would make the plan describe another stack.
        run.state.borrow_mut().rotation_tags = vec!["rotation:active-slot".to_owned()];
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with("Stack org/testnet has rotation tags")
        );
        run.state.borrow_mut().rotation_tags.clear();
        run.set("active-slot", "b");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with("Stack org/testnet configures active-slot b, but slot a is active.")
        );
        run.state.borrow_mut().config.remove("active-slot");
        let serving = |epoch| {
            run.state
                .borrow_mut()
                .hosts
                .get_mut("i-0aaa")
                .unwrap()
                .session
                .epoch = epoch
        };
        serving(None);
        assert_eq!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))),
            "Arm a standby only next to a serving guardian."
        );
        serving(Some(1253));
        assert_eq!(
            error(run.step(&["no"], |ctx| arm(ctx, Slot::B))),
            "Not confirmed; nothing was changed."
        );
        assert!(!run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn arms_only_the_one_instance_the_plan_creates() {
        let run = Run::new();
        let other = "urn:pulumi:testnet::enclave::aws:ec2/instance:Instance::other";
        run.state.borrow_mut().other_creates = vec![other.to_owned()];
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "Stack org/testnet's plan creates 2 guardian instances, not slot b's one"
            )
        );
        run.state.borrow_mut().other_creates.clear();
        assert!(!run.state.borrow().deployed.contains_key("b"));

        // The standby the outputs then name must be the instance arming created.
        run.state.borrow_mut().standby_output = Some("i-0elsewhere".to_owned());
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "Stack org/testnet's standby i-0elsewhere is not the instance arming slot b created"
            )
        );
        run.state.borrow_mut().standby_output = None;
        let target = format!("{}b", world::URN_PREFIX);
        assert!(run.exec.ran(&[
            "pulumi",
            "-C",
            crate::stack::tests::ENCLAVE,
            "up",
            "--stack",
            "org/testnet",
            "--target",
            &target,
        ]));
    }

    #[test]
    fn updates_the_proxy_only_to_follow_the_slots() {
        let run = Run::new();
        let prompts = ok(run.step(&[], proxy_update));
        assert!(prompts.is_empty(), "nothing to change, so nothing asked");
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));

        run.state.borrow_mut().running_tag = "v0".to_owned();
        assert!(error(run.step(&["yes"], proxy_update)).starts_with("The proxy runs repo:v0, but"));
        run.state.borrow_mut().running_tag = "v1".to_owned();

        run.state.borrow_mut().service_counts = (1, 0, 2);
        assert!(
            error(run.step(&["yes"], proxy_update))
                .starts_with("The proxy service runs 0 of 1 tasks in 2 deployments.")
        );
        run.state.borrow_mut().service_counts = (1, 1, 1);

        // ECS can roll a deployment back once Pulumi has recorded it.
        run.state.borrow_mut().rolls_back = true;
        assert!(error(run.step(&["yes"], proxy_update)).contains("its deployment rolled back."));
        run.state.borrow_mut().rolls_back = false;
        // The plan would start from the state ECS rolled back from.
        assert!(
            error(run.step(&["yes"], proxy_update))
                .contains("a deployment rolled back, or the service changed outside Pulumi.")
        );
        run.state.borrow_mut().rolled_back = None;
        let prompts = ok(run.step(&[], proxy_update));
        assert!(prompts.is_empty(), "ECS runs what the slots need");
    }

    /// An operator who confirms once the relay's guardian has started a provisioning round.
    struct RoundStarts<'a>(&'a Run);

    impl crate::ask::Ask for RoundStarts<'_> {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, _prompt: &str) -> std::io::Result<Option<String>> {
            self.0.lifecycle("b", "withdraw/OPERATOR_INITIALIZED");
            Ok(Some("yes".to_owned()))
        }
    }

    /// An operator who answers `answer` once `change` has happened to the world.
    struct Meanwhile<'a> {
        run: &'a Run,
        change: fn(&Run),
        answer: String,
    }

    impl crate::ask::Ask for Meanwhile<'_> {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, _prompt: &str) -> std::io::Result<Option<String>> {
            (self.change)(self.run);
            Ok(Some(self.answer.clone()))
        }
    }

    #[test]
    fn applies_nothing_that_changed_while_it_asked() {
        let run = Run::new();
        // A proxy deploy finishes while the operator reads the plan.
        let deploy = |run: &Run| {
            let mut state = run.state.borrow_mut();
            state.revision += 1;
            state.running_tag = "v2".to_owned();
            state.configured_tag = "v2".to_owned();
        };
        let ask = |change, answer: &str| Meanwhile {
            run: &run,
            change,
            answer: answer.to_owned(),
        };
        let drift = |run: &Run| {
            run.state.borrow_mut().extra_change =
                Some(("update".to_owned(), format!("{}a", world::URN_PREFIX)));
        };
        assert!(
            run.step_asking(&ask(drift, "yes"), |ctx| arm(ctx, Slot::B))
                .unwrap_err()
                .to_string()
                .starts_with("Slot b's plan changed while this step waited for you.")
        );
        run.state.borrow_mut().extra_change = None;
        // A yaml edit that lands meanwhile, such as a dev build's features, which the plan doesn't show.
        let features = |run: &Run| run.set("eif-features-b", "non-enclave-dev");
        assert!(
            run.step_asking(&ask(features, "yes"), |ctx| arm(ctx, Slot::B))
                .unwrap_err()
                .to_string()
                .contains("sets eif-features for a slot")
        );
        run.state.borrow_mut().config.remove("eif-features-b");
        assert!(!run.state.borrow().deployed.contains_key("b"));
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        assert!(
            run.step_asking(&ask(deploy, "yes"), proxy_update)
                .unwrap_err()
                .to_string()
                .starts_with("The proxy's service or plan changed while this step waited for you.")
        );
        assert_eq!(run.state.borrow().standby, None, "nothing was applied");

        // A guardian that starts a session meanwhile is no longer the one checked.
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        let starts = |run: &Run| run.lifecycle("b", "withdraw/OPERATOR_INITIALIZED");
        assert!(
            run.step_asking(&ask(starts, &standby), |ctx| teardown(ctx, Slot::B))
                .unwrap_err()
                .to_string()
                .starts_with(
                    "Slot b's guardian, configuration or plan changed while this step waited for you."
                )
        );
        assert!(run.state.borrow().deployed.contains_key("b"));
        // Abandoning it needs no proxy update first, though the relay still serves slot a.
        ok(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)));
        assert!(!run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn rolls_the_proxy_only_outside_a_provisioning_round() {
        // A provisioning round's shares live in the relay's memory, which a roll drops.
        let run = Run::new();
        run.armed_and_provisioned();
        let stale = "http://192.0.2.99:3000";
        run.state.borrow_mut().backend = stale.to_owned();
        run.lifecycle("b", "withdraw/OPERATOR_INITIALIZED");
        assert!(
            error(run.step(&["yes"], proxy_update))
                .starts_with("The guardian the relay serves is in a key provisioner round")
        );
        run.lifecycle("b", "withdraw/PROVISIONER_INITIALIZED");
        assert!(
            run.step_asking(&RoundStarts(&run), proxy_update)
                .unwrap_err()
                .to_string()
                .starts_with("The guardian the relay serves is in a key provisioner round")
        );
        assert_eq!(run.state.borrow().backend, stale, "nothing was applied");

        // One it can't read may be in a round.
        run.lifecycle("b", "withdraw/PROVISIONER_INITIALIZED");
        let standby = run.instance("b");
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .running = false;
        assert!(
            error(run.step(&["yes"], proxy_update))
                .starts_with("Could not read the guardian the proxy's relay serves")
        );
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .running = true;
        ok(run.step(&["yes"], proxy_update));
        assert_ne!(run.state.borrow().backend, stale);
    }

    #[test]
    fn tears_down_only_a_stopped_standby() {
        let run = Run::new();
        run.armed_and_provisioned();
        assert_eq!(
            error(run.step(&["x"], |ctx| teardown(ctx, Slot::A))),
            "Slot a runs the active guardian. Only a standby can be torn down."
        );
        assert!(
            error(run.step(&["x"], |ctx| teardown(ctx, Slot::B)))
                .starts_with("Disable slot b first")
        );
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        // A guardian that activated, as a retiring one is until switchover stops it, is never torn down.
        run.lifecycle("b", "withdraw/ACTIVATED");
        assert!(
            error(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)))
                .contains("is activated and still runs")
        );
        assert!(run.state.borrow().deployed.contains_key("b"));
        // A standby that never served can be abandoned, with a warning.
        run.lifecycle("b", "withdraw/PROVISIONER_INITIALIZED");
        ok(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)));
        assert!(!run.state.borrow().deployed.contains_key("b"));
        assert!(Path::new(&run.repo.path().join(".hashi")).exists());
        // The relay still serves the host that's gone, which can't answer or run a round.
        ok(run.step(&["yes"], proxy_update));
        assert_eq!(run.state.borrow().standby, None);
    }

    #[test]
    fn tears_down_nothing_once_the_serving_guardian_stops_answering() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        // A provisioned standby may hold the only live copy of the key by then.
        let stops = |run: &Run| {
            run.state
                .borrow_mut()
                .hosts
                .get_mut("i-0aaa")
                .unwrap()
                .session
                .epoch = None;
        };
        let ask = Meanwhile {
            run: &run,
            change: stops,
            answer: standby,
        };
        assert_eq!(
            run.step_asking(&ask, |ctx| teardown(ctx, Slot::B))
                .unwrap_err()
                .to_string(),
            "Tear nothing down until a guardian serves."
        );
        assert!(run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn tears_down_a_stopped_guardian_without_reaching_it() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        // A stopped unit starts no session, and its guardian answers no tunnel.
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .running = false;
        ok(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)));
        assert!(!run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn waits_for_every_run_that_applies_the_guardian_stacks() {
        let mut run = Run::new();
        let runs = |run: &Run, runs: &[(&str, &str, &str)]| {
            run.state.borrow_mut().workflow_runs = runs
                .iter()
                .map(|(repo, status, path)| {
                    ((*repo).to_owned(), (*status).to_owned(), (*path).to_owned())
                })
                .collect();
        };
        runs(
            &run,
            &[
                ("org/infra", "waiting", ".github/workflows/lint.yml"),
                (
                    "org/other",
                    "waiting",
                    ".github/workflows/guardian-proxy.yaml",
                ),
            ],
        );
        ok(run.step(&[], proxy_update));
        // One waiting for an approval applies the stack once it gets one.
        runs(
            &run,
            &[(
                "org/infra",
                "waiting",
                ".github/workflows/guardian-proxy.yaml@refs/heads/main",
            )],
        );
        assert_eq!(
            error(run.step(&[], proxy_update)),
            "org/infra's .github/workflows/guardian-proxy.yaml has a run waiting, and it applies the guardian stacks too. Wait for it to finish."
        );

        // The proxy's workflow counts too, wherever it lives.
        runs(
            &run,
            &[("org/deploy", "queued", ".github/workflows/proxy.yaml")],
        );
        run.env.push((
            "GUARDIAN_PROXY_WORKFLOW".to_owned(),
            "org/deploy/.github/workflows/proxy.yaml@main".to_owned(),
        ));
        assert!(
            error(run.step(&[], proxy_update))
                .starts_with("org/deploy's .github/workflows/proxy.yaml has a run queued")
        );
        run.env.retain(|(key, _)| key != "GUARDIAN_WORKFLOWS");
        assert_eq!(
            error(run.step(&[], proxy_update)),
            "testnet.env does not set GUARDIAN_WORKFLOWS."
        );
    }

    #[test]
    fn tears_down_a_host_ec2_has_already_ended() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        // A teardown cut off once EC2 had begun ending the host, which SSM no longer reaches.
        run.state
            .borrow_mut()
            .ec2_states
            .insert(standby.clone(), "shutting-down".to_owned());
        ok(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)));
        assert!(!run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn applies_only_a_plan_of_exactly_its_shape() {
        let run = Run::new();
        let serving = format!("{}a", world::URN_PREFIX);
        let drift = |op: &str| Some((op.to_owned(), serving.clone()));
        run.state.borrow_mut().extra_change = drift("replace");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with("Arming slot b must create its instance and change nothing else")
        );
        assert!(!run.state.borrow().deployed.contains_key("b"));

        run.state.borrow_mut().extra_change = None;
        run.armed_and_provisioned();
        run.state.borrow_mut().extra_change = drift("update");
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        assert!(
            error(run.step(&[&standby], |ctx| teardown(ctx, Slot::B))).starts_with(
                "Tearing down slot b must delete its instance and change nothing else"
            )
        );
        assert!(run.state.borrow().deployed.contains_key("b"));
    }
}
