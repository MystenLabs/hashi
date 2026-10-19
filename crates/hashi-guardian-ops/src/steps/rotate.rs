// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Moving the guardian's key to a fresh host in the stack's other slot: `arm` a standby, `proxy-update`,
//! `switchover` and `teardown`. Every step re-reads the stack, the hosts and the proxy, applies only a targeted plan of
//! exactly the expected shape, and can run again to resume.

use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde_json::Value;
use serde_json::json;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::commit::Tree;
use crate::commit::require_same_formats;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;
use crate::github::require_no_guardian_runs;
use crate::guardian::CURRENT_FOR;
use crate::guardian::Lifecycle;
use crate::guardian::ProxyInfo;
use crate::guardian::proxy_info;
use crate::guardian::relay_info;
use crate::guardian::require_reached;
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
use crate::print_detail;
use crate::print_info;
use crate::print_success;
use crate::print_warning;
use crate::proxy::image_commit;
use crate::proxy::update_proxy;
use crate::render::Build;
use crate::render::Settings;
use crate::render::require_fresh;
use crate::stack::Bucket;
use crate::stack::INSTANCE;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::stack::is_hex;
use crate::stack::project_name;
use crate::stack::pulumi;
use crate::steps::session::activate;
use crate::steps::slot;
use crate::sui;
use crate::sui::require_epoch_window;

/// What declining the proxy update leaves once the stack has flipped.
const FLIPPED: Unchanged = Unchanged {
    no_input: "no input received; the stack has flipped, but the proxy still fronts the old guardian, which still serves; run switchover again to finish, or roll back",
    declined: "not confirmed; the stack has flipped, but the proxy still fronts the old guardian, which still serves; run switchover again to finish, or roll back",
};

/// What declining the stop leaves: the proxy fronting the new guardian, which serves nothing until it activates.
const STOP_DECLINED: Unchanged = Unchanged {
    no_input: "no input received; nothing was stopped, and the proxy fronts the new guardian, which serves nothing until it activates; run switchover again to finish, or roll back",
    declined: "not confirmed; nothing was stopped, and the proxy fronts the new guardian, which serves nothing until it activates; run switchover again to finish, or roll back",
};

/// The proxy's views are cached for 30 seconds, so waits for them to change poll this long.
const POLLS: usize = 12;
const POLL_INTERVAL: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(10)
};

const GUARDIAN_UNIT_STATE: &str = "if systemctl is-enabled --quiet hashi-guardian-enclave.service || systemctl is-active --quiet hashi-guardian-enclave.service; then echo GUARDIAN_RUNNING; else echo GUARDIAN_STOPPED; fi";

/// Fail unless a host's guardian is stopped for good. Its unit ignores a failed `terminate-enclave` when it stops, so
/// the enclave is checked apart from the unit.
const STOPPED_CHECKS: [&str; 2] = [
    "if systemctl is-enabled --quiet hashi-guardian-enclave.service || systemctl is-active --quiet hashi-guardian-enclave.service; then echo the enclave unit is still enabled or active; exit 1; fi",
    "enclaves=\"$(nitro-cli describe-enclaves)\" || { echo could not list the enclaves; exit 1; }; if printf '%s' \"$enclaves\" | grep -q EnclaveID; then echo an enclave still runs; exit 1; fi",
];

fn tree(ctx: &Ctx, view: &SlotView) -> Result<Tree> {
    Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )
}

/// Polls `check` until it returns something, up to two minutes.
fn poll<T>(mut check: impl FnMut() -> Option<T>) -> Option<T> {
    for attempt in 0..POLLS {
        if let Some(found) = check() {
            return Some(found);
        }
        if attempt + 1 < POLLS {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    None
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
            "arming slot {slot} must create its instance and change nothing else, but this plan does not; nothing was changed"
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
            "slot {slot}'s plan changed while this step waited for you; nothing was changed: run this step again"
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
            "stack {} no longer shows slot {active}'s guardian {serving} as active; check its outputs before going on",
            stack.name
        );
    }
    let Some(standby) = after.output("standby_instance_id") else {
        bail!(
            "stack {} lists no standby after arming slot {slot}; check its outputs",
            stack.name
        );
    };
    // Only the program knew which instance it would create, so check it is the standby the outputs name.
    if after.instance_urn(ctx, standby)?.as_deref() != Some(urn.as_str()) {
        bail!(
            "stack {}'s standby {standby} is not the instance arming slot {slot} created, {urn}; check the stack before going on",
            stack.name
        );
    }
    print_success(&format!(
        "Armed slot {slot} on {standby}. The host builds the enclave image at boot; follow it with host --slot {slot}, then run proxy-update so the relay reaches it."
    ));
    next(&format!(
        "host --slot {slot}, until its boot completes; then proxy-update"
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
        print_info(&format!(
            "Arming slot {slot} next to slot {active}'s guardian"
        ));
    }
    if view.role != Role::Absent {
        bail!("slot {slot} already runs a guardian, as the {}", view.role);
    }
    require_pulumi_version(ctx)?;
    require_no_guardian_runs(ctx)?;
    let Some(serving) = serving.filter(|_| active != slot) else {
        bail!(
            "slot {slot} is the stack's active slot; arm adds a standby next to a serving guardian"
        );
    };
    if !stack.slot_enabled(slot)? {
        bail!(
            "enable slot {slot} first: set slot-{slot}-enabled to \"true\" in stack {}'s Pulumi.<stack>.yaml",
            stack.name
        );
    }
    let configured_active = stack.config("active-slot").unwrap_or("a");
    if configured_active != active.to_string() {
        bail!(
            "stack {} configures active-slot {configured_active}, but slot {active} is active; set it back before arming",
            stack.name
        );
    }
    let pcr0 = stack.config(&view.pcr0_key).unwrap_or("");
    if !is_hex(pcr0, 96) {
        bail!(
            "stack {}'s {} is not a PCR0 measurement: {}; measure slot {slot}'s build with measure --slot {slot}, and set it to the PCR0 that prints",
            stack.name,
            view.pcr0_key,
            if pcr0.is_empty() { "unset" } else { pcr0 }
        );
    }
    let settings = Settings::read(ctx, &stack, &view)?;
    require_proxy_decodes(ctx, &stack, &view)?;
    let (suffix, active_suffix) = (slot.suffix(), active.suffix());
    for key in ["eif-features", "eif-ceremony-mode"] {
        if stack.config(&format!("{key}{suffix}")).is_some()
            || stack.config(&format!("{key}{active_suffix}")).is_some()
        {
            bail!(
                "stack {} sets {key} for a slot; a real guardian builds with neither: unset it",
                stack.name
            );
        }
    }
    let tags = stack.rotation_tags(ctx)?;
    if !tags.is_empty() {
        bail!(
            "stack {} has rotation tags, which hold rotation state apart from its configuration: {}; this flow keeps it in Pulumi.<stack>.yaml, so clear them once you know the yaml says the same",
            stack.name,
            tags.join(", ")
        );
    }
    serving_info(ctx).context("arm a standby only next to a serving guardian")?;
    require_keeps_serving(ctx, &stack, &view, &settings)?;
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
            "stack {}'s plan creates {} guardian instances, not slot {slot}'s one: {}",
            stack.name,
            instances.len(),
            instances.join(" ")
        );
    };
    if !others.is_empty() {
        bail!(
            "stack {} also plans to create resources that arming slot {slot} would leave out; create them first, from {}: pulumi up --stack {} {}",
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

/// Stops unless the proxy's build decodes what the slot's guardian sends, as it must to relay or front it. A guardian
/// on the active slot's build needs no check: the proxy already serves that one.
fn require_proxy_decodes(ctx: &Ctx, stack: &Stack, view: &SlotView) -> Result<()> {
    let active = stack.active()?;
    if stack.config(&format!("hashi-commit{}", active.suffix())) != Some(view.commit.as_str()) {
        require_same_formats(
            ctx,
            &view.commit,
            &image_commit(ctx, stack)?,
            "the proxy's build",
        )?;
    }
    Ok(())
}

/// Applies the proxy stack so the proxy follows the enclave stack's slots.
pub fn proxy_update(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    print_info(&format!(
        "Updating the proxy of stack {} to follow its guardian slots",
        stack.name
    ));
    require_no_guardian_runs(ctx)?;
    let other = stack.active()?.other();
    if stack.role(other)? == Role::Standby {
        require_proxy_decodes(ctx, &stack, &stack.slot(ctx, other)?)?;
    }
    let view = stack.slot(ctx, stack.active()?)?;
    update_proxy(
        ctx,
        &stack,
        &tree(ctx, &view)?,
        &NOTHING_CHANGED,
        &|| Ok(()),
    )?;
    print_success(&format!(
        "The proxy answers at {}.",
        ctx.env.proxy_url()?.url
    ));
    Ok(())
}

/// Makes the slot's provisioned standby the serving guardian: flips the active slot, points the proxy at it, stops the
/// old guardian for good, and activates the new one. Each phase is decided from live state, so a rerun resumes where
/// an earlier run stopped.
pub fn switchover(ctx: &Ctx, slot_arg: Slot) -> Result<()> {
    let mut stack = Stack::load(ctx)?;
    let mut view = stack.slot(ctx, slot_arg)?;
    let bucket = stack.bucket()?;
    let slot = view.slot;
    let other = slot.other();
    let tree = tree(ctx, &view)?;
    let guardian_init = tree.guardian_init(ctx)?;
    // The stack reports only an enabled slot's instance, and every run must find the old guardian to stop it.
    if !stack.slot_enabled(other)? {
        bail!(
            "keep slot-{other}-enabled \"true\" in stack {}'s Pulumi.<stack>.yaml until slot {other}'s teardown: switchover finds the guardian it stops through it",
            stack.name
        );
    }
    // One reading of the epoch sets this run's deadlines, which each phase checks right before it acts.
    let window = sui::window(ctx, sui::now())?;

    if stack.active()? != slot {
        print_info(&format!(
            "Checking that slot {slot}'s guardian is ready to serve"
        ));
        if view.role != Role::Standby {
            bail!("slot {slot} runs no standby guardian to switch over to");
        }
        require_fresh(ctx, &stack, &view)?;
        let reached = require_reached(ctx, &stack, &view, &tree)?;
        let lifecycle = &reached.info.lifecycle;
        if !lifecycle.is("withdraw/PROVISIONER_INITIALIZED") {
            bail!(
                "slot {slot}'s guardian is {lifecycle}, not provisioned and waiting for activation"
            );
        }
        let serving = serving_info(ctx)?;
        let standby_btc = reached.info.btc_key.as_deref();
        if standby_btc.is_none() || standby_btc != serving.btc_pubkey.as_deref() {
            bail!(
                "slot {slot}'s guardian holds BTC key {}, but the serving guardian holds {}",
                standby_btc.unwrap_or("none"),
                serving.btc_pubkey.as_deref().unwrap_or("none")
            );
        }
        let serving_key = serving
            .signing_pub_key
            .as_deref()
            .filter(|key| crate::stack::is_hex(key, 64))
            .ok_or_else(|| anyhow!("the proxy's /info names no serving guardian's signing key"))?;
        let serving_init = OperatorInit::read(ctx, &bucket, serving_key)?;
        let standby_config = reached.info.config_hash.as_deref();
        if standby_config != Some(serving_init.config_hash.as_str()) {
            // The hash covers the PCR allowlist too, which a rotation onto another build extends.
            let standby_init = OperatorInit::read(ctx, &bucket, &reached.signing_key)?;
            if standby_config != Some(standby_init.config_hash.as_str())
                || !standby_init.keeps(&serving_init)
            {
                bail!(
                    "slot {slot}'s guardian has config hash {}, but the serving guardian has {}; their limiter or deployment block differ, and switching over would change them",
                    standby_config.unwrap_or("none"),
                    serving_init.config_hash
                );
            }
        }
        require_initialized_as_rendered(ctx, &stack, &view, &bucket, &reached.signing_key)?;
        // The monitor reads both builds' records: the serving one's through the switchover and its re-audits after.
        require_monitor_allows(ctx, &stack, &[&view, &stack.slot(ctx, other)?])?;
        require_proxy_decodes(ctx, &stack, &view)?;
        require_pulumi_version(ctx)?;
        require_no_guardian_runs(ctx)?;
        require_epoch_window(&window, serving.committee_epoch.as_deref())?;
        if stack.config("active-slot") != Some(&slot.to_string()) {
            bail!(
                "set active-slot to {slot} in stack {}'s Pulumi.<stack>.yaml first, and commit it",
                stack.name
            );
        }

        print_info(&format!("Making slot {slot} the stack's active slot"));
        let old_instance = stack.output("enclave_instance_id").map(str::to_owned);
        let instance = view.require_instance(&stack)?.to_owned();
        let Some(urn) = stack.instance_urn(ctx, &instance)? else {
            bail!(
                "could not find slot {slot}'s instance {instance} in stack {}'s state",
                stack.name
            );
        };
        if !preview_slot(ctx, &stack, &urn)?.is_empty() {
            bail!(
                "flipping the active slot must change no resource, but this plan does; nothing was changed"
            );
        }
        print_warning(
            "From here until activation, nodes' new withdrawals fail and are retried: through the proxy's update, then the ten minutes activation waits once the old guardian stops, about 15 to 20 minutes in all. Until the old guardian stops, you can still roll back to it.",
        );
        confirm(
            ctx.ask,
            &format!("Make slot {slot} the active slot?"),
            &NOTHING_CHANGED,
        )?;
        // The question can wait any time, while a yaml edit or a workflow changes what the flip would apply.
        if !preview(ctx, &stack.dir, &stack.name, Some(&urn))?
            .changes()
            .is_empty()
        {
            bail!(
                "slot {slot}'s plan changed while this step waited for you; nothing was changed: run this step again"
            );
        }
        require_no_guardian_runs(ctx)?;
        up_slot(ctx, &stack, &urn)?;
        stack = Stack::load(ctx)?;
        // A target that names nothing applies cleanly too, so check the flip happened before relying on it.
        if stack.active()? != slot
            || stack.output("enclave_instance_id") != Some(instance.as_str())
            || stack.output("standby_instance_id").map(str::to_owned) != old_instance
        {
            bail!(
                "stack {}'s outputs did not flip to slot {slot}; nothing else was changed: check its outputs",
                stack.name
            );
        }
        view = stack.slot(ctx, slot)?;
    }

    let info = slot_info(ctx, &tree, &view)?;
    let (Some(signing_key), Some(slot_btc)) = (info.signing_key.clone(), info.btc_key.clone())
    else {
        bail!(
            "slot {slot}'s guardian did not report its signing and BTC keys at {}",
            view.endpoint
        );
    };
    let activated = info.lifecycle.is("withdraw/ACTIVATED");
    if !activated {
        // A rerun can come long after the checks before the flip.
        require_no_guardian_runs(ctx)?;
        require_initialized_as_rendered(ctx, &stack, &view, &bucket, &signing_key)?;
    }
    let fronts = |info: &ProxyInfo| info.signing_pub_key.as_deref() == Some(signing_key.as_str());
    if !proxy_info(ctx).is_ok_and(|info| fronts(&info)) {
        print_info(&format!("Pointing the proxy at slot {slot}'s guardian"));
        if !activated && let Some(refusal) = window.refusal() {
            bail!("{refusal}");
        }
        let front_by = window.end - sui::REMAINING_SECS;
        update_proxy(ctx, &stack, &tree, &FLIPPED, &|| {
            if !activated && sui::now() > front_by {
                bail!(
                    "Sui epoch {} ends in under {} now, too soon for slot {slot}'s guardian to activate in it; the stack has flipped, but the proxy still fronts slot {other}'s guardian: run this step again once the next epoch has settled, or roll back",
                    window.epoch,
                    sui::duration(sui::REMAINING_SECS)
                );
            }
            Ok(())
        })?;
        if poll(|| proxy_info(ctx).ok().filter(fronts)).is_none() {
            bail!(
                "the proxy does not front slot {slot}'s guardian two minutes after its update; the old guardian still runs: check the proxy before going on"
            );
        }
    }

    if let Some(old_instance) = stack.output("standby_instance_id") {
        let state = guardian_unit_state(ctx, &bucket.region, old_instance)
            .with_context(|| format!("could not read slot {other}'s host {old_instance}"))?;
        if state.contains("GUARDIAN_RUNNING") {
            print_info(&format!("Stopping slot {other}'s guardian"));
            let stop_by = window.end - sui::STOP_REMAINING_SECS;
            // What the stop and the activation after it rely on, checked again once the question below is answered.
            let ready = || -> Result<()> {
                // A run that replaces a host meanwhile could leave neither guardian holding the key.
                require_no_guardian_runs(ctx)?;
                // Nothing activation needs may be found wrong only after the stop.
                if !activated {
                    require_fresh(ctx, &stack, &view)?;
                }
                require_monitor_allows(ctx, &stack, &[&view, &stack.slot(ctx, other)?])?;
                let now = slot_info(ctx, &tree, &view)?;
                if now.signing_key.as_deref() != Some(signing_key.as_str())
                    || now.lifecycle != info.lifecycle
                {
                    bail!(
                        "slot {slot}'s guardian is {} now, not the session {} in {} that this run checked; nothing was stopped: run this step again",
                        now.lifecycle,
                        &signing_key[..16],
                        info.lifecycle
                    );
                }
                // The relay still reaches the old guardian: the last check that it is the one that served, with one key.
                let old = relay_info(ctx, &tree).with_context(|| {
                    format!(
                        "could not confirm through the relay that slot {other}'s guardian is the activated one; nothing was stopped"
                    )
                })?;
                if old.btc_key.as_deref() != Some(slot_btc.as_str())
                    || old.signing_key.as_deref() == Some(signing_key.as_str())
                    || !old.lifecycle.is("withdraw/ACTIVATED")
                {
                    bail!(
                        "could not confirm through the relay that slot {other}'s guardian is the activated one, holding slot {slot}'s BTC key {slot_btc}; nothing was stopped"
                    );
                }
                let left = window.end - sui::now();
                if !activated && sui::now() > stop_by {
                    bail!(
                        "Sui epoch {} ends in about {}, too soon for slot {slot}'s guardian to activate before it once slot {other}'s stops; nothing was stopped; so that slot {other}'s guardian serves through the epoch's turn, roll back to it: set active-slot back to {other}, apply that with a pulumi up targeted at the URN the flip's plan printed, and run proxy-update; then switch over again once the next epoch has settled",
                        window.epoch,
                        sui::duration(left)
                    );
                }
                Ok(())
            };
            ready()?;
            print_warning(&format!(
                "Stopping slot {other}'s guardian on {old_instance} cannot be undone: its copy of the key is gone, and only slot {slot}'s guardian holds it in memory after this."
            ));
            confirm_typed(
                ctx.ask,
                old_instance,
                &format!("to stop slot {other}'s guardian for good"),
                &STOP_DECLINED,
            )?;
            ready()?;
            let stopped = host::run(
                ctx,
                &bucket.region,
                old_instance,
                &[
                    "systemctl disable --now hashi-guardian-enclave.service hashi-guardian-bridge.service",
                    STOPPED_CHECKS[0],
                    STOPPED_CHECKS[1],
                ],
            )
            .with_context(|| {
                format!(
                    "the stop of slot {other}'s guardian on {old_instance} may have run; run this step again: it checks the host first"
                )
            })?;
            if !stopped.success {
                print_detail(&stopped.text);
                bail!(
                    "stopping slot {other}'s guardian did not finish; run this step again: it checks the host first"
                );
            }
            print_success(&format!("Stopped slot {other} guardian on {old_instance}."));
        } else if !activated {
            // Activation waits for the old guardian to fall quiet, which an enclave left running never does.
            let stopped = host::run(ctx, &bucket.region, old_instance, &STOPPED_CHECKS)?;
            if !stopped.success {
                print_detail(&stopped.text);
                bail!(
                    "slot {other}'s guardian unit on {old_instance} is stopped, but the host still runs an enclave or could not say; terminate it there with nitro-cli terminate-enclave --all, then run this step again"
                );
            }
        }
    }

    if !activated {
        print_info(&format!("Activating slot {slot}'s guardian"));
        require_fresh(ctx, &stack, &view)?;
        activate(ctx, &tree, &guardian_init, &view)?;
    }

    print_info(&format!(
        "Checking that the proxy serves slot {slot}'s guardian"
    ));
    let serves = |info: &ProxyInfo| {
        fronts(info)
            && info.btc_pubkey.as_deref() == Some(slot_btc.as_str())
            && info.git_revision.as_deref() == Some(view.commit.as_str())
            && info.committee_epoch.is_some()
            && info.age().is_some_and(|age| age <= CURRENT_FOR)
    };
    let Some(serving) = poll(|| proxy_info(ctx).ok().filter(serves)) else {
        bail!(
            "the proxy's /info does not show slot {slot}'s activated guardian: {}",
            proxy_info(ctx).map_or_else(|error| format!("{error:#}"), |info| format!("{info:?}"))
        );
    };
    print_success(&format!(
        "Slot {slot}'s guardian serves at committee epoch {}, with BTC key {slot_btc}.",
        serving.committee_epoch.as_deref().unwrap_or("")
    ));
    // A committee handoff while the proxy fronted the guardian before its activation reached it as nothing. The
    // guardian serves by now, so a failed read only goes unchecked.
    match sui::window(ctx, sui::now()) {
        Ok(now)
            if now.since >= sui::SETTLE_SECS
                && serving.committee_epoch.as_deref() != Some(now.epoch.to_string().as_str()) =>
        {
            print_warning(&format!(
                "Slot {slot}'s guardian holds committee epoch {}, but Sui is at epoch {}, and it refuses what the newer committee signs. Restart hashi's leader, which hands the guardian the committees it missed.",
                serving.committee_epoch.as_deref().unwrap_or("none"),
                now.epoch
            ));
        }
        Ok(_) => {}
        Err(error) => print_warning(&format!(
            "Could not read the Sui epoch, so this step did not check that slot {slot}'s guardian holds the current committee: {error:#}"
        )),
    }
    print_info(&format!(
        "Once it has served for a while, tear down slot {other} with teardown --slot {other}."
    ));
    next(&format!(
        "after a soak, set slot-{other}-enabled to \"false\" and run teardown --slot {other}"
    ));
    Ok(())
}

/// `BITCOIN_NETWORK` as a guardian logs it: it reads mainnet as bitcoin, in any case, and writes it lowercase.
fn logged_network(settings: &Settings) -> String {
    match settings.bitcoin_network.to_ascii_lowercase().as_str() {
        "mainnet" => "bitcoin".to_owned(),
        network => network.to_owned(),
    }
}

/// Stops unless the slot's rendered files, which activation reads, hold what its guardian was initialized with.
fn require_initialized_as_rendered(
    ctx: &Ctx,
    stack: &Stack,
    view: &SlotView,
    bucket: &Bucket,
    signing_key: &str,
) -> Result<()> {
    OperatorInit::read(ctx, bucket, signing_key)?
        .require_rendered(&Settings::read(ctx, stack, view)?, view.slot)
}

/// A withdraw session's configuration, from its operator-init record. Activation drops the configuration hash from a
/// guardian's own report, so a serving session's is read here.
struct OperatorInit {
    config_hash: String,
    limiter: Value,
    deployment: Value,
}

impl OperatorInit {
    /// The record of the session named by the start of its signing key. It must have one version, as a guardian
    /// requires of each record it reads.
    fn read(ctx: &Ctx, bucket: &Bucket, signing_key: &str) -> Result<Self> {
        let session = signing_key
            .get(..16)
            .ok_or_else(|| anyhow!("{signing_key} is not a guardian's signing key"))?;
        let key = format!("init/{session}/02-oi-guardian-info.json");
        let url = format!("s3://{}/{key}", bucket.name);
        let versions = read(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3api", "list-object-versions", "--region", &bucket.region])
                .args(["--bucket", &bucket.name, "--prefix", &key])
                .arg("--query")
                .arg(format!(
                    "[length(Versions[?Key=='{key}'] || `[]`), length(DeleteMarkers[?Key=='{key}'] || `[]`)]"
                ))
                .args(["--output", "text"]),
        )
        .with_context(|| format!("could not list the versions of {url}"))?;
        match versions.split_whitespace().collect::<Vec<_>>()[..] {
            ["1", "0"] => {}
            ["0", "0"] => bail!("there is no {url}"),
            _ => bail!(
                "{url} has versions or delete markers beside the one its guardian wrote ({}); find out who wrote them before going on",
                versions.trim()
            ),
        }
        let record: Value = read_json(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3", "cp", "--only-show-errors", "--region", &bucket.region])
                .arg(&url)
                .arg("-"),
        )
        .with_context(|| format!("could not read {url}"))?;
        let info = record.pointer("/message/Init/OIGuardianInfo");
        let withdraw = info.and_then(|info| info.pointer("/mode/Withdraw"));
        let (Some(config_hash), Some(limiter), Some(deployment)) = (
            withdraw
                .and_then(|withdraw| withdraw.get("config_hash"))
                .and_then(Value::as_str),
            withdraw.and_then(|withdraw| withdraw.get("limiter_config")),
            info.and_then(|info| info.get("deployment")),
        ) else {
            bail!("{url} is not a withdraw session's operator-init record");
        };
        Ok(Self {
            config_hash: config_hash.to_owned(),
            limiter: limiter.clone(),
            deployment: deployment.clone(),
        })
    }

    /// Stops unless `settings` give this session's limiter and deployment exactly: activation recomputes its
    /// configuration hash from them, the allowlist's order included.
    fn require_rendered(&self, settings: &Settings, slot: Slot) -> Result<()> {
        let deployment = json!({
            "bucket_info": { "name": settings.bucket, "region": settings.region },
            "retention_environment": settings.retention_environment,
            "bitcoin_network": logged_network(settings),
            "pcr_allowlist": {
                "current_build": {
                    "git_revision": settings.commit,
                    "pcr0": settings.pcr0.to_ascii_lowercase(),
                },
                "prev_builds": settings
                    .prev_builds
                    .iter()
                    .map(|build| json!({
                        "git_revision": build.commit,
                        "pcr0": build.pcr0.to_ascii_lowercase(),
                    }))
                    .collect::<Vec<_>>(),
            },
        });
        let limiter = json!({
            "refill_rate": settings.refill_rate,
            "max_bucket_capacity": settings.max_bucket_capacity,
        });
        if self.deployment != deployment || self.limiter != limiter {
            bail!(
                "slot {slot}'s configurations give limiter {limiter} and deployment {deployment}, but its guardian was initialized with limiter {} and deployment {}; activating it would fail once the old guardian has stopped: render the settings it was initialized with",
                self.limiter,
                self.deployment
            );
        }
        Ok(())
    }

    /// Whether this session keeps `serving`'s limiter and deployment, its PCR allowlist only adding builds to
    /// `serving`'s.
    fn keeps(&self, serving: &Self) -> bool {
        let split = |deployment: &Value| -> Option<(Value, Vec<Value>)> {
            let mut rest = deployment.as_object()?.clone();
            let allowlist = rest.remove("pcr_allowlist")?;
            let mut builds = vec![allowlist.get("current_build")?.clone()];
            builds.extend(allowlist.get("prev_builds")?.as_array()?.iter().cloned());
            Some((Value::Object(rest), builds))
        };
        let (Some((rest, builds)), Some((serving_rest, serving_builds))) =
            (split(&self.deployment), split(&serving.deployment))
        else {
            return false;
        };
        self.limiter == serving.limiter
            && rest == serving_rest
            && serving_builds.iter().all(|build| builds.contains(build))
    }

    fn prev_builds(&self) -> Option<Vec<Build>> {
        self.deployment
            .pointer("/pcr_allowlist/prev_builds")?
            .as_array()?
            .iter()
            .map(build_of)
            .collect()
    }
}

fn build_of(value: &Value) -> Option<Build> {
    Some(Build {
        commit: value.get("git_revision")?.as_str()?.to_owned(),
        pcr0: value.get("pcr0")?.as_str()?.to_owned(),
    })
}

/// The build each session of the log ran, from its operator-init record.
fn session_builds(ctx: &Ctx, bucket: &Bucket) -> Result<Vec<(String, Build)>> {
    let keys: Vec<String> = read_json(
        ctx.exec,
        &Cmd::new("aws")
            .args(["s3api", "list-objects-v2", "--region", &bucket.region])
            .args(["--bucket", &bucket.name, "--prefix", "init/"])
            .args(["--query", "Contents[].Key || `[]`", "--output", "json"]),
    )
    .with_context(|| format!("could not list s3://{}/init/", bucket.name))?;
    let mut builds = Vec::new();
    for key in keys {
        let Some(session) = key
            .strip_prefix("init/")
            .and_then(|rest| rest.strip_suffix("/02-oi-guardian-info.json"))
        else {
            continue;
        };
        let record: Value = read_json(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3", "cp", "--only-show-errors", "--region", &bucket.region])
                .arg(format!("s3://{}/{key}", bucket.name))
                .arg("-"),
        )
        .with_context(|| format!("could not read s3://{}/{key}", bucket.name))?;
        let build = record
            .pointer("/message/Init/OIGuardianInfo/deployment/pcr_allowlist/current_build")
            .and_then(build_of)
            .ok_or_else(|| anyhow!("s3://{}/{key} names no build", bucket.name))?;
        builds.push((session.to_owned(), build));
    }
    Ok(builds)
}

/// Stops unless a standby's settings keep the serving guardian's limiter and deployment, and allowlist every build that
/// ran a session in the log and every one the serving guardian allowlists. Guardians and key provisioners verify the
/// records of every recent session, and switchover refuses less, but only once the standby is provisioned.
pub(crate) fn require_keeps_serving(
    ctx: &Ctx,
    stack: &Stack,
    view: &SlotView,
    settings: &Settings,
) -> Result<()> {
    let bucket = stack.bucket()?;
    let serving_key = proxy_info(ctx)?
        .signing_pub_key
        .filter(|key| is_hex(key, 64))
        .ok_or_else(|| anyhow!("the proxy's /info names no serving guardian's signing key"))?;
    let serving = OperatorInit::read(ctx, &bucket, &serving_key)?;
    for (name, theirs, ours) in [
        (
            "refill-rate-sats-per-sec",
            serving.limiter.get("refill_rate"),
            Value::from(settings.refill_rate),
        ),
        (
            "max-bucket-capacity-sats",
            serving.limiter.get("max_bucket_capacity"),
            Value::from(settings.max_bucket_capacity),
        ),
        (
            "the log bucket",
            serving.deployment.pointer("/bucket_info/name"),
            Value::from(settings.bucket.as_str()),
        ),
        (
            "the log bucket's region",
            serving.deployment.pointer("/bucket_info/region"),
            Value::from(settings.region.as_str()),
        ),
        (
            "RETENTION_ENVIRONMENT",
            serving.deployment.get("retention_environment"),
            Value::from(settings.retention_environment.as_str()),
        ),
        (
            "BITCOIN_NETWORK",
            serving.deployment.get("bitcoin_network"),
            Value::from(logged_network(settings)),
        ),
    ] {
        if theirs != Some(&ours) {
            bail!(
                "slot {}'s configurations give {name} as {ours}, but the serving guardian's give {}; a switchover keeps the serving guardian's limiter and deployment block: set it back",
                view.slot,
                theirs.map_or("none".to_owned(), Value::to_string)
            );
        }
    }
    let serving_prev = serving.prev_builds().ok_or_else(|| {
        anyhow!(
            "could not read the builds the serving guardian {} allowlists",
            &serving_key[..16]
        )
    })?;
    require_lists_log_builds(
        ctx,
        stack,
        view,
        settings,
        serving_prev
            .into_iter()
            .map(|build| (build, "the serving guardian allowlists it".to_owned()))
            .collect(),
    )
}

/// Stops unless `settings` allowlist each build that wrote the stack's log, and each of `also`: a reader resolves a
/// record's writer by that session's own build, so a guardian that leaves one out can't read what it wrote.
pub(crate) fn require_lists_log_builds(
    ctx: &Ctx,
    stack: &Stack,
    view: &SlotView,
    settings: &Settings,
    also: Vec<(Build, String)>,
) -> Result<()> {
    let required = session_builds(ctx, &stack.bucket()?)?
        .into_iter()
        .map(|(session, build)| (build, format!("session {session} ran it")))
        .chain(also);
    let own = Build {
        commit: settings.commit.clone(),
        pcr0: settings.pcr0.clone(),
    };
    let mut missing: Vec<(Build, String)> = Vec::new();
    for (build, why) in required {
        match std::iter::once(&own)
            .chain(&settings.prev_builds)
            .find(|listed| listed.commit == build.commit)
        {
            Some(listed) if listed.pcr0 == build.pcr0 => {}
            Some(listed) => bail!(
                "slot {}'s configurations measure {} as {}, but {why} as {}",
                view.slot,
                build.commit,
                listed.pcr0,
                build.pcr0
            ),
            None if missing.iter().any(|(seen, _)| seen.commit == build.commit) => {}
            None => missing.push((build, why)),
        }
    }
    if !missing.is_empty() {
        bail!(
            "slot {}'s configurations leave out {}; every guardian of the log must allowlist those builds: add each to prev-builds in stack {}'s Pulumi.<stack>.yaml, as its git_revision and the pcr0 its own measurement gave, never one read from the log bucket",
            view.slot,
            missing
                .iter()
                .map(|(build, why)| format!("{} ({why})", build.commit))
                .collect::<Vec<_>>()
                .join("; "),
            stack.name
        );
    }
    Ok(())
}

/// Stops unless hashi-monitor, where `HASHI_MONITOR_PULUMI_DIR` names its program, allowlists each of these slots'
/// builds: it rejects every record from a build it doesn't.
fn require_monitor_allows(ctx: &Ctx, stack: &Stack, views: &[&SlotView]) -> Result<()> {
    let Some(dir) = ctx.env.get("HASHI_MONITOR_PULUMI_DIR") else {
        print_warning(
            "HASHI_MONITOR_PULUMI_DIR is unset, so this step did not check that hashi-monitor allowlists the guardians' builds.",
        );
        return Ok(());
    };
    project_name(dir)?;
    let entry: Value = read_json(
        ctx.exec,
        &pulumi(dir).args(["config", "get", "audit", "--json", "--stack", &stack.name]),
    )
    .with_context(|| {
        format!(
            "could not read the audit configuration of hashi-monitor's stack {} in {dir}",
            stack.name
        )
    })?;
    let audit = entry
        .get("objectValue")
        .cloned()
        .or_else(|| serde_json::from_str(entry.get("value")?.as_str()?).ok());
    let allowlist = audit
        .as_ref()
        .and_then(|audit| audit.pointer("/deployment/pcr_allowlist"));
    let builds: Vec<&Value> = allowlist
        .and_then(|allowlist| allowlist.get("current_build"))
        .into_iter()
        .chain(
            allowlist
                .and_then(|allowlist| allowlist.get("prev_builds"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .collect();
    for view in views {
        let pcr0 = stack.config(&view.pcr0_key).unwrap_or("");
        let listed = builds
            .iter()
            .filter_map(|build| build_of(build))
            .any(|build| {
                build.commit == view.commit
                    && !pcr0.is_empty()
                    && build.pcr0.eq_ignore_ascii_case(pcr0)
            });
        if !listed {
            bail!(
                "hashi-monitor does not allowlist {} with PCR0 {}; add it to deployment.pcr_allowlist in the audit configuration of stack {} in {dir}, keeping every build already there, deploy that stack, then run this step again",
                view.commit,
                if pcr0.is_empty() { "unset" } else { pcr0 },
                stack.name
            );
        }
    }
    Ok(())
}

/// Destroys a standby slot's host: the retired guardian after a switchover, or a standby that never served.
pub fn teardown(ctx: &Ctx, slot_arg: Slot) -> Result<()> {
    let (stack, view) = slot(ctx, Some(slot_arg))?;
    stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    let slot = view.slot;
    print_info(&format!(
        "Tearing down slot {slot}'s guardian host {instance}"
    ));
    if view.role != Role::Standby {
        bail!("slot {slot} runs the active guardian; only a standby can be torn down");
    }
    require_pulumi_version(ctx)?;
    require_no_guardian_runs(ctx)?;
    if stack.slot_enabled(slot)? {
        bail!(
            "disable slot {slot} first: set slot-{slot}-enabled to \"false\" in stack {}'s Pulumi.<stack>.yaml, and commit it",
            stack.name
        );
    }
    let active = stack.active()?;
    let configured_active = stack.config("active-slot").unwrap_or("a");
    if configured_active != active.to_string() {
        bail!(
            "stack {} configures active-slot {configured_active}, but slot {active} is active",
            stack.name
        );
    }
    serving_info(ctx).context("tear nothing down until a guardian serves")?;
    let Some(host) = stack
        .instances(ctx)?
        .into_iter()
        .find(|resource| resource.id.as_deref() == Some(instance))
    else {
        bail!(
            "could not find slot {slot}'s instance {instance} in stack {}'s state",
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
            .with_context(|| format!("could not read slot {slot}'s host"))?;
        if state.contains("GUARDIAN_STOPPED") {
            return Ok(None);
        }
        // A retiring guardian still signs until the switchover step stops it; a standby never has.
        let lifecycle = slot_info(ctx, &tree(ctx, &view)?, &view)?.lifecycle;
        if lifecycle.is("withdraw/ACTIVATED") {
            bail!(
                "slot {slot}'s guardian on {instance} is activated and still runs; stop it with the switchover step first"
            );
        }
        Ok(Some(lifecycle))
    };
    let found = guardian()?;
    match &found {
        None => print_info(&format!(
            "No guardian runs on slot {slot}'s host {instance}."
        )),
        Some(lifecycle) => print_warning(&format!(
            "Slot {slot}'s guardian still runs ({lifecycle}). Tearing it down abandons it: what was provisioned or dealt to it is lost."
        )),
    }
    let changes = preview_slot(ctx, &stack, &host.urn)?;
    if changes != [Change::new("delete", &host.urn)] {
        bail!(
            "tearing down slot {slot} must delete its instance and change nothing else, but this plan does not; nothing was changed"
        );
    }
    confirm_typed(
        ctx.ask,
        instance,
        &format!("to destroy slot {slot}'s host"),
        &NOTHING_CHANGED,
    )?;
    // The question can wait any time, while the stack's configuration, either guardian or the plan changes.
    serving_info(ctx).context("tear nothing down until a guardian serves")?;
    let now = Stack::load(ctx)?;
    if now.slot_enabled(slot)?
        || now.active()? != active
        || now.config("active-slot").unwrap_or("a") != configured_active
        || now.instance(slot)? != Some(instance)
        || guardian()? != found
        || preview(ctx, &now.dir, &now.name, Some(&host.urn))?.changes() != changes
    {
        bail!(
            "slot {slot}'s guardian, configuration or plan changed while this step waited for you; nothing was changed: run this step again"
        );
    }
    require_no_guardian_runs(ctx)?;
    up_slot(ctx, &now, &host.urn)?;
    let after = Stack::load(ctx)?;
    if after.output("standby_instance_id").is_some() || after.active()? != active {
        bail!(
            "stack {}'s outputs do not show slot {active} alone; check them before going on",
            stack.name
        );
    }
    print_success(&format!(
        "Tore down slot {slot}. Run proxy-update, so the relay stops pointing at it."
    ));
    if stack.config(&format!("hashi-commit{}", active.suffix())) != Some(view.commit.as_str()) {
        print_warning(&format!(
            "Slot {slot}'s build {} may have written the log, so every later guardian allowlists it. Before you point hashi-commit{} at another build, add this one to prev-builds in stack {}'s Pulumi.<stack>.yaml, unless it lists it already.",
            view.commit,
            slot.suffix(),
            stack.name
        ));
    }
    next("proxy-update");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::json;

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

        /// Gives slot b a later, measured build, beside a proxy built at slot a's.
        fn on_next_build(&self) {
            std::fs::create_dir_all(
                self.repo
                    .path()
                    .join(".hashi/guardian-init")
                    .join(world::NEXT),
            )
            .unwrap();
            self.set("hashi-commit-b", world::NEXT);
            self.set("eif-pcr0-b", &"0d".repeat(48));
            let mut state = self.state.borrow_mut();
            state.configured_tag = world::COMMIT[..9].to_owned();
            state.running_tag = state.configured_tag.clone();
        }

        /// A hashi-monitor that audits the guardian, allowlisting `builds`.
        fn monitor_config(&mut self, builds: &[(&str, &str)]) {
            world::monitor(&mut self.env);
            self.state.borrow_mut().monitor_builds = Some(
                builds
                    .iter()
                    .map(|(commit, pcr0)| ((*commit).to_owned(), (*pcr0).to_owned()))
                    .collect(),
            );
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
    fn moves_the_key_from_slot_a_to_slot_b() {
        let run = Run::new();
        let prompts = ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        assert_eq!(prompts, ["Create slot b's guardian host? [y/N] "]);
        let standby = run.instance("b");
        ok(run.step(&["yes"], proxy_update));
        let standby_ip = run.state.borrow().hosts[&standby].ip.clone();
        assert_eq!(
            run.state.borrow().standby,
            Some(format!("http://{standby_ip}:3000"))
        );
        world::provision(&run.state, Slot::B);
        run.render(Slot::B);
        run.set("active-slot", "b");

        let old = run.instance("a");
        let prompts = ok(run.step(&["yes", "yes", &old], |ctx| switchover(ctx, Slot::B)));
        assert_eq!(
            prompts,
            [
                "Make slot b the active slot? [y/N] ".to_owned(),
                "Update the proxy of stack org/testnet? [y/N] ".to_owned(),
                format!("Type {old} to stop slot a's guardian for good: "),
            ]
        );
        {
            let state = run.state.borrow();
            assert_eq!(state.outputs_active, Slot::B);
            assert!(!state.hosts[&old].running);
            assert_eq!(
                state.hosts[&standby].session.lifecycle,
                "withdraw/ACTIVATED"
            );
        }
        // Run again, it finds nothing left to do.
        assert!(ok(run.step(&[], |ctx| switchover(ctx, Slot::B))).is_empty());

        run.set("slot-a-enabled", "false");
        let prompts = ok(run.step(&[&old], |ctx| teardown(ctx, Slot::A)));
        assert_eq!(prompts, [format!("Type {old} to destroy slot a's host: ")]);
        assert!(!run.state.borrow().deployed.contains_key("a"));
        ok(run.step(&["yes"], proxy_update));
        assert_eq!(run.state.borrow().standby, None);
    }

    #[test]
    fn moves_the_key_onto_another_build() {
        let mut run = Run::new();
        run.on_next_build();
        run.armed_and_provisioned();
        let operator = std::fs::read_to_string(
            run.repo
                .path()
                .join(".hashi/guardian/testnet/b/operator.yaml"),
        )
        .unwrap();
        assert!(operator.contains(&format!(
            "    prev_builds:\n      - git_revision: \"{}\"\n",
            world::COMMIT
        )));
        run.set("active-slot", "b");

        // hashi-monitor rejects every record from a build it does not allowlist.
        let serving_pcr0 = "0c".repeat(48);
        run.monitor_config(&[(world::COMMIT, &serving_pcr0)]);
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B))).starts_with(&format!(
                "hashi-monitor does not allowlist {} with PCR0 {};",
                world::NEXT,
                "0d".repeat(48)
            ))
        );
        // Nor from the serving build, whose records it reads through the switchover and re-audits after.
        run.monitor_config(&[(world::NEXT, &"0d".repeat(48))]);
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B))).starts_with(&format!(
                "hashi-monitor does not allowlist {} with PCR0 {};",
                world::COMMIT,
                serving_pcr0
            ))
        );
        // Each entry pairs a revision with its own PCR0.
        run.monitor_config(&[
            (world::COMMIT, &"0d".repeat(48)),
            (world::NEXT, &"0e".repeat(48)),
        ]);
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .contains("does not allowlist")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);

        run.monitor_config(&[
            (world::COMMIT, &serving_pcr0),
            (world::NEXT, &"0d".repeat(48)),
        ]);
        let old = run.instance("a");
        ok(run.step(&["yes", "yes", &old], |ctx| switchover(ctx, Slot::B)));
        let standby = run.instance("b");
        assert_eq!(
            run.state.borrow().hosts[&standby].session.lifecycle,
            "withdraw/ACTIVATED"
        );
        run.set("slot-a-enabled", "false");
        ok(run.step(&[&old], |ctx| teardown(ctx, Slot::A)));
    }

    #[test]
    fn keeps_every_build_of_the_log_on_later_rotations() {
        let mut run = Run::new();
        run.on_next_build();
        run.monitor_config(&[
            (world::COMMIT, &"0c".repeat(48)),
            (world::NEXT, &"0d".repeat(48)),
        ]);
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        let old = run.instance("a");
        ok(run.step(&["yes", "yes", &old], |ctx| switchover(ctx, Slot::B)));
        run.set("slot-a-enabled", "false");
        let notes = run.step(&[&old], |ctx| teardown(ctx, Slot::A));
        ok(notes);
        ok(run.step(&["yes"], proxy_update));

        // Slot b serves the later build, and allowlists slot a's, which wrote the log first.
        run.set("slot-a-enabled", "true");
        run.set("hashi-commit", world::NEXT);
        run.set("eif-pcr0", &"0d".repeat(48));
        // The serving slot's own render would leave it out too, and a session it starts couldn't read the log.
        let refused = error(run.step(&[], |ctx| crate::steps::configs::render(ctx, Some(Slot::B))));
        assert!(
            refused.starts_with(&format!(
                "slot b's configurations leave out {}",
                world::COMMIT
            )),
            "{refused}"
        );
        let refused = error(run.step(&["yes"], |ctx| arm(ctx, Slot::A)));
        assert!(
            refused.starts_with(&format!(
                "slot a's configurations leave out {} (session {} ran it); every guardian of the log must allowlist those builds: add each to prev-builds",
                world::COMMIT,
                "aa".repeat(8)
            )),
            "{refused}"
        );
        assert!(!run.state.borrow().deployed.contains_key("a"));
        run.set(
            "prev-builds",
            &json!([{ "git_revision": world::COMMIT, "pcr0": "0c".repeat(48) }]).to_string(),
        );
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::A)));
        ok(run.step(&["yes"], proxy_update));
        world::provision(&run.state, Slot::A);
        run.render(Slot::A);
        let operator = std::fs::read_to_string(
            run.repo
                .path()
                .join(".hashi/guardian/testnet/a/operator.yaml"),
        )
        .unwrap();
        assert!(operator.contains(&format!(
            "    prev_builds:\n      - git_revision: \"{}\"\n",
            world::COMMIT
        )));
        run.set("active-slot", "a");
        let old = run.instance("b");
        ok(run.step(&["yes", "yes", &old], |ctx| switchover(ctx, Slot::A)));
        let promoted = run.instance("a");
        assert_eq!(
            run.state.borrow().hosts[&promoted].session.lifecycle,
            "withdraw/ACTIVATED"
        );
    }

    #[test]
    fn arms_only_a_standby_that_keeps_the_serving_configuration() {
        let run = Run::new();
        // A standby on another build ran a session before it was abandoned, so it wrote the log too.
        let abandoned = "f1".repeat(8);
        run.state.borrow_mut().init_records.insert(
            abandoned.clone(),
            world::init_record("", &[(world::NEXT.to_owned(), "0d".repeat(48))]),
        );
        let refused = error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        assert!(
            refused.starts_with(&format!(
                "slot b's configurations leave out {} (session {abandoned} ran it);",
                world::NEXT
            )),
            "{refused}"
        );
        let listed = |pcr0: &str| {
            json!([{ "git_revision": world::NEXT, "pcr0": pcr0.repeat(48) }]).to_string()
        };
        run.set("prev-builds", &listed("0e"));
        assert_eq!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))),
            format!(
                "slot b's configurations measure {} as {}, but session {abandoned} ran it as {}",
                world::NEXT,
                "0e".repeat(48),
                "0d".repeat(48)
            )
        );
        run.set("prev-builds", &listed("0d"));
        run.set("refill-rate-sats-per-sec", "1");
        assert_eq!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))),
            "slot b's configurations give refill-rate-sats-per-sec as 1, but the serving guardian's give 11574; a switchover keeps the serving guardian's limiter and deployment block: set it back"
        );
        run.set("refill-rate-sats-per-sec", "11574");
        assert!(!run.state.borrow().deployed.contains_key("b"));
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        // render refuses the same, before any key provisioner downloads what it writes.
        run.set("prev-builds", "[]");
        let refused = error(run.step(&[], |ctx| crate::steps::configs::render(ctx, Some(Slot::B))));
        assert!(
            refused.starts_with("slot b's configurations leave out"),
            "{refused}"
        );
        assert!(
            !run.repo
                .path()
                .join(".hashi/guardian/testnet/b/operator.yaml")
                .exists()
        );
    }

    #[test]
    fn arms_another_build_only_if_it_speaks_and_logs_as_the_serving_one() {
        let run = Run::new();
        run.on_next_build();
        run.state.borrow_mut().format_changes =
            vec!["crates/hashi-types/src/guardian/s3/log_messages/init.rs".to_owned()];
        let refused = error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        assert!(
            refused.starts_with(&format!(
                "{} changes the guardian's protos or log records from slot a's build",
                world::NEXT
            )),
            "{refused}"
        );
        run.state.borrow_mut().format_changes.clear();

        run.state.borrow_mut().configured_tag = "v1".to_owned();
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with("the proxy's image tag v1 names no commit")
        );
        run.state.borrow_mut().configured_tag = format!("{}-dev", world::COMMIT);
        run.set("eif-pcr0-b", "");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "stack org/testnet's eif-pcr0-b is not a PCR0 measurement: unset; measure slot b's build"
            )
        );
        run.set("eif-pcr0-b", &"0d".repeat(48));
        assert!(!run.state.borrow().deployed.contains_key("b"));
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
        // The render step allowlists slot a's build for it, as the serving guardian's.
        ok(run.step(&[], |ctx| crate::steps::configs::render(ctx, Some(Slot::B))));
        let operator = std::fs::read_to_string(
            run.repo
                .path()
                .join(".hashi/guardian/testnet/b/operator.yaml"),
        )
        .unwrap();
        assert!(operator.contains(world::COMMIT), "{operator}");
        // A proxy built since then must decode slot b's guardian too.
        run.state.borrow_mut().format_changes =
            vec!["crates/hashi-types/proto/sui/hashi/v1alpha/guardian_service.proto".to_owned()];
        assert!(
            error(run.step(&["yes"], proxy_update)).starts_with(&format!(
                "{} changes the guardian's protos or log records from the proxy's build",
                world::NEXT
            ))
        );
        run.state.borrow_mut().format_changes.clear();
        assert!(run.state.borrow().deployed.contains_key("b"));
    }

    #[test]
    fn switches_onto_another_build_only_with_the_same_configuration() {
        let run = Run::new();
        run.on_next_build();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        let standby = run.instance("b");
        let session = run.state.borrow().hosts[&standby].session.key[..16].to_owned();
        let edit_record = |change: &dyn Fn(&mut Value)| {
            let mut state = run.state.borrow_mut();
            change(state.init_records.get_mut(&session).unwrap());
        };
        let refused = || {
            assert!(
                error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                    .contains("their limiter or deployment block differ")
            );
            assert_eq!(run.state.borrow().outputs_active, Slot::A);
        };

        edit_record(&|record| {
            record["mode"]["Withdraw"]["limiter_config"]["refill_rate"] = 1.into()
        });
        refused();
        edit_record(&|record| {
            record["mode"]["Withdraw"]["limiter_config"]["refill_rate"] = 11574.into()
        });
        // Every build the serving guardian allowlists wrote the log, so the new one must allowlist it too.
        edit_record(&|record| {
            record["deployment"]["pcr_allowlist"]["prev_builds"] = Value::Array(Vec::new())
        });
        refused();
    }

    #[test]
    fn arms_only_next_to_a_serving_guardian() {
        let run = Run::new();
        assert_eq!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::A))),
            "slot a already runs a guardian, as the active"
        );
        run.set("slot-b-enabled", "false");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with("enable slot b first")
        );
        run.set("slot-b-enabled", "true");
        run.set("eif-features-b", "non-enclave-dev");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .contains("sets eif-features for a slot")
        );
        run.state.borrow_mut().config.remove("eif-features-b");
        let unfetched = "1".repeat(40);
        run.set("hashi-commit-b", &unfetched);
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with(&format!("this checkout does not have {unfetched}"))
        );
        run.set("hashi-commit-b", world::COMMIT);
        run.set("eif-pcr0-b", &"0d".repeat(48));
        assert!(error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).contains("but eif-pcr0 is 0c"));
        run.set("eif-pcr0-b", &"0c".repeat(48));
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
                .starts_with("stack org/testnet has rotation tags")
        );
        run.state.borrow_mut().rotation_tags.clear();
        run.set("active-slot", "b");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with("stack org/testnet configures active-slot b, but slot a is active;")
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
            "arm a standby only next to a serving guardian"
        );
        serving(Some(1253));
        assert_eq!(
            error(run.step(&["no"], |ctx| arm(ctx, Slot::B))),
            "not confirmed; nothing was changed"
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
                "stack org/testnet's plan creates 2 guardian instances, not slot b's one"
            )
        );
        run.state.borrow_mut().other_creates.clear();
        assert!(!run.state.borrow().deployed.contains_key("b"));

        // The standby the outputs then name must be the instance arming created.
        run.state.borrow_mut().standby_output = Some("i-0elsewhere".to_owned());
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "stack org/testnet's standby i-0elsewhere is not the instance arming slot b created"
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
        // A one-slot stack names no other build to check.
        let single = Run::new();
        for key in ["hashi-commit-b", "eif-pcr0-b", "slot-b-enabled"] {
            single.state.borrow_mut().config.remove(key);
        }
        assert!(ok(single.step(&[], proxy_update)).is_empty());

        let run = Run::new();
        let prompts = ok(run.step(&[], proxy_update));
        assert!(prompts.is_empty(), "nothing to change, so nothing asked");
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));

        run.state.borrow_mut().running_tag = "v0".to_owned();
        assert!(error(run.step(&["yes"], proxy_update)).starts_with("the proxy runs repo:v0, but"));
        run.state.borrow_mut().running_tag = "v1".to_owned();

        run.state.borrow_mut().service_counts = (1, 0, 2);
        assert!(
            error(run.step(&["yes"], proxy_update))
                .starts_with("the proxy service runs 0 of 1 tasks in 2 deployments;")
        );
        run.state.borrow_mut().service_counts = (1, 1, 1);

        // ECS can roll a deployment back once Pulumi has recorded it.
        run.state.borrow_mut().rolls_back = true;
        assert!(error(run.step(&["yes"], proxy_update)).contains("its deployment rolled back;"));
        run.state.borrow_mut().rolls_back = false;
        // The plan would start from the state ECS rolled back from.
        assert!(
            error(run.step(&["yes"], proxy_update))
                .contains("a deployment rolled back, or the service changed outside Pulumi;")
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
                .starts_with("slot b's plan changed while this step waited for you;")
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
                .starts_with("the proxy's service or plan changed while this step waited for you;")
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
                    "slot b's guardian, configuration or plan changed while this step waited for you;"
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
                .starts_with("the guardian the relay serves is in a key provisioner round")
        );
        run.lifecycle("b", "withdraw/PROVISIONER_INITIALIZED");
        assert!(
            run.step_asking(&RoundStarts(&run), proxy_update)
                .unwrap_err()
                .to_string()
                .starts_with("the guardian the relay serves is in a key provisioner round")
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
                .starts_with("could not read the guardian the proxy's relay serves")
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
    fn rechecks_each_phase_after_its_question() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        // A yaml edit while the flip's question waits.
        let drift = |run: &Run| {
            run.state.borrow_mut().extra_change =
                Some(("update".to_owned(), format!("{}b", world::URN_PREFIX)));
        };
        let flip = Meanwhile {
            run: &run,
            change: drift,
            answer: "yes".to_owned(),
        };
        assert!(
            run.step_asking(&flip, |ctx| switchover(ctx, Slot::B))
                .unwrap_err()
                .to_string()
                .starts_with("slot b's plan changed while this step waited for you;")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);
        run.state.borrow_mut().extra_change = None;

        // Proxy deploys that land while the questions wait: the flip still applies, but the proxy update refuses.
        let deploy = |run: &Run| {
            let mut state = run.state.borrow_mut();
            state.revision += 1;
            state.running_tag = "v2".to_owned();
            state.configured_tag = "v2".to_owned();
        };
        let update = Meanwhile {
            run: &run,
            change: deploy,
            answer: "yes".to_owned(),
        };
        let old = run.instance("a");
        assert_eq!(
            run.step_asking(&update, |ctx| switchover(ctx, Slot::B))
                .unwrap_err()
                .to_string(),
            "the proxy's service or plan changed while this step waited for you; the proxy was not updated: run this step again"
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::B);
        assert!(run.state.borrow().hosts[&old].running);

        // An apply of the enclave stack that starts while the stop's question waits.
        assert_eq!(
            error(run.step(&["yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            STOP_DECLINED.declined
        );
        let applies = |run: &Run| {
            run.state.borrow_mut().workflow_runs = vec![(
                "org/infra".to_owned(),
                "in_progress".to_owned(),
                ".github/workflows/guardian-enclave.yaml".to_owned(),
            )];
        };
        let stop = Meanwhile {
            run: &run,
            change: applies,
            answer: old.clone(),
        };
        assert!(
            run.step_asking(&stop, |ctx| switchover(ctx, Slot::B))
                .unwrap_err()
                .to_string()
                .contains("has a run in_progress")
        );
        assert!(run.state.borrow().hosts[&old].running);
    }

    #[test]
    fn switches_over_only_once_ready() {
        let run = Run::new();
        run.armed_and_provisioned();
        assert_eq!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B))),
            "set active-slot to b in stack org/testnet's Pulumi.<stack>.yaml first, and commit it"
        );
        run.set("active-slot", "b");
        run.state.borrow_mut().epoch_age = (10 * 60, 24 * 3600 + 10 * 60);
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .ends_with("30 minutes after the epoch turns")
        );
        run.state.borrow_mut().epoch_age = (3 * 3600, 27 * 3600);
        let standby = run.instance("b");
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .session
            .config_hash = Some("d0".repeat(32));
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .contains("their limiter or deployment block differ")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);
    }

    #[test]
    fn resumes_after_each_phase() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        let old = run.instance("a");
        // Declining the proxy update leaves the stack flipped and the old guardian running.
        assert_eq!(
            error(run.step(&["yes", "no"], |ctx| switchover(ctx, Slot::B))),
            FLIPPED.declined
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::B);
        assert!(run.state.borrow().hosts[&old].running);
        // Declining the stop leaves the proxy on slot b and the old guardian running.
        assert_eq!(
            error(run.step(&["yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            STOP_DECLINED.declined
        );
        assert!(run.state.borrow().hosts[&old].running);
        // A withdrawal signed right after activation fails activate's own post-check, which this survives.
        run.state.borrow_mut().activate_false_failure = true;
        let prompts = ok(run.step(&[&old], |ctx| switchover(ctx, Slot::B)));
        assert_eq!(
            prompts,
            [format!("Type {old} to stop slot a's guardian for good: ")]
        );
        let standby = run.instance("b");
        assert_eq!(
            run.state.borrow().hosts[&standby].session.lifecycle,
            "withdraw/ACTIVATED"
        );
    }

    #[test]
    fn activates_only_once_the_old_enclave_is_gone() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        run.state.borrow_mut().terminate_fails = true;
        let old = run.instance("a");
        assert!(
            error(run.step(&["yes", "yes", &old], |ctx| switchover(ctx, Slot::B)))
                .starts_with("stopping slot a's guardian did not finish")
        );
        // The unit reads stopped now, but activation would wait on the enclave it left running.
        assert!(
            error(run.step(&[], |ctx| switchover(ctx, Slot::B))).contains("still runs an enclave")
        );
        let standby = run.instance("b");
        assert_eq!(
            run.state.borrow().hosts[&standby].session.lifecycle,
            "withdraw/PROVISIONER_INITIALIZED"
        );
        run.state.borrow_mut().hosts.get_mut(&old).unwrap().enclave = false;
        ok(run.step(&[], |ctx| switchover(ctx, Slot::B)));
        assert_eq!(
            run.state.borrow().hosts[&standby].session.lifecycle,
            "withdraw/ACTIVATED"
        );
    }

    #[test]
    fn rechecks_everything_before_the_stop_on_a_rerun() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("slot-a-enabled", "false");
        run.set("active-slot", "b");
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .starts_with("keep slot-a-enabled \"true\"")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);
        run.set("slot-a-enabled", "true");

        let old = run.instance("a");
        assert_eq!(
            error(run.step(&["yes", "yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            STOP_DECLINED.declined
        );
        let operator = run
            .repo
            .path()
            .join(".hashi/guardian/testnet/b/operator.yaml");
        let rendered = std::fs::read(&operator).unwrap();
        std::fs::write(&operator, "changed").unwrap();
        assert!(
            error(run.step(&[&old], |ctx| switchover(ctx, Slot::B))).starts_with("out of date")
        );
        std::fs::write(&operator, rendered).unwrap();

        // A relay that falls back to the new guardian cannot vouch for the old one.
        let standby = run.state.borrow_mut().standby.take();
        assert!(
            error(run.step(&[&old], |ctx| switchover(ctx, Slot::B)))
                .starts_with("could not confirm through the relay")
        );
        run.state.borrow_mut().standby = standby;

        // Too close to the epoch's turn for activation to beat it, so the old guardian must keep serving.
        run.state.borrow_mut().epoch_age = (23 * 3600 + 45 * 60, 47 * 3600 + 45 * 60);
        let refusal = error(run.step(&[&old], |ctx| switchover(ctx, Slot::B)));
        assert!(
            refusal.starts_with("Sui epoch 1253 ends in about 1") && refusal.contains("roll back"),
            "{refusal}"
        );
        assert!(run.state.borrow().hosts[&old].running);
        run.state.borrow_mut().epoch_age = (23 * 3600 + 30 * 60, 47 * 3600 + 30 * 60);
        ok(run.step(&[&old], |ctx| switchover(ctx, Slot::B)));
        assert!(!run.state.borrow().hosts[&old].running);
    }

    #[test]
    fn switches_over_only_to_what_the_files_render() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        // Activation reads the rendered files, and a guardian initialized with other settings refuses them.
        run.set("refill-rate-sats-per-sec", "999");
        run.render(Slot::B);
        let refusal = error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)));
        assert!(
            refusal.contains("but its guardian was initialized with limiter"),
            "{refusal}"
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);
    }

    /// An operator who types the old instance once slot b's guardian has restarted into a new session.
    struct StandbyRestarts<'a>(&'a Run);

    impl crate::ask::Ask for StandbyRestarts<'_> {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, _prompt: &str) -> std::io::Result<Option<String>> {
            let standby = self.0.instance("b");
            self.0
                .state
                .borrow_mut()
                .hosts
                .get_mut(&standby)
                .unwrap()
                .session
                .key = "dd".repeat(32);
            Ok(Some(self.0.instance("a")))
        }
    }

    #[test]
    fn stops_the_old_guardian_only_for_the_session_it_checked() {
        let run = Run::new();
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        assert_eq!(
            error(run.step(&["yes", "yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            STOP_DECLINED.declined
        );
        let refusal = run
            .step_asking(&StandbyRestarts(&run), |ctx| switchover(ctx, Slot::B))
            .unwrap_err()
            .to_string();
        assert!(
            refusal.ends_with("nothing was stopped: run this step again"),
            "{refusal}"
        );
        assert!(run.state.borrow().hosts[&run.instance("a")].running);
    }

    #[test]
    fn reads_a_record_as_a_guardian_writes_it() {
        // The shape of testnet's records, with made-up values.
        let record = json!({
            "schema_version": 1,
            "object_key": "init/abababababababab/02-oi-guardian-info.json",
            "session_id": "abababababababab",
            "timestamp_ms": 1791481146340u64,
            "message": { "Init": { "OIGuardianInfo": {
                "deployment": {
                    "bucket_info": { "name": "guardian-bucket", "region": "us-west-2" },
                    "retention_environment": "testnet",
                    "bitcoin_network": "signet",
                    "pcr_allowlist": {
                        "current_build": { "git_revision": world::NEXT, "pcr0": "0d".repeat(48) },
                        "prev_builds": [{ "git_revision": world::COMMIT, "pcr0": "0c".repeat(48) }],
                    },
                },
                "encryption_pubkey": [1, 2, 3],
                "mode": { "Withdraw": {
                    "secret_sharing_instance": { "threshold": 2 },
                    "config_hash": "95".repeat(32),
                    "limiter_config": { "refill_rate": 11574, "max_bucket_capacity": 1000000000 },
                    "hashi_object_id": "0x2",
                    "mpc_master_g": [4, 5, 6],
                    "genesis_state_hash": [7, 8, 9],
                } },
            } } },
            "signature": "c2lnbmF0dXJl",
        })
        .to_string();
        let exec = crate::exec::fake::Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["aws", "s3api", "list-object-versions", ..] => Some((true, "1\t0\n".to_owned())),
                [
                    "aws",
                    "s3",
                    "cp",
                    ..,
                    "s3://guardian-bucket/init/abababababababab/02-oi-guardian-info.json",
                    "-",
                ] => Some((true, record.clone())),
                _ => None,
            }
        });
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let bucket = Bucket {
            name: "guardian-bucket".to_owned(),
            region: "us-west-2".to_owned(),
        };
        let init = OperatorInit::read(&ctx, &bucket, &"ab".repeat(32)).unwrap();
        assert_eq!(init.config_hash, "95".repeat(32));
        assert_eq!(init.limiter["max_bucket_capacity"], 1000000000);
        assert_eq!(
            init.prev_builds().unwrap(),
            [Build {
                commit: world::COMMIT.to_owned(),
                pcr0: "0c".repeat(48),
            }]
        );
    }

    #[test]
    fn reads_only_a_record_with_one_version() {
        let exec = crate::exec::fake::Fake::new(|words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["aws", "s3api", "list-object-versions", ..] => Some((true, "2\t0\n".to_owned())),
                _ => None,
            }
        });
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let bucket = Bucket {
            name: "guardian-bucket".to_owned(),
            region: "us-west-2".to_owned(),
        };
        let error = OperatorInit::read(&ctx, &bucket, &"aa".repeat(32))
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.starts_with("s3://guardian-bucket/init/aaaaaaaaaaaaaaaa/02-oi-guardian-info.json has versions or delete markers"),
            "{error}"
        );
        assert!(!exec.ran(&["aws", "s3", "cp"]));
    }

    #[test]
    fn tears_down_only_a_stopped_standby() {
        let run = Run::new();
        run.armed_and_provisioned();
        assert_eq!(
            error(run.step(&["x"], |ctx| teardown(ctx, Slot::A))),
            "slot a runs the active guardian; only a standby can be torn down"
        );
        assert!(
            error(run.step(&["x"], |ctx| teardown(ctx, Slot::B)))
                .starts_with("disable slot b first")
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
            "tear nothing down until a guardian serves"
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
            "org/infra's .github/workflows/guardian-proxy.yaml has a run waiting, and it applies the guardian stacks too; wait for it to finish"
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
            "testnet.env does not set GUARDIAN_WORKFLOWS"
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
                .starts_with("arming slot b must create its instance and change nothing else")
        );
        assert!(!run.state.borrow().deployed.contains_key("b"));

        run.state.borrow_mut().extra_change = None;
        run.armed_and_provisioned();
        run.set("active-slot", "b");
        run.state.borrow_mut().extra_change = drift("update");
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .starts_with("flipping the active slot must change no resource")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);

        run.set("active-slot", "a");
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        assert!(
            error(run.step(&[&standby], |ctx| teardown(ctx, Slot::B))).starts_with(
                "tearing down slot b must delete its instance and change nothing else"
            )
        );
        assert!(run.state.borrow().deployed.contains_key("b"));
    }
}
