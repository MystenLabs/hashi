// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Moving the guardian's key to a fresh host in the stack's other slot: `arm` a standby, `proxy-update`,
//! `switchover` and `teardown`. Every step re-reads the stack, the hosts and the proxy, applies only a targeted plan of
//! exactly the expected shape, and can run again to resume.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde_json::Value;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::commit::Tree;
use crate::commit::require_same_formats;
use crate::exec::Cmd;
use crate::exec::read;
use crate::github::require_no_guardian_runs;
use crate::guardian::ProxyInfo;
use crate::guardian::proxy_info;
use crate::guardian::relay_info;
use crate::guardian::require_reached;
use crate::guardian::slot_info;
use crate::host;
use crate::next;
use crate::plan::Change;
use crate::plan::preview_slot;
use crate::plan::require_pulumi_version;
use crate::plan::up_slot;
use crate::proxy::image_commit;
use crate::proxy::update_proxy;
use crate::render::prev_builds;
use crate::render::require_fresh;
use crate::say;
use crate::stack::Bucket;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::stack::Stack;
use crate::stack::is_hex;
use crate::steps::slot;
use crate::sui::require_epoch_window;
use crate::sui::require_time_window;
use crate::warn;

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
pub fn arm(ctx: &Ctx, slot_arg: Slot) -> Result<()> {
    let stack = Stack::load(ctx)?;
    let view = stack.slot(ctx, slot_arg)?;
    stack.bucket()?;
    let slot = view.slot;
    let active = stack.active()?;
    let serving = stack.output("enclave_instance_id");
    say(&format!("Arm slot {slot} next to slot {active}'s guardian"));
    if view.role != Role::Absent {
        bail!("Slot {slot} already runs a guardian, as the {}.", view.role);
    }
    require_pulumi_version(ctx, &stack.dir, &stack)?;
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
    let pcr0 = stack.config(&view.pcr0_key).unwrap_or("");
    if !is_hex(pcr0, 96) {
        bail!(
            "Stack {}'s {} is not a PCR0 measurement: {}. Measure slot {slot}'s build with measure {slot}, and set it to the PCR0 that prints.",
            stack.name,
            view.pcr0_key,
            if pcr0.is_empty() { "unset" } else { pcr0 }
        );
    }
    // A standby on another build must also speak as the proxy's build does, which decodes it.
    if !prev_builds(ctx, &stack, &view, pcr0)?.is_empty() {
        require_same_formats(
            ctx,
            &view.commit,
            &image_commit(ctx, &stack)?,
            "the proxy's build",
        )?;
    }
    let (suffix, active_suffix) = (slot.suffix(), active.suffix());
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
            "Stack {} has rotation tags from sui-operations' rotation scripts: {}. This flow keeps rotation state in Pulumi.<stack>.yaml, so clear them once you know the yaml says the same.",
            stack.name,
            tags.join(", ")
        );
    }
    let url = ctx.env.proxy_url()?.url;
    if !proxy_info(ctx).is_ok_and(|info| info.committee_epoch.is_some()) {
        bail!("The proxy at {url} serves no activated guardian. Arm a standby only next to one.");
    }
    let Some(serving_urn) = stack.instance_urn(ctx, serving)? else {
        bail!(
            "Could not find slot {active}'s instance {serving} in stack {}'s state.",
            stack.name
        );
    };
    let urn = format!(
        "{}::hashi-guardian-enclave-{slot}",
        serving_urn
            .rsplit_once("::")
            .map_or("", |(prefix, _)| prefix)
    );
    let changes = preview_slot(ctx, &stack, &urn)?;
    if changes != [Change::new("create", &urn)] {
        bail!(
            "Arming slot {slot} must create its instance and change nothing else, but this plan does not. Nothing was changed."
        );
    }
    confirm(
        ctx.ask,
        &format!("Create slot {slot}'s guardian host?"),
        &NOTHING_CHANGED,
    )?;
    up_slot(ctx, &stack, &urn)?;
    let after = Stack::load(ctx)?;
    if after.output("enclave_instance_id") != Some(serving) || after.active()? != active {
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
    println!(
        "\nArmed slot {slot} on {standby}. The host builds the enclave image at boot; follow it with: host {slot}. Then run proxy-update, so the relay reaches it."
    );
    next(&format!(
        "host {slot}, until its boot completes; then proxy-update"
    ));
    Ok(())
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
            "Keep slot-{other}-enabled \"true\" in stack {}'s Pulumi.<stack>.yaml until slot {other}'s teardown: switchover finds the guardian it stops through it.",
            stack.name
        );
    }

    if stack.active()? != slot {
        say(&format!("Check slot {slot}'s guardian is ready to serve"));
        if view.role != Role::Standby {
            bail!("Slot {slot} runs no standby guardian to switch over to.");
        }
        require_fresh(ctx, &stack, &view)?;
        let reached = require_reached(ctx, &stack, &view, &tree)?;
        let lifecycle = &reached.info.lifecycle;
        if !lifecycle.is("withdraw/PROVISIONER_INITIALIZED") {
            bail!(
                "Slot {slot}'s guardian is {lifecycle}, not provisioned and waiting for activation."
            );
        }
        let serving = proxy_info(ctx)?;
        let standby_btc = reached.info.btc_key.as_deref();
        if standby_btc.is_none() || standby_btc != serving.btc_pubkey.as_deref() {
            bail!(
                "Slot {slot}'s guardian holds BTC key {}, but the serving guardian holds {}.",
                standby_btc.unwrap_or("none"),
                serving.btc_pubkey.as_deref().unwrap_or("none")
            );
        }
        let serving_key = serving
            .signing_pub_key
            .as_deref()
            .filter(|key| crate::stack::is_hex(key, 64))
            .ok_or_else(|| anyhow!("The proxy's /info names no serving guardian's signing key."))?;
        let serving_init = OperatorInit::read(ctx, &bucket, serving_key)?;
        let standby_config = reached.info.config_hash.as_deref();
        if standby_config != Some(serving_init.config_hash.as_str()) {
            // The hash covers the PCR allowlist too, which a rotation onto another build extends.
            let standby_init = OperatorInit::read(ctx, &bucket, &reached.signing_key)?;
            if standby_config != Some(standby_init.config_hash.as_str())
                || !standby_init.keeps(&serving_init)
            {
                bail!(
                    "Slot {slot}'s guardian has config hash {}, but the serving guardian has {}. Their limiter or deployment block differ, and switching over would change them.",
                    standby_config.unwrap_or("none"),
                    serving_init.config_hash
                );
            }
        }
        require_monitor_allows(&stack, &view)?;
        require_pulumi_version(ctx, &stack.dir, &stack)?;
        require_no_guardian_runs(ctx)?;
        require_epoch_window(ctx, serving.committee_epoch.as_deref())?;
        if stack.config("active-slot") != Some(&slot.to_string()) {
            bail!(
                "Set active-slot to {slot} in stack {}'s Pulumi.<stack>.yaml first, and commit it.",
                stack.name
            );
        }

        say(&format!("Make slot {slot} the stack's active slot"));
        let old_instance = stack.output("enclave_instance_id").map(str::to_owned);
        let instance = view.require_instance(&stack)?.to_owned();
        let Some(urn) = stack.instance_urn(ctx, &instance)? else {
            bail!(
                "Could not find slot {slot}'s instance {instance} in stack {}'s state.",
                stack.name
            );
        };
        if !preview_slot(ctx, &stack, &urn)?.is_empty() {
            bail!(
                "Flipping the active slot must change no resource, but this plan does. Nothing was changed."
            );
        }
        warn(
            "From here until activation, nodes' new withdrawals fail and are retried. Until the old guardian stops, setting active-slot back undoes this.",
        );
        confirm(
            ctx.ask,
            &format!("Make slot {slot} the active slot?"),
            &NOTHING_CHANGED,
        )?;
        up_slot(ctx, &stack, &urn)?;
        stack = Stack::load(ctx)?;
        // A target that names nothing applies cleanly too, so check the flip happened before relying on it.
        if stack.active()? != slot
            || stack.output("enclave_instance_id") != Some(instance.as_str())
            || stack.output("standby_instance_id").map(str::to_owned) != old_instance
        {
            bail!(
                "Stack {}'s outputs did not flip to slot {slot}. Nothing else was changed: check its outputs.",
                stack.name
            );
        }
        view = stack.slot(ctx, slot)?;
    }

    let info = slot_info(ctx, &tree, &view)?;
    let (Some(signing_key), Some(slot_btc)) = (info.signing_key.clone(), info.btc_key.clone())
    else {
        bail!(
            "Slot {slot}'s guardian did not report its signing and BTC keys at {}.",
            view.endpoint
        );
    };
    let activated = info.lifecycle.is("withdraw/ACTIVATED");
    if !activated {
        // A rerun can come long after the checks before the flip.
        require_time_window(ctx)?;
        require_no_guardian_runs(ctx)?;
    }
    let fronts = |info: &ProxyInfo| info.signing_pub_key.as_deref() == Some(signing_key.as_str());
    if !proxy_info(ctx).is_ok_and(|info| fronts(&info)) {
        say(&format!("Point the proxy at slot {slot}'s guardian"));
        update_proxy(ctx, &stack, &tree)?;
        if poll(|| proxy_info(ctx).ok().filter(fronts)).is_none() {
            bail!(
                "The proxy does not front slot {slot}'s guardian two minutes after its update. The old guardian still runs: check the proxy before going on."
            );
        }
    }

    if let Some(old_instance) = stack.output("standby_instance_id") {
        let state = guardian_unit_state(ctx, &bucket.region, old_instance)
            .with_context(|| format!("Could not read slot {other}'s host {old_instance}."))?;
        if state.contains("GUARDIAN_RUNNING") {
            say(&format!("Stop slot {other}'s guardian"));
            // Nothing activation needs may be found wrong only after the stop.
            require_fresh(ctx, &stack, &view)?;
            require_monitor_allows(&stack, &view)?;
            // The relay still reaches the old guardian: the last check that it is the one that served, with one key.
            let old = relay_info(ctx, &tree).ok();
            if !old.as_ref().is_some_and(|old| {
                old.btc_key.as_deref() == Some(slot_btc.as_str())
                    && old.signing_key.as_deref() != Some(signing_key.as_str())
                    && old.lifecycle.is("withdraw/ACTIVATED")
            }) {
                bail!(
                    "Could not confirm through the relay that slot {other}'s guardian is the activated one, holding slot {slot}'s BTC key {slot_btc}. Nothing was stopped."
                );
            }
            require_time_window(ctx)?;
            warn(&format!(
                "Stopping slot {other}'s guardian on {old_instance} cannot be undone: its copy of the key is gone, and only slot {slot}'s guardian holds it in memory after this."
            ));
            confirm_typed(
                ctx.ask,
                old_instance,
                &format!("to stop slot {other}'s guardian for good"),
                &NOTHING_CHANGED,
            )?;
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
                    "The stop of slot {other}'s guardian on {old_instance} may have run. Run this step again: it checks the host first."
                )
            })?;
            if !stopped.success {
                println!("{}", stopped.text);
                bail!(
                    "Stopping slot {other}'s guardian did not finish. Run this step again: it checks the host first."
                );
            }
            println!("Stopped slot {other} guardian on {old_instance}.");
        } else if !activated {
            // Activation waits for the old guardian to fall quiet, which an enclave left running never does.
            let stopped = host::run(ctx, &bucket.region, old_instance, &STOPPED_CHECKS)?;
            if !stopped.success {
                println!("{}", stopped.text);
                bail!(
                    "Slot {other}'s guardian unit on {old_instance} is stopped, but the host still runs an enclave or could not say. Terminate it there with nitro-cli terminate-enclave --all, then run this step again."
                );
            }
        }
    }

    if !activated {
        say(&format!("Activate slot {slot}'s guardian"));
        println!(
            "It waits until every other guardian session has been quiet for ten minutes, and prints little until then."
        );
        require_fresh(ctx, &stack, &view)?;
        // The activation waits on S3 for up to 15 minutes and then calls the guardian, so the tunnel's 20 idle
        // minutes must start now.
        slot_info(ctx, &tree, &view)?;
        std::io::stdout().flush()?;
        let activated = ctx.exec.run(
            &guardian_init
                .cmd()
                .args(["operator", "activate", "--config", "operator.yaml"])
                .cwd(&view.dir),
        )?;
        if !slot_info(ctx, &tree, &view)?
            .lifecycle
            .is("withdraw/ACTIVATED")
        {
            bail!(
                "Slot {slot}'s guardian is not activated. Run this step again: it resumes with activation."
            );
        }
        // Its post-check compares limiter state, which a withdrawal signed right after activation changes.
        if !activated {
            warn(&format!(
                "operator activate failed, but slot {slot}'s guardian reports itself activated."
            ));
        }
    }

    say(&format!("Check the proxy serves slot {slot}'s guardian"));
    let serves = |info: &ProxyInfo| {
        fronts(info)
            && info.btc_pubkey.as_deref() == Some(slot_btc.as_str())
            && info.git_revision.as_deref() == Some(view.commit.as_str())
            && info.committee_epoch.is_some()
    };
    let Some(serving) = poll(|| proxy_info(ctx).ok().filter(serves)) else {
        bail!(
            "The proxy's /info does not show slot {slot}'s activated guardian: {}",
            proxy_info(ctx).map_or("no answer".to_owned(), |info| format!("{info:?}"))
        );
    };
    println!(
        "Serving:     slot {slot}, committee epoch {}, BTC key {slot_btc}",
        serving.committee_epoch.as_deref().unwrap_or("")
    );
    println!("Once it has served for a while, tear down slot {other}: teardown {other}.");
    next(&format!(
        "after a soak, set slot-{other}-enabled to \"false\" and run teardown {other}"
    ));
    Ok(())
}

/// A withdraw session's configuration, from its operator-init record. Activation drops the configuration hash from a
/// guardian's own report, so a serving session's is read here.
struct OperatorInit {
    config_hash: String,
    limiter: Value,
    deployment: Value,
}

impl OperatorInit {
    /// The record of the session named by the start of its signing key.
    fn read(ctx: &Ctx, bucket: &Bucket, signing_key: &str) -> Result<Self> {
        let session = &signing_key[..16];
        let record = read(
            ctx.exec,
            &Cmd::new("aws")
                .args(["s3", "cp", "--only-show-errors", "--region", &bucket.region])
                .arg(format!(
                    "s3://{}/init/{session}/02-oi-guardian-info.json",
                    bucket.name
                ))
                .arg("-"),
        )
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|record| {
            let info = record.pointer("/message/Init/OIGuardianInfo")?;
            let withdraw = info.pointer("/mode/Withdraw")?;
            Some(Self {
                config_hash: withdraw.get("config_hash")?.as_str()?.to_owned(),
                limiter: withdraw.get("limiter_config")?.clone(),
                deployment: info.get("deployment")?.clone(),
            })
        });
        record.ok_or_else(|| {
            anyhow!(
                "Could not read the configuration of guardian session {session} from s3://{}/init/{session}/.",
                bucket.name
            )
        })
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
}

/// Stops unless hashi-monitor, where it runs beside the guardian, allowlists the slot's build: it rejects every record
/// from a build it doesn't, and reads the latest ceremony record when it starts, which a re-deal writes. Its stack
/// configuration is checked as sui-operations' guardian-rotate.sh does.
pub(crate) fn require_monitor_allows(stack: &Stack, view: &SlotView) -> Result<()> {
    let config = Path::new(&stack.dir)
        .parent()
        .unwrap_or(Path::new("."))
        .join("hashi-monitor")
        .join(format!("Pulumi.{}.yaml", stack.short_name()));
    if !config.exists() {
        return Ok(());
    }
    let text = std::fs::read_to_string(&config)
        .with_context(|| format!("Could not read {}.", config.display()))?;
    let pcr0 = stack.config(&view.pcr0_key).unwrap_or("");
    let missing = if !text.contains(view.commit.as_str()) {
        ""
    } else if pcr0.is_empty() || !text.contains(pcr0) {
        " with its PCR0"
    } else {
        return Ok(());
    };
    bail!(
        "hashi-monitor does not allowlist {}{missing}. Add it to the audit builds in {}, deploy that stack, then run this step again.",
        view.commit,
        config.display()
    )
}

/// Destroys a standby slot's host: the retired guardian after a switchover, or a standby that never served.
pub fn teardown(ctx: &Ctx, slot_arg: Slot) -> Result<()> {
    let (stack, view) = slot(ctx, Some(slot_arg), "teardown")?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    let slot = view.slot;
    say(&format!("Tear down slot {slot}'s guardian host {instance}"));
    if view.role != Role::Standby {
        bail!("Slot {slot} runs the active guardian. Only a standby can be torn down.");
    }
    require_pulumi_version(ctx, &stack.dir, &stack)?;
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
    let url = ctx.env.proxy_url()?.url;
    if !proxy_info(ctx).is_ok_and(|info| info.committee_epoch.is_some()) {
        bail!(
            "The proxy at {url} serves no activated guardian. Tear nothing down until one serves."
        );
    }
    let state = guardian_unit_state(ctx, &bucket.region, instance)
        .with_context(|| format!("Could not read slot {slot}'s host."))?;
    if !state.contains("GUARDIAN_STOPPED") {
        // A retiring guardian still signs until the switchover step stops it; a standby never has.
        let lifecycle = slot_info(ctx, &tree(ctx, &view)?, &view)?.lifecycle;
        if lifecycle.is("withdraw/ACTIVATED") {
            bail!(
                "Slot {slot}'s guardian on {instance} is activated and still runs. Stop it with the switchover step first."
            );
        }
        warn(&format!(
            "Slot {slot}'s guardian still runs ({lifecycle}). Tearing it down abandons it: what was provisioned or dealt to it is lost."
        ));
    }
    let Some(urn) = stack.instance_urn(ctx, instance)? else {
        bail!(
            "Could not find slot {slot}'s instance {instance} in stack {}'s state.",
            stack.name
        );
    };
    if preview_slot(ctx, &stack, &urn)? != [Change::new("delete", &urn)] {
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
    up_slot(ctx, &stack, &urn)?;
    let after = Stack::load(ctx)?;
    if after.output("standby_instance_id").is_some() || after.active()? != active {
        bail!(
            "Stack {}'s outputs do not show slot {active} alone. Check them before going on.",
            stack.name
        );
    }
    println!("\nTore down slot {slot}. Run proxy-update, so the relay stops pointing at it.");
    if stack.config(&format!("hashi-commit{}", active.suffix())) != Some(view.commit.as_str()) {
        println!(
            "Keep slot {slot}'s hashi-commit{0} and eif-pcr0{0} in stack {1}'s Pulumi.<stack>.yaml: slot {active}'s configurations list its build, which wrote the log.",
            slot.suffix(),
            stack.name
        );
    }
    next("proxy-update");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    use super::*;
    use crate::ask::scripted::Scripted;
    use crate::exec::fake::Fake;
    use crate::render::SlotRender;
    use crate::world;
    use crate::world::State;

    struct Run {
        repo: tempfile::TempDir,
        state: Rc<RefCell<State>>,
        exec: Fake,
        env: Vec<(String, String)>,
    }

    impl Run {
        fn new() -> Self {
            let repo = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(world::COMMIT))
                .unwrap();
            let state = world::serving_world();
            let exec = world::exec(&state);
            let env = world::env(repo.path());
            Self {
                repo,
                state,
                exec,
                env,
            }
        }

        /// Runs `step` with the operator answering `answers`, and returns its result and the prompts it showed.
        fn step(
            &self,
            answers: &[&str],
            step: impl FnOnce(&Ctx) -> Result<()>,
        ) -> (Result<()>, Vec<String>) {
            let pairs: Vec<(&str, &str)> = self
                .env
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let ask = Scripted::new(answers);
            let ctx = Ctx::for_test(self.repo.path(), &self.exec, &pairs).with_ask(&ask);
            let result = step(&ctx);
            let prompts = ask.prompts.borrow().clone();
            (result, prompts)
        }

        fn render(&self, slot: Slot) {
            let pairs: Vec<(&str, &str)> = self
                .env
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let ctx = Ctx::for_test(self.repo.path(), &self.exec, &pairs);
            let stack = Stack::load(&ctx).unwrap();
            let view = stack.slot(&ctx, slot).unwrap();
            SlotRender::new(&ctx, &stack, &view)
                .unwrap()
                .rendered
                .write(&view.dir)
                .unwrap();
        }

        fn set(&self, key: &str, value: &str) {
            self.state
                .borrow_mut()
                .config
                .insert(key.to_owned(), value.to_owned());
        }

        fn instance(&self, slot: &str) -> String {
            self.state.borrow().deployed[slot].clone()
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

        /// hashi-monitor's stack configuration beside the enclave stack.
        fn monitor_config(&self, text: &str) {
            let dir = self.repo.path().join("pulumi/services/hashi-monitor");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Pulumi.testnet.yaml"), text).unwrap();
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
        assert_eq!(
            prompts,
            ["Create slot b's guardian host? Type y/yes to continue: "]
        );
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
                "Make slot b the active slot? Type y/yes to continue: ".to_owned(),
                "Update the proxy of stack mysten/testnet? Type y/yes to continue: ".to_owned(),
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
        let run = Run::new();
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
        let audited = |builds: &[(&str, &str)]| {
            builds
                .iter()
                .map(|(commit, pcr0)| {
                    format!("  - git_revision: \"{commit}\"\n    pcr0: \"{pcr0}\"\n")
                })
                .collect::<String>()
        };
        let serving_pcr0 = "0c".repeat(48);
        run.monitor_config(&audited(&[(world::COMMIT, &serving_pcr0)]));
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B))).starts_with(&format!(
                "hashi-monitor does not allowlist {}. Add it",
                world::NEXT
            ))
        );
        run.monitor_config(&audited(&[
            (world::COMMIT, &serving_pcr0),
            (world::NEXT, &"0e".repeat(48)),
        ]));
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .contains("does not allowlist")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);

        run.monitor_config(&audited(&[
            (world::COMMIT, &serving_pcr0),
            (world::NEXT, &"0d".repeat(48)),
        ]));
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
                .starts_with("The proxy's image tag v1 names no commit")
        );
        run.state.borrow_mut().configured_tag = format!("{}-dev", world::COMMIT);
        run.set("eif-pcr0-b", "");
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).starts_with(
                "Stack mysten/testnet's eif-pcr0-b is not a PCR0 measurement: unset. Measure slot b's build"
            )
        );
        run.set("eif-pcr0-b", &"0d".repeat(48));
        assert!(!run.state.borrow().deployed.contains_key("b"));
        ok(run.step(&["yes"], |ctx| arm(ctx, Slot::B)));
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
                    .contains("Their limiter or deployment block differ")
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
        let unfetched = "1".repeat(40);
        run.set("hashi-commit-b", &unfetched);
        assert!(
            error(run.step(&["yes"], |ctx| arm(ctx, Slot::B)))
                .starts_with(&format!("This checkout does not have {unfetched}"))
        );
        run.set("hashi-commit-b", world::COMMIT);
        run.set("eif-pcr0-b", &"0d".repeat(48));
        assert!(error(run.step(&["yes"], |ctx| arm(ctx, Slot::B))).contains("but eif-pcr0 is 0c"));
        run.set("eif-pcr0-b", &"0c".repeat(48));
        assert_eq!(
            error(run.step(&["no"], |ctx| arm(ctx, Slot::B))),
            "Not confirmed; nothing was changed."
        );
        assert!(!run.state.borrow().deployed.contains_key("b"));
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

        // A provisioning round's shares live in the relay's memory, which a roll drops.
        ok(run.step(&["yes"], proxy_update));
        let standby = run.instance("b");
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .session
            .lifecycle = "withdraw/OPERATOR_INITIALIZED".to_owned();
        run.set("slot-b-enabled", "false");
        assert!(
            error(run.step(&["yes"], proxy_update))
                .starts_with("The guardian the relay serves is in a key provisioner round")
        );
    }

    #[test]
    fn switches_over_only_once_ready() {
        let run = Run::new();
        run.armed_and_provisioned();
        assert_eq!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B))),
            "Set active-slot to b in stack mysten/testnet's Pulumi.<stack>.yaml first, and commit it."
        );
        run.set("active-slot", "b");
        run.state.borrow_mut().epoch_age = (10 * 60, 24 * 3600 + 10 * 60);
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .ends_with("30 minutes after the epoch turns.")
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
                .contains("Their limiter or deployment block differ")
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
            "Not confirmed; nothing was changed."
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::B);
        assert!(run.state.borrow().hosts[&old].running);
        // Declining the stop leaves the proxy on slot b and the old guardian running.
        assert_eq!(
            error(run.step(&["yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            "Not confirmed; nothing was changed."
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
                .starts_with("Stopping slot a's guardian did not finish")
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
                .starts_with("Keep slot-a-enabled \"true\"")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);
        run.set("slot-a-enabled", "true");

        let old = run.instance("a");
        assert_eq!(
            error(run.step(&["yes", "yes", "i-0wrong"], |ctx| switchover(ctx, Slot::B))),
            "Not confirmed; nothing was changed."
        );
        let operator = run
            .repo
            .path()
            .join(".hashi/guardian/testnet/b/operator.yaml");
        let rendered = std::fs::read(&operator).unwrap();
        std::fs::write(&operator, "changed").unwrap();
        assert!(
            error(run.step(&[&old], |ctx| switchover(ctx, Slot::B))).starts_with("Out of date")
        );
        std::fs::write(&operator, rendered).unwrap();

        // A relay that falls back to the new guardian cannot vouch for the old one.
        let standby = run.state.borrow_mut().standby.take();
        assert!(
            error(run.step(&[&old], |ctx| switchover(ctx, Slot::B)))
                .starts_with("Could not confirm through the relay")
        );
        run.state.borrow_mut().standby = standby;

        run.state.borrow_mut().epoch_age = (23 * 3600 + 30 * 60, 47 * 3600 + 30 * 60);
        assert!(error(run.step(&[&old], |ctx| switchover(ctx, Slot::B))).contains("ends in about"));
        assert!(run.state.borrow().hosts[&old].running);
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
        // A standby that never served can be abandoned, with a warning.
        run.set("slot-b-enabled", "false");
        let standby = run.instance("b");
        ok(run.step(&[&standby], |ctx| teardown(ctx, Slot::B)));
        assert!(!run.state.borrow().deployed.contains_key("b"));
        assert!(Path::new(&run.repo.path().join(".hashi")).exists());
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
        run.set("active-slot", "b");
        run.state.borrow_mut().extra_change = drift("update");
        assert!(
            error(run.step(&["yes"], |ctx| switchover(ctx, Slot::B)))
                .starts_with("Flipping the active slot must change no resource")
        );
        assert_eq!(run.state.borrow().outputs_active, Slot::A);

        run.set("active-slot", "a");
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
