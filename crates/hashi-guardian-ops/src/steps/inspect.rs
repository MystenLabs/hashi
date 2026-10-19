// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that change nothing: `status`.

use anyhow::Result;

use crate::Ctx;
use crate::guardian::CURRENT_FOR;
use crate::guardian::ProxyInfo;
use crate::guardian::proxy_info;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::Stack;
use crate::stack::pulumi_pin;
use crate::stack::pulumi_version;

/// Prints the stack's slots and the proxy. A read that fails is shown rather than fatal, so it still reports a partly
/// broken stack.
pub fn status(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    println!("Stack:         {}", stack.name);
    let pulumi = match (pulumi_pin(ctx), pulumi_version(ctx)) {
        (Ok(pinned), Ok(current)) if pinned == current => {
            format!("{current}, as PULUMI_VERSION pins")
        }
        (Ok(pinned), Ok(current)) => format!(
            "{current}, but PULUMI_VERSION pins {pinned}: put it first on your PATH before a step that changes a stack"
        ),
        (Err(error), _) | (_, Err(error)) => format!("unknown: {error:#}"),
    };
    println!("Pulumi:        {pulumi}");
    let written = match stack.written_by(ctx) {
        Ok(written) if written.is_empty() => "unknown".to_owned(),
        Ok(written) => written,
        Err(error) => format!("unknown: {error:#}"),
    };
    println!("Written by:    Pulumi {written}");
    let tags = match stack.rotation_tags(ctx) {
        Ok(tags) if tags.is_empty() => "none".to_owned(),
        Ok(tags) => tags.join(", "),
        Err(error) => format!("unknown: {error:#}"),
    };
    println!("Rotation tags: {tags}");
    for slot in Slot::ALL {
        println!("Slot {slot}:        {}", describe_slot(&stack, slot));
    }

    let proxy = match proxy_info(ctx) {
        Ok(info) => describe_proxy(&info),
        Err(error) => format!("unknown: {error:#}"),
    };
    println!("Proxy:         {proxy}");
    Ok(())
}

fn describe_slot(stack: &Stack, slot: Slot) -> String {
    let enabled = match stack.slot_enabled(slot) {
        Ok(true) => "enabled".to_owned(),
        Ok(false) => "disabled".to_owned(),
        Err(error) => format!("enabled or not unknown ({error:#})"),
    };
    let role = stack.role(slot);
    let deployed = match (&role, stack.instance(slot)) {
        (Ok(Role::Absent), _) => "not deployed".to_owned(),
        (Ok(role), Ok(Some(instance))) => format!("{role} on {instance}"),
        (Ok(role), _) => role.to_string(),
        (Err(error), _) => format!("{error:#}"),
    };
    let suffix = slot.suffix();
    let commit = stack.config(&format!("hashi-commit{suffix}"));
    let build = match (commit, stack.config(&format!("eif-pcr0{suffix}"))) {
        (None, None) => String::new(),
        (commit, pcr0) => format!(
            ", commit {}, PCR0 {}",
            commit.unwrap_or("unset"),
            pcr0.unwrap_or("unset")
        ),
    };
    // The stack's last update recorded the active slot's commit; one that differs has not been applied.
    let applied = match stack.output("guardian_hashi_commit") {
        Some(applied) if matches!(role, Ok(Role::Active)) && commit != Some(applied) => {
            format!(", but the stack last applied commit {applied}")
        }
        _ => String::new(),
    };
    format!("{enabled}, {deployed}{build}{applied}")
}

fn describe_proxy(info: &ProxyInfo) -> String {
    let age = match info.age() {
        Some(age) if age > CURRENT_FOR => format!(
            ", as of {}s ago, too old to show that the proxy still reaches that guardian",
            age.as_secs()
        ),
        Some(age) => format!(", as of {}s ago", age.as_secs()),
        None => ", as of an unknown time".to_owned(),
    };
    format!(
        "fronts {} (BTC key {}, build {}), {}{age}",
        info.signing_pub_key.as_deref().unwrap_or("no guardian"),
        info.btc_pubkey.as_deref().unwrap_or("none"),
        info.git_revision.as_deref().unwrap_or("unknown"),
        match &info.committee_epoch {
            Some(epoch) => format!("serving at committee epoch {epoch}"),
            None => "not activated".to_owned(),
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::Cmd;
    use crate::exec::Exec;
    use crate::exec::fake::Fake;
    use crate::stack::tests::ENCLAVE;
    use crate::stack::tests::stack_env;

    #[test]
    fn reports_a_partly_broken_stack() {
        let repo = tempfile::tempdir().unwrap();
        let stack = crate::stack::tests::two_slots();
        // The stack loads, and every other read fails. Any other command is a change, which fails the test.
        let exec = Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "config", ..] | ["pulumi", "-C", _, "stack", "output", ..] => {
                    stack
                        .output(&Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                ["pulumi", "version"]
                | ["pulumi", "-C", _, "stack", "export", ..]
                | ["pulumi", "-C", _, "stack", "tag", "ls", ..]
                | ["curl", ..] => Some((false, String::new())),
                _ => None,
            }
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        status(&ctx).unwrap();
        for read in [
            &["pulumi", "version"][..],
            &["pulumi", "-C", ENCLAVE, "stack", "export"],
            &["pulumi", "-C", ENCLAVE, "stack", "tag", "ls"],
            &["curl"],
        ] {
            assert!(exec.ran(read), "{read:?}");
        }
    }

    #[test]
    fn shows_what_has_not_been_applied_and_a_proxy_view_gone_stale() {
        let repo = tempfile::tempdir().unwrap();
        let exec = crate::stack::tests::stack_world(
            serde_json::json!({ "hashi-commit": "c4".repeat(20), "slot-b-enabled": "yes" }),
            serde_json::json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "guardian_hashi_commit": crate::stack::tests::COMMIT,
            }),
        );
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        let stack = Stack::load(&ctx).unwrap();
        assert_eq!(
            describe_slot(&stack, Slot::A),
            format!(
                "enabled, active on i-0aaa, commit {}, PCR0 unset, but the stack last applied commit {}",
                "c4".repeat(20),
                crate::stack::tests::COMMIT
            )
        );
        assert_eq!(
            describe_slot(&stack, Slot::B),
            "enabled or not unknown (stack org/testnet sets slot-b-enabled to yes, not true or false), not deployed"
        );
        let info = ProxyInfo {
            signing_pub_key: Some("aa".to_owned()),
            btc_pubkey: None,
            git_revision: None,
            committee_epoch: Some("7".to_owned()),
            timestamp_ms: Some("1720000000123".to_owned()),
        };
        assert!(
            describe_proxy(&info)
                .ends_with("ago, too old to show that the proxy still reaches that guardian")
        );
    }
}
