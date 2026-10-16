// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that change nothing: `status`.

use anyhow::Result;

use crate::Ctx;
use crate::guardian::ProxyInfo;
use crate::guardian::proxy_info;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::Stack;
use crate::stack::pulumi_version;

/// Prints the stack's slots and the proxy. A read that fails is shown rather than fatal, so it still reports a partly
/// broken stack.
pub fn status(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    say(&format!("Guardian stack {}", stack.name));
    let pulumi = match (stack.pinned_pulumi_version(), pulumi_version(ctx)) {
        (Ok(pinned), Ok(current)) if pinned == current => {
            format!("{current}, as sui-operations' guardian workflows install")
        }
        (Ok(pinned), Ok(current)) => format!(
            "{current}, but sui-operations' guardian workflows install {pinned}: put it first on your PATH before a step that changes a stack"
        ),
        (Err(error), _) | (_, Err(error)) => format!("unknown: {error}"),
    };
    println!("Pulumi:        {pulumi}");
    let written = match stack.written_by(ctx) {
        Ok(written) if written.is_empty() => "unknown".to_owned(),
        Ok(written) => written,
        Err(error) => format!("unknown: {error}"),
    };
    println!("Written by:    Pulumi {written}");
    let tags = match stack.rotation_tags(ctx) {
        Ok(tags) if tags.is_empty() => "none".to_owned(),
        Ok(tags) => format!("{}, from sui-operations' rotation scripts", tags.join(", ")),
        Err(error) => format!("unknown: {error}"),
    };
    println!("Rotation tags: {tags}");
    for slot in Slot::ALL {
        println!("Slot {slot}:        {}", describe_slot(&stack, slot));
    }

    let proxy = match proxy_info(ctx) {
        Ok(info) => describe_proxy(&info),
        Err(error) => format!("unknown: {error}"),
    };
    println!("Proxy:         {proxy}");
    Ok(())
}

fn describe_slot(stack: &Stack, slot: Slot) -> String {
    let enabled = match stack.slot_enabled(slot) {
        Ok(true) => "enabled",
        Ok(false) => "disabled",
        Err(error) => return error.to_string(),
    };
    let deployed = match (stack.role(slot), stack.instance(slot)) {
        (Ok(Role::Absent), _) => "not deployed".to_owned(),
        (Ok(role), Ok(Some(instance))) => format!("{role} on {instance}"),
        (Ok(role), _) => role.to_string(),
        (Err(error), _) => error.to_string(),
    };
    let suffix = slot.suffix();
    let build = match (
        stack.config(&format!("hashi-commit{suffix}")),
        stack.config(&format!("eif-pcr0{suffix}")),
    ) {
        (None, None) => String::new(),
        (commit, pcr0) => format!(
            ", commit {}, PCR0 {}",
            commit.unwrap_or("unset"),
            pcr0.unwrap_or("unset")
        ),
    };
    format!("{enabled}, {deployed}{build}")
}

fn describe_proxy(info: &ProxyInfo) -> String {
    format!(
        "fronts {} (BTC key {}, build {}), {}",
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
    use crate::stack::tests::stack_env_at;
    use crate::stack::tests::sui_operations;

    #[test]
    fn reports_a_partly_broken_stack() {
        let repo = tempfile::tempdir().unwrap();
        let dir = sui_operations(repo.path());
        let stack = crate::stack::tests::two_slots();
        // The stack loads, and every other read fails.
        let exec = Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "config", ..] | ["pulumi", "-C", _, "stack", "output", ..] => {
                    stack
                        .output(&Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                _ => Some((false, String::new())),
            }
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env_at(&dir));
        status(&ctx).unwrap();
        for read in [
            &["pulumi", "version"][..],
            &["pulumi", "-C", &dir, "stack", "export"],
            &["pulumi", "-C", &dir, "stack", "tag", "ls"],
            &["curl"],
        ] {
            assert!(exec.ran(read), "{read:?}");
        }
    }
}
