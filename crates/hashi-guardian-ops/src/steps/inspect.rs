// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that change nothing: `status`, `info`, `host` and `tunnel`.

use std::io::Write;

use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::guardian::CURRENT_FOR;
use crate::guardian::ProxyInfo;
use crate::guardian::proxy_info;
use crate::guardian::relay_info;
use crate::guardian::require_reached;
use crate::host;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::Stack;
use crate::stack::pulumi_version;
use crate::steps::slot;
use crate::warn;

/// Prints the stack's slots, the proxy and the relay. A read that fails is shown rather than fatal, so it still reports
/// a partly broken stack.
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
        Ok(tags) => format!("{}, from sui-operations' rotation scripts", tags.join(", ")),
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
    // The relay leads to a standby once the proxy follows it, so its answer is read with the standby's build.
    let relay = stack
        .active()
        .and_then(|active| {
            let read_as = match stack.role(active.other())? {
                Role::Standby => active.other(),
                _ => active,
            };
            stack.slot(ctx, read_as)
        })
        .and_then(|view| {
            Tree::at(
                ctx,
                &view.commit,
                &format!("the commit slot {}'s guardian runs", view.slot),
            )
        })
        .and_then(|tree| relay_info(ctx, &tree));
    let relay = match relay {
        Ok(info) => format!(
            "sends key provisioners to {} ({}){}",
            info.signing_key.as_deref().unwrap_or("no guardian"),
            info.lifecycle,
            if info.lifecycle.in_kp_round() {
                "; a key provisioner round is open"
            } else {
                ""
            }
        ),
        Err(error) => format!("unknown: {error:#}"),
    };
    println!("Relay:         {relay}");
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
            ", as of {}s ago: the guardian has stopped answering the proxy",
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

/// Prints a slot's guardian through its tunnel, once the proxy is shown to lead to it.
pub fn info(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "info")?;
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let reached = require_reached(ctx, &stack, &view, &tree)?;
    let url = ctx.env.proxy_url()?.url;
    println!(
        "Slot:        {}, {}, on {}",
        view.slot,
        view.role,
        view.instance.as_deref().unwrap_or("")
    );
    println!("Signing key: {}", reached.signing_key);
    println!(
        "BTC key:     {}",
        reached
            .info
            .btc_key
            .as_deref()
            .unwrap_or("none; the guardian is not provisioned")
    );
    println!("Lifecycle:   {}", reached.info.lifecycle);
    match &reached.proxy {
        Some(proxy) => {
            println!("Proxy:       fronts this guardian at {url}");
            match &proxy.committee_epoch {
                Some(epoch) => println!("Serving:     committee epoch {epoch}"),
                None => println!("Serving:     no; the guardian is not activated"),
            }
        }
        None => println!("Relay:       sends key provisioners to this guardian at {url}"),
    }
    Ok(())
}

/// Prints a slot's host: the end of its boot log, its enclave and its units.
pub fn host(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "host")?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    say(&format!("Guardian host {instance}, slot {}", view.slot));
    let commands = host::report_commands();
    let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
    let report = host::run(ctx, &bucket.region, instance, &commands)?;
    println!("{}", report.text);
    if !report.success {
        bail!("Could not read the host. A new instance takes a minute to accept commands.");
    }
    // Only a cross-check: key provisioners' tools verify PCR0 from a fresh attestation.
    if let Some(reported) = host::reported_pcr0(&report.text) {
        if Some(reported) == stack.config(&view.pcr0_key) {
            println!(
                "\nThe enclave reports the PCR0 that {} configures.",
                view.pcr0_key
            );
        } else {
            warn(&format!(
                "The enclave reports PCR0 {reported}, not the {} stack {} configures. Key provisioners' tools will refuse it.",
                view.pcr0_key, stack.name
            ));
        }
    }
    Ok(())
}

/// Forwards the slot's local port to its guardian. It runs until stopped, so it gets a terminal of its own.
pub fn tunnel(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "tunnel")?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    say(&format!(
        "Forward {} to slot {}'s guardian on {instance}",
        view.endpoint, view.slot
    ));
    println!("Leave this running in its own terminal while operator steps run.");
    std::io::stdout().flush()?;
    let error = ctx.exec.exec(
        &Cmd::new("aws")
            .args(["ssm", "start-session", "--region", &bucket.region])
            .args(["--target", instance])
            .args(["--document-name", "AWS-StartPortForwardingSession"])
            .arg("--parameters")
            .arg(format!("portNumber=3000,localPortNumber={}", view.port)),
    );
    Err(anyhow::Error::new(error).context("Could not start the tunnel."))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::exec::fake::Fake;
    use crate::guardian::tests::info_json;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::stack_env;

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A two-slot stack whose tunnels reach guardians with `KEY_A` and `KEY_B`, and whose proxy fronts `fronted` and
    /// relays to `relayed`.
    fn world(fronted: &'static str, relayed: &'static str) -> Fake {
        let stack = crate::stack::tests::two_slots();
        Fake::new(move |words| {
            if words[0] == "pulumi" {
                return crate::exec::Exec::output(&stack, &Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout));
            }
            let last = words.last().unwrap().as_str();
            match (words[0].as_str(), last) {
                ("grpcurl", "sui.hashi.v1alpha.GuardianService/GetGuardianInfo") => {
                    let key = if words.contains(&"127.0.0.1:3000".to_owned()) {
                        KEY_A
                    } else {
                        KEY_B
                    };
                    Some((
                        true,
                        json!({ "info": info_json(key, None, "none") }).to_string(),
                    ))
                }
                ("grpcurl", "sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo") => {
                    Some((
                        true,
                        json!({ "signedInfo": { "data": info_json(relayed, None, "none") } })
                            .to_string(),
                    ))
                }
                ("curl", url) if url.ends_with("/info") => Some((
                    true,
                    json!({ "signingPubKey": fronted, "committeeEpoch": "1253" }).to_string(),
                )),
                _ => None,
            }
        })
    }

    fn test_ctx<'a>(repo: &std::path::Path, exec: &'a Fake) -> Ctx<'a> {
        std::fs::create_dir_all(repo.join(".hashi/guardian-init").join(COMMIT)).unwrap();
        Ctx::for_test(repo, exec, &stack_env())
    }

    #[test]
    fn info_checks_the_proxy_leads_to_the_slot() {
        let repo = tempfile::tempdir().unwrap();
        let exec = world(KEY_A, KEY_B);
        let ctx = test_ctx(repo.path(), &exec);
        info(&ctx, Some(Slot::A)).unwrap();
        info(&ctx, Some(Slot::B)).unwrap();
        assert!(exec.ran(&["grpcurl", "-import-path"]));

        let exec = world(KEY_B, KEY_A);
        let ctx = test_ctx(repo.path(), &exec);
        let error = info(&ctx, Some(Slot::A)).unwrap_err().to_string();
        assert!(error.starts_with(&format!("The proxy fronts guardian {KEY_B}, but http://127.0.0.1:3000 reaches slot a's {KEY_A}.")), "{error}");
        let error = info(&ctx, Some(Slot::B)).unwrap_err().to_string();
        assert!(error.starts_with(&format!("The proxy's relay sends key provisioners to guardian {KEY_A}, but http://127.0.0.1:3001 reaches slot b's {KEY_B}.")), "{error}");
        assert_eq!(
            info(&ctx, None).unwrap_err().to_string(),
            "Stack mysten/testnet has guardian slots a and b. Name the one this step acts on: info a or info b."
        );
    }

    #[test]
    fn info_refuses_a_standby_tunnel_that_reaches_the_active_guardian() {
        // Before the proxy follows a new standby, its relay leads to the guardian it fronts.
        let repo = tempfile::tempdir().unwrap();
        let exec = world(KEY_B, KEY_B);
        let ctx = test_ctx(repo.path(), &exec);
        assert_eq!(
            info(&ctx, Some(Slot::B)).unwrap_err().to_string(),
            format!(
                "http://127.0.0.1:3001 reaches the guardian the proxy fronts, {KEY_B}, not slot b's standby. Check that the tunnel is slot b's."
            )
        );
    }

    #[test]
    fn status_reports_a_partly_broken_stack() {
        let repo = tempfile::tempdir().unwrap();
        let dir = crate::stack::tests::sui_operations(repo.path());
        let stack = crate::stack::tests::two_slots();
        // The stack loads, and every other read fails.
        let exec = Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "config", ..] | ["pulumi", "-C", _, "stack", "output", ..] => {
                    crate::exec::Exec::output(&stack, &Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                _ => Some((false, String::new())),
            }
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &crate::stack::tests::stack_env_at(&dir));
        status(&ctx).unwrap();
        for read in [
            &["pulumi", "version"][..],
            &["pulumi", "-C", &dir, "stack", "export"],
            &["pulumi", "-C", &dir, "stack", "tag", "ls"],
            &["curl"],
            &["git"],
        ] {
            assert!(exec.ran(read), "{read:?}");
        }
    }

    #[test]
    fn decodes_with_the_guardian_commits_protos() {
        let repo = tempfile::tempdir().unwrap();
        let exec = world(KEY_A, KEY_B);
        let ctx = test_ctx(repo.path(), &exec);
        info(&ctx, Some(Slot::A)).unwrap();
        let protos = repo
            .path()
            .join(".hashi/guardian-init")
            .join(COMMIT)
            .join("crates/hashi-types/proto");
        let log = exec.log.borrow();
        let grpcurl = log.iter().find(|words| words[0] == "grpcurl").unwrap();
        assert_eq!(
            grpcurl[1..3],
            ["-import-path".to_owned(), protos.display().to_string()]
        );
    }

    #[test]
    fn tunnel_forwards_the_slots_port() {
        let repo = tempfile::tempdir().unwrap();
        let exec = world(KEY_A, KEY_B);
        let ctx = test_ctx(repo.path(), &exec);
        assert!(tunnel(&ctx, Some(Slot::B)).is_err());
        assert_eq!(
            exec.log.borrow().last().unwrap()[..],
            [
                "aws",
                "ssm",
                "start-session",
                "--region",
                "us-west-2",
                "--target",
                "i-0bbb",
                "--document-name",
                "AWS-StartPortForwardingSession",
                "--parameters",
                "portNumber=3000,localPortNumber=3001",
            ]
        );
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
        let ctx = Ctx::for_test(repo.path(), &exec, &crate::stack::tests::stack_env());
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
            "enabled or not unknown (Stack mysten/testnet sets slot-b-enabled to yes, not true or false.), not deployed"
        );
        let info = ProxyInfo {
            signing_pub_key: Some("aa".to_owned()),
            btc_pubkey: None,
            git_revision: None,
            committee_epoch: Some("7".to_owned()),
            timestamp_ms: Some("1720000000123".to_owned()),
        };
        assert!(
            describe_proxy(&info).ends_with("ago: the guardian has stopped answering the proxy")
        );
    }
}
