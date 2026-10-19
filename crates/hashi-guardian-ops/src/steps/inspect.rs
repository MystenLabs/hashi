// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that change nothing: `status`, `info`, `host` and `tunnel`.

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
use crate::print_info;
use crate::print_warning;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::Stack;
use crate::stack::pulumi_pin;
use crate::stack::pulumi_version;
use crate::steps::slot;

/// Prints the stack's slots, the proxy and the relay. A read that fails is shown rather than fatal, so it still reports
/// a partly broken stack.
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
            view.require_deployed(ctx, &stack)?;
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

/// Prints a slot's guardian through its tunnel, once the proxy is shown to lead to it.
pub fn info(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg)?;
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
    let (stack, view) = slot(ctx, arg)?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    println!("Guardian host {instance}, slot {}", view.slot);
    let commands = host::report_commands();
    let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
    let report = host::run(ctx, &bucket.region, instance, &commands)?;
    println!("{}", report.text);
    if !report.success {
        bail!("could not read the host; a new instance takes a minute to accept commands");
    }
    // Only a cross-check: key provisioners' tools verify PCR0 from a fresh attestation.
    if let Some(reported) = host::reported_pcr0(&report.text) {
        if Some(reported) == stack.config(&view.pcr0_key) {
            println!(
                "\nThe enclave reports the PCR0 that {} configures.",
                view.pcr0_key
            );
        } else {
            print_warning(&format!(
                "The enclave reports PCR0 {reported}, not the {} stack {} configures. Key provisioners' tools will refuse it.",
                view.pcr0_key, stack.name
            ));
        }
    }
    Ok(())
}

/// Forwards the slot's local port to its guardian. It runs until stopped, so it gets a terminal of its own.
pub fn tunnel(ctx: &Ctx, arg: Option<Slot>) -> Result<()> {
    let (stack, view) = slot(ctx, arg)?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    print_info(&format!(
        "Forwarding {} to slot {}'s guardian on {instance}",
        view.endpoint, view.slot
    ));
    print_info("Leave this running in its own terminal while operator steps run.");
    let error = ctx.exec.exec(
        &Cmd::new("aws")
            .args(["ssm", "start-session", "--region", &bucket.region])
            .args(["--target", instance])
            .args(["--document-name", "AWS-StartPortForwardingSession"])
            .arg("--parameters")
            .arg(format!("portNumber=3000,localPortNumber={}", view.port)),
    );
    Err(anyhow::Error::new(error).context("could not start the tunnel"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use base64ct::Base64;
    use base64ct::Encoding;
    use serde_json::json;

    use super::*;
    use crate::exec::fake::Fake;
    use crate::guardian::tests::info_json;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::ENCLAVE;
    use crate::stack::tests::stack_env;

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// What `aws ec2 describe-instance-attribute` prints for a host launched to build `commit`.
    fn user_data(commit: &str) -> String {
        Base64::encode_string(format!("#!/bin/bash\ngit checkout {commit}\n").as_bytes())
    }

    /// A two-slot stack whose hosts build `COMMIT`, whose tunnels reach guardians with `KEY_A` and `KEY_B`, and whose
    /// proxy fronts `fronted` and relays to `relayed`.
    fn world(fronted: &'static str, relayed: &'static str) -> Fake {
        world_as_of(fronted, relayed, Some(Duration::ZERO))
    }

    /// [`world`], with the proxy's view `age` old, or undated.
    fn world_as_of(fronted: &'static str, relayed: &'static str, age: Option<Duration>) -> Fake {
        let stack = crate::stack::tests::two_slots();
        let answered = age.map(|age| {
            (SystemTime::now() - age)
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string()
        });
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
                ("curl", url) if url.ends_with("/info") => {
                    let mut info = json!({ "signingPubKey": fronted, "committeeEpoch": "1253" });
                    if let Some(answered) = &answered {
                        info["timestampMs"] = answered.clone().into();
                    }
                    Some((true, info.to_string()))
                }
                ("aws", _) if words[1] == "ec2" => Some((true, user_data(COMMIT))),
                _ => None,
            }
        })
    }

    /// A world where `stack`'s configuration and outputs load, its hosts build `launched` (or can't be read), and every
    /// other read fails. Any other command is a change, which fails the test.
    fn only_the_stack(stack: Fake, launched: Option<&'static str>) -> Fake {
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "config", ..] | ["pulumi", "-C", _, "stack", "output", ..] => {
                    crate::exec::Exec::output(&stack, &Cmd::new("pulumi").args(&words[1..]))
                        .ok()
                        .map(|output| (output.success, output.stdout))
                }
                ["aws", "ec2", "describe-instance-attribute", ..] => Some(
                    launched.map_or((false, String::new()), |commit| (true, user_data(commit))),
                ),
                ["pulumi", "version"]
                | ["pulumi", "-C", _, "stack", "export", ..]
                | ["pulumi", "-C", _, "stack", "tag", "ls", ..]
                | ["curl", ..] => Some((false, String::new())),
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
        assert!(error.starts_with(&format!("the proxy fronts guardian {KEY_B}, but http://127.0.0.1:3000 reaches slot a's {KEY_A};")), "{error}");
        let error = info(&ctx, Some(Slot::B)).unwrap_err().to_string();
        assert!(error.starts_with(&format!("the proxy's relay sends key provisioners to guardian {KEY_A}, but http://127.0.0.1:3001 reaches slot b's {KEY_B};")), "{error}");
        assert_eq!(
            info(&ctx, None).unwrap_err().to_string(),
            "stack org/testnet has guardian slots a and b; name the one this step acts on with --slot a or --slot b"
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
                "http://127.0.0.1:3001 reaches the guardian the proxy fronts, {KEY_B}, not slot b's standby; check that the tunnel is slot b's"
            )
        );
    }

    #[test]
    fn info_needs_a_current_proxy_view_of_an_active_guardian() {
        // The proxy serves its last view while it can't reach its guardian, so an old one shows nothing about the route.
        let repo = tempfile::tempdir().unwrap();
        let exec = world_as_of(KEY_A, KEY_B, Some(CURRENT_FOR * 2));
        let ctx = test_ctx(repo.path(), &exec);
        let error = info(&ctx, Some(Slot::A)).unwrap_err().to_string();
        assert!(
            error.starts_with("the proxy's /info is ")
                && error.contains(
                    "s old, too old to show that the proxy still reaches slot a's guardian;"
                ),
            "{error}"
        );
        // A standby's tunnel has only to reach a guardian other than the one the proxy last showed.
        info(&ctx, Some(Slot::B)).unwrap();

        let exec = world_as_of(KEY_A, KEY_B, None);
        let ctx = test_ctx(repo.path(), &exec);
        assert_eq!(
            info(&ctx, Some(Slot::A)).unwrap_err().to_string(),
            "the proxy's /info does not say when its guardian answered, so it does not show that the proxy reaches slot a's guardian"
        );
    }

    #[test]
    fn reads_no_guardian_whose_host_builds_another_commit() {
        // Until the stack deploys a slot's new commit, its host runs the old one, which the new commit's protos may
        // misread. Both hosts here build COMMIT.
        let pending = "c4".repeat(20);
        let outputs = json!({
            "active_slot": "a",
            "enclave_instance_id": "i-0aaa",
            "standby_instance_id": "i-0bbb",
            "s3_bucket_name": "guardian-bucket",
            "s3_bucket_region": "us-west-2",
        });
        let mut no_standby = outputs.clone();
        no_standby["standby_instance_id"] = "".into();
        for (slot, host, config, outputs) in [
            (
                Slot::A,
                "i-0aaa",
                json!({ "hashi-commit": pending }),
                no_standby,
            ),
            (
                Slot::B,
                "i-0bbb",
                json!({ "hashi-commit": COMMIT, "hashi-commit-b": pending, "slot-b-enabled": "true" }),
                outputs,
            ),
        ] {
            let repo = tempfile::tempdir().unwrap();
            let exec = only_the_stack(
                crate::stack::tests::stack_world(config, outputs),
                Some(COMMIT),
            );
            let ctx = test_ctx(repo.path(), &exec);
            std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(&pending))
                .unwrap();
            assert_eq!(
                info(&ctx, Some(slot)).unwrap_err().to_string(),
                format!(
                    "stack org/testnet configures commit {pending} for slot {slot}, but its host {host} was launched to build another commit; set it back, or deploy it, first"
                )
            );
            // status reads the relay as this slot, and grpcurl would fail the test.
            status(&ctx).unwrap();
        }
    }

    #[test]
    fn status_reports_a_partly_broken_stack() {
        let repo = tempfile::tempdir().unwrap();
        let exec = only_the_stack(crate::stack::tests::two_slots(), None);
        let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
        status(&ctx).unwrap();
        for read in [
            &["pulumi", "version"][..],
            &["pulumi", "-C", ENCLAVE, "stack", "export"],
            &["pulumi", "-C", ENCLAVE, "stack", "tag", "ls"],
            &["curl"],
            &["aws", "ec2", "describe-instance-attribute"],
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
