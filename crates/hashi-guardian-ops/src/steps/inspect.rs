// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The steps that change nothing: `status`, `info`, `host` and `tunnel`.

use std::io::Write;

use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::commit::Tree;
use crate::exec::Cmd;
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
use crate::sui;
use crate::warn;

/// Prints the stack's slots, the proxy, the relay and the epoch. A read that fails is shown rather than fatal, so it
/// still reports a partly broken stack.
pub fn status(ctx: &Ctx) -> Result<()> {
    let stack = Stack::load(ctx)?;
    say(&format!("Guardian stack {}", stack.name));
    let pulumi = match (stack.written_by(ctx), pulumi_version(ctx)) {
        (Ok(written), Ok(current)) if written == current => {
            format!("{current}, which last wrote the stack")
        }
        (Ok(written), Ok(current)) => format!(
            "{current}, but Pulumi {written} last wrote the stack: put it first on your PATH before a step that changes it"
        ),
        (Err(error), _) | (_, Err(error)) => format!("unknown: {error}"),
    };
    println!("Pulumi:        {pulumi}");
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
    let relay = stack
        .active()
        .and_then(|active| stack.slot(ctx, active))
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
        Err(error) => format!("unknown: {error}"),
    };
    println!("Relay:         {relay}");
    if ctx.env.get("SUI_GRAPHQL_URL").is_some() {
        let epoch = match sui::window(ctx, sui::now()) {
            Ok(window) => format!(
                "{}, began {} ago, ends in about {}{}",
                window.epoch,
                sui::duration(window.since),
                sui::duration(window.remaining),
                if window.allows_switchover() {
                    "; the time allows a switchover"
                } else {
                    "; too close to the turn for a switchover"
                }
            ),
            Err(error) => format!("unknown: {error}"),
        };
        println!("Sui epoch:     {epoch}");
    }
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
}
