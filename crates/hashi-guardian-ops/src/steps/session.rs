// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A guardian session's life, through `hashi-guardian-init` at the guardian's commit: `ceremony`, `new-session`,
//! `provision` and `activate`.

use std::io::Write;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use crate::Ctx;
use crate::ask::Unchanged;
use crate::ask::confirm;
use crate::ask::confirm_typed;
use crate::commit::Tree;
use crate::guardian::completed_ceremonies;
use crate::guardian::require_reached;
use crate::host;
use crate::next;
use crate::render::require_fresh;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::steps::slot;
use crate::warn;

/// The `operator` commands of `hashi-guardian-init` this tool hands a step to.
#[derive(Clone, Copy)]
pub enum OperatorStep {
    Ceremony,
    Provision { do_genesis: bool },
    Activate,
}

impl OperatorStep {
    fn name(self) -> &'static str {
        match self {
            Self::Ceremony => "ceremony",
            Self::Provision { .. } => "provision",
            Self::Activate => "activate",
        }
    }
}

/// Runs `operator <step>` against the slot's guardian, once its rendered files are fresh and its tunnel is shown to
/// reach the guardian the proxy leads to.
pub fn operator(ctx: &Ctx, arg: Option<Slot>, step: OperatorStep) -> Result<()> {
    let (stack, view) = slot(ctx, arg, step.name())?;
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    require_fresh(ctx, &stack, &view)?;
    // Another guardian's tunnel can be holding the local port.
    require_reached(ctx, &stack, &view, &tree)?;
    if let OperatorStep::Ceremony = step {
        let bucket = stack.bucket()?;
        if completed_ceremonies(ctx, &bucket)? != 0 {
            bail!(
                "s3://{} already holds a completed key ceremony. A new guardian key needs a new s3-bucket-name.",
                bucket.name
            );
        }
        warn(&format!(
            "The ceremony fixes three things for the life of the guardian's key: Bitcoin network {}, retention class {}, and log bucket s3://{}.",
            ctx.env.require("BITCOIN_NETWORK")?,
            ctx.env.require("RETENTION_ENVIRONMENT")?,
            bucket.name
        ));
        confirm(
            ctx.ask,
            "Run the ceremony with them?",
            &Unchanged {
                no_input: "No input received; the ceremony was not run.",
                declined: "Not confirmed; the ceremony was not run.",
            },
        )?;
    }
    next(&match step {
        OperatorStep::Ceremony => format!(
            "once every key provisioner has confirmed and this prints the guardian's BTC key, new-session {}",
            view.slot
        ),
        OperatorStep::Provision { .. } if view.role == Role::Standby => format!(
            "once a threshold of key provisioners has provisioned it, switchover {}",
            view.slot
        ),
        OperatorStep::Provision { .. } => format!(
            "once a threshold of key provisioners has provisioned it, activate {}",
            view.slot
        ),
        OperatorStep::Activate => format!("info {}", view.slot),
    });
    let mut cmd = guardian_init
        .cmd()
        .args(["operator", step.name(), "--config", "operator.yaml"])
        // The configuration lists certificates relative to its own directory.
        .cwd(&view.dir);
    if let OperatorStep::Provision { do_genesis: true } = step {
        cmd = cmd.arg("--do-genesis");
    }
    std::io::stdout().flush()?;
    Err(anyhow::Error::new(ctx.exec.exec(&cmd)).context("Could not run hashi-guardian-init."))
}

/// Restarts the slot's enclave, so the next `operator` step finds a fresh session. Whatever the old session held is
/// lost, so it says what that is and has the operator type the instance ID.
pub fn new_session(ctx: &Ctx, arg: Option<Slot>, abandon: bool) -> Result<()> {
    let (stack, view) = slot(ctx, arg, "new-session")?;
    let bucket = stack.bucket()?;
    let instance = view.require_instance(&stack)?;
    say(&format!(
        "Start a fresh guardian session on slot {}, {instance}",
        view.slot
    ));
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {}'s guardian runs", view.slot),
    )?;
    // Another guardian's tunnel can be holding the local port, and its state would pass the gates below.
    let lifecycle = require_reached(ctx, &stack, &view, &tree)?.info.lifecycle;
    // Restarting a ceremony session before it commits loses the ceremony.
    if completed_ceremonies(ctx, &bucket)? == 0 {
        bail!(
            "s3://{}/ceremony/ holds no completed ceremony, so a fresh session would have no key to be provisioned with.",
            bucket.name
        );
    }
    let slot = view.slot;
    match lifecycle.to_string().as_str() {
        "ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS" => {
            if !abandon {
                bail!(
                    "Slot {slot}'s guardian has dealt shares that not every key provisioner has confirmed yet. Restarting it abandons that ceremony, and everyone who took part starts it again. To do that anyway: new-session {slot} --abandon"
                );
            }
            warn(&format!("Abandoning slot {slot}'s ceremony."));
        }
        "ceremony/OPERATOR_INITIALIZED" => warn(&format!(
            "Slot {slot}'s guardian is initialized for a ceremony that has not dealt yet. Restarting it ends that session, so that step starts again."
        )),
        "withdraw/ACTIVATED" => {
            if stack.slots()?.len() > 1 {
                bail!(
                    "Slot {slot}'s guardian serves withdrawals while the stack has two slots. Move its key with the switchover step instead."
                );
            }
            warn(&format!(
                "Slot {slot}'s guardian is serving withdrawals. Restarting it loses its key, and it serves nothing until a threshold of key provisioners provision it again."
            ));
        }
        other => warn(&format!(
            "Restarting the enclave ends its session ({other}). A guardian that holds its key loses it, and serves nothing until a threshold of key provisioners provision it again."
        )),
    }
    confirm_typed(
        ctx.ask,
        instance,
        "to restart that guardian",
        &Unchanged {
            no_input: "No input received; nothing was restarted.",
            declined: "Not confirmed; nothing was restarted.",
        },
    )?;
    // Starting the enclave unit does not start the bridge that depends on it. is-active succeeds when any one of
    // several units is active, and the enclave unit is active while it retries.
    let check_units = format!(
        "for unit in {}; do systemctl is-active --quiet $unit || {{ echo $unit is not active; exit 1; }}; done",
        host::UNITS
    );
    let restarted = host::run(
        ctx,
        &bucket.region,
        instance,
        &[
            "systemctl restart hashi-guardian-enclave.service",
            "sleep 20",
            "systemctl start hashi-guardian-bridge.service",
            &check_units,
            "nitro-cli describe-enclaves",
            "nitro-cli describe-enclaves | grep -q RUNNING",
        ],
    )?;
    if !restarted.success {
        println!("{}", restarted.text);
        return Err(anyhow!(
            "The restart did not leave the enclave and its units running. Check the host step before going on."
        ));
    }
    println!(
        "\nGuardian restarted. Run the info step: its signing key must be new and its BTC key unset."
    );
    next(&format!("info {slot}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::ask::scripted::Scripted;
    use crate::exec::Cmd;
    use crate::exec::Exec;
    use crate::exec::fake::Fake;
    use crate::guardian::tests::info_json;
    use crate::stack::tests::COMMIT;
    use crate::stack::tests::stack_env;

    const KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// A two-slot stack whose slot b reaches a guardian in `lifecycle`, over a bucket holding `ceremonies`.
    fn world(lifecycle: &'static str, ceremonies: u64) -> Fake {
        world_relaying_to(lifecycle, ceremonies, KEY)
    }

    /// The same, with the relay sending key provisioners to the guardian whose signing key is `relayed`.
    fn world_relaying_to(lifecycle: &'static str, ceremonies: u64, relayed: &'static str) -> Fake {
        let stack = crate::stack::tests::two_slots();
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                [
                    "grpcurl",
                    ..,
                    "sui.hashi.v1alpha.GuardianService/GetGuardianInfo",
                ] => Some((
                    true,
                    json!({ "info": info_json(KEY, None, lifecycle) }).to_string(),
                )),
                [
                    "grpcurl",
                    ..,
                    "sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo",
                ] => Some((
                    true,
                    json!({ "signedInfo": { "data": info_json(relayed, None, lifecycle) } })
                        .to_string(),
                )),
                ["aws", "s3api", "list-objects-v2", ..] => Some((true, format!("{ceremonies}\n"))),
                ["aws", "ssm", "send-command", ..] => Some((true, "cmd-1\n".to_owned())),
                ["aws", "ssm", "wait", ..] => Some((true, String::new())),
                ["aws", "ssm", "get-command-invocation", ..] => {
                    Some((true, "RUNNING\t\n".to_owned()))
                }
                _ => None,
            }
        })
    }

    fn run(exec: &Fake, answers: &[&str], abandon: bool) -> Result<()> {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let ask = Scripted::new(answers);
        let ctx = Ctx::for_test(repo.path(), exec, &stack_env()).with_ask(&ask);
        new_session(&ctx, Some(Slot::B), abandon)
    }

    #[test]
    fn refuses_to_abandon_an_unconfirmed_ceremony_unasked() {
        let exec = world("ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS", 1);
        let error = run(&exec, &["i-0bbb"], false).unwrap_err().to_string();
        assert!(
            error.ends_with("To do that anyway: new-session b --abandon"),
            "{error}"
        );
        assert!(!exec.ran(&["aws", "ssm", "send-command"]));
        run(&exec, &["i-0bbb"], true).unwrap();
        assert!(exec.ran(&["aws", "ssm", "send-command"]));
    }

    #[test]
    fn refuses_without_a_completed_ceremony() {
        let exec = world("none", 0);
        assert_eq!(
            run(&exec, &["i-0bbb"], false).unwrap_err().to_string(),
            "s3://guardian-bucket/ceremony/ holds no completed ceremony, so a fresh session would have no key to be provisioned with."
        );
    }

    #[test]
    fn restarts_only_the_guardian_the_proxy_leads_to() {
        // Slot b's port reaches some other guardian, whose state would pass every gate.
        let other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let exec = world_relaying_to("ceremony/COMPLETED", 1, other);
        let error = run(&exec, &["i-0bbb"], false).unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "The proxy's relay sends key provisioners to guardian {other}"
            )),
            "{error}"
        );
        assert!(!exec.ran(&["aws", "ssm", "send-command"]));
    }

    #[test]
    fn refuses_the_serving_guardian_mid_rotation() {
        let exec = world("withdraw/ACTIVATED", 1);
        assert_eq!(
            run(&exec, &["i-0bbb"], false).unwrap_err().to_string(),
            "Slot b's guardian serves withdrawals while the stack has two slots. Move its key with the switchover step instead."
        );
    }

    #[test]
    fn restarts_only_the_typed_instance() {
        let exec = world("ceremony/COMPLETED", 2);
        assert_eq!(
            run(&exec, &["i-0aaa"], false).unwrap_err().to_string(),
            "Not confirmed; nothing was restarted."
        );
        assert!(!exec.ran(&["aws", "ssm", "send-command"]));
        run(&exec, &["i-0bbb"], false).unwrap();
        let log = exec.log.borrow();
        let send = log.iter().find(|words| words[2] == "send-command").unwrap();
        assert!(send.contains(&"i-0bbb".to_owned()));
    }
}
