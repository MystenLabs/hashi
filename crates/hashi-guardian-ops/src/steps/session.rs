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
use crate::commit::GuardianInit;
use crate::commit::Tree;
use crate::guardian::completed_ceremonies;
use crate::guardian::require_reached;
use crate::guardian::slot_info;
use crate::host;
use crate::next;
use crate::render::require_fresh;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
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
    let reached = require_reached(ctx, &stack, &view, &tree)?;
    if let OperatorStep::Ceremony = step {
        let bucket = stack.bucket()?;
        let no_ceremony = || -> Result<()> {
            if completed_ceremonies(ctx, &bucket)? != 0 {
                bail!(
                    "s3://{} already holds a completed key ceremony. A new guardian key needs a new s3-bucket-name.",
                    bucket.name
                );
            }
            Ok(())
        };
        no_ceremony()?;
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
        // The question can wait any time, while the files, the tunnel or the bucket change.
        require_fresh(ctx, &stack, &view)?;
        if require_reached(ctx, &stack, &view, &tree)?.signing_key != reached.signing_key {
            bail!(
                "{} reaches another guardian than the one this step checked. The ceremony was not run: run this step again.",
                view.endpoint
            );
        }
        no_ceremony()?;
    }
    let then = match step {
        OperatorStep::Activate => {
            say(&format!("Activate slot {}'s guardian", view.slot));
            activate(ctx, &tree, &guardian_init, &view)?;
            next(&format!("info {}", view.slot));
            return Ok(());
        }
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
    };
    let mut cmd = guardian_init
        .cmd()
        .args(["operator", step.name(), "--config", "operator.yaml"])
        // The configuration lists certificates relative to its own directory.
        .cwd(&view.dir);
    if let OperatorStep::Provision { do_genesis: true } = step {
        cmd = cmd.arg("--do-genesis");
    }
    std::io::stdout().flush()?;
    if !ctx.exec.run(&cmd)? {
        bail!(
            "hashi-guardian-init operator {} did not succeed.",
            step.name()
        );
    }
    next(&then);
    Ok(())
}

/// Runs `operator activate` on the slot's guardian and checks that it activated. The CLI's post-check compares the
/// live limiter state, which a withdrawal signed right after activation changes, so a failure is only a warning when
/// the same session, with the same keys, then reports itself activated.
pub(crate) fn activate(
    ctx: &Ctx,
    tree: &Tree,
    guardian_init: &GuardianInit,
    view: &SlotView,
) -> Result<()> {
    let before = slot_info(ctx, tree, view)?;
    if before.lifecycle.is("withdraw/ACTIVATED") {
        println!("Slot {}'s guardian is already activated.", view.slot);
        return Ok(());
    }
    if !before.lifecycle.is("withdraw/PROVISIONER_INITIALIZED") {
        bail!(
            "Slot {}'s guardian is {}, not provisioned and waiting for activation.",
            view.slot,
            before.lifecycle
        );
    }
    println!(
        "It waits until every other guardian session has been quiet for ten minutes, and prints little until then."
    );
    std::io::stdout().flush()?;
    let activated = ctx.exec.run(
        &guardian_init
            .cmd()
            .args(["operator", "activate", "--config", "operator.yaml"])
            .cwd(&view.dir),
    )?;
    let after = slot_info(ctx, tree, view)?;
    if after.signing_key != before.signing_key || after.btc_key != before.btc_key {
        bail!(
            "{} now reaches a guardian with other keys than the one activation ran on. Check that the tunnel is slot {}'s.",
            view.endpoint,
            view.slot
        );
    }
    if !after.lifecycle.is("withdraw/ACTIVATED") {
        bail!(
            "Slot {}'s guardian is {}, not activated. Run this step again once it can activate.",
            view.slot,
            after.lifecycle
        );
    }
    if !activated {
        warn(&format!(
            "operator activate failed, but slot {}'s guardian reports itself activated.",
            view.slot
        ));
    }
    Ok(())
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
    let reached = require_reached(ctx, &stack, &view, &tree)?;
    let lifecycle = reached.info.lifecycle.clone();
    // Only a committed key can be provisioned, but a ceremony that never committed runs again on a fresh session.
    let retries_ceremony = lifecycle.is("ceremony/OPERATOR_INITIALIZED")
        || lifecycle.is("ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS");
    if !retries_ceremony && completed_ceremonies(ctx, &bucket)? == 0 {
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
        "withdraw/ACTIVATED" if stack.slots()?.len() > 1 => bail!(
            "Slot {slot}'s guardian serves withdrawals while the stack has two slots. Move its key with the switchover step instead."
        ),
        // It holds the key in memory, which a restart loses until a threshold of key provisioners provision it again.
        held @ ("withdraw/ACTIVATED" | "withdraw/PROVISIONER_INITIALIZED") => {
            if !abandon {
                bail!(
                    "Slot {slot}'s guardian holds the key ({held}). Restarting it loses that copy, and it serves nothing until a threshold of key provisioners provision it again. To do that anyway: new-session {slot} --abandon"
                );
            }
            warn(&format!(
                "Discarding the key slot {slot}'s guardian holds ({held})."
            ));
        }
        // The relay holds what key provisioners have sent it for this session.
        "withdraw/OPERATOR_INITIALIZED" => {
            if !abandon {
                bail!(
                    "Slot {slot}'s guardian waits for key provisioners to provision it. Restarting it drops the shares they have sent, and each sends theirs again. To do that anyway: new-session {slot} --abandon"
                );
            }
            warn(&format!("Abandoning slot {slot}'s provisioning round."));
        }
        fresh @ ("none" | "ceremony/COMPLETED") => warn(&format!(
            "Restarting the enclave ends its session ({fresh})."
        )),
        other => {
            if !abandon {
                bail!(
                    "Slot {slot}'s guardian is {other}, a stage this tool doesn't know, so it can't tell what a restart loses. To restart it anyway: new-session {slot} --abandon"
                );
            }
            warn(&format!("Abandoning slot {slot}'s session ({other})."));
        }
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
    // The prompt can wait any time, so the guardian it was about must still be the one the restart ends.
    let now = slot_info(ctx, &tree, &view)?;
    if now.signing_key.as_deref() != Some(reached.signing_key.as_str())
        || now.lifecycle != lifecycle
    {
        bail!(
            "Slot {slot}'s guardian changed while this step waited for you ({lifecycle} then, {} now). Nothing was restarted: run this step again.",
            now.lifecycle
        );
    }
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
    const OTHER_KEY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    /// A two-slot stack whose slot b reaches a guardian in `lifecycle`, over a bucket holding `ceremonies`.
    fn world(lifecycle: &'static str, ceremonies: u64) -> Fake {
        world_relaying_to(lifecycle, ceremonies, KEY)
    }

    /// The same, with the relay sending key provisioners to the guardian whose signing key is `relayed`.
    fn world_relaying_to(lifecycle: &'static str, ceremonies: u64, relayed: &'static str) -> Fake {
        world_changing(lifecycle, lifecycle, ceremonies, relayed)
    }

    /// The same, with slot b's guardian in `then` once it has been read once, as if it changed while a prompt waited.
    fn world_changing(
        lifecycle: &'static str,
        then: &'static str,
        ceremonies: u64,
        relayed: &'static str,
    ) -> Fake {
        let stack = crate::stack::tests::two_slots();
        let reads = std::cell::Cell::new(0);
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
                ] => {
                    reads.set(reads.get() + 1);
                    let now = if reads.get() > 1 { then } else { lifecycle };
                    Some((
                        true,
                        json!({ "info": info_json(KEY, None, now) }).to_string(),
                    ))
                }
                // The proxy fronts slot a's guardian.
                ["curl", ..] => Some((
                    true,
                    json!({ "signingPubKey": "cc".repeat(32), "committeeEpoch": "1253" })
                        .to_string(),
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
        // The key's first ceremony, which has committed nothing yet, and a later one.
        for ceremonies in [0, 1] {
            let exec = world(
                "ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS",
                ceremonies,
            );
            let error = run(&exec, &["i-0bbb"], false).unwrap_err().to_string();
            assert!(
                error.ends_with("To do that anyway: new-session b --abandon"),
                "{error}"
            );
            assert!(!exec.ran(&["aws", "ssm", "send-command"]));
            run(&exec, &["i-0bbb"], true).unwrap();
            assert!(exec.ran(&["aws", "ssm", "send-command"]));
        }
    }

    #[test]
    fn refuses_without_a_completed_ceremony() {
        let exec = world("none", 0);
        assert_eq!(
            run(&exec, &["i-0bbb"], false).unwrap_err().to_string(),
            "s3://guardian-bucket/ceremony/ holds no completed ceremony, so a fresh session would have no key to be provisioned with."
        );
        // A ceremony that never dealt runs again on a fresh session.
        let exec = world("ceremony/OPERATOR_INITIALIZED", 0);
        run(&exec, &["i-0bbb"], false).unwrap();
        assert!(exec.ran(&["aws", "ssm", "send-command"]));
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
    fn discards_a_key_only_when_asked() {
        // A key held, shares the relay holds, and a stage nothing says the cost of losing.
        for lifecycle in [
            "withdraw/PROVISIONER_INITIALIZED",
            "withdraw/OPERATOR_INITIALIZED",
            "withdraw/UNSPECIFIED",
        ] {
            let exec = world(lifecycle, 1);
            let error = run(&exec, &["i-0bbb"], false).unwrap_err().to_string();
            assert!(
                error.ends_with("new-session b --abandon"),
                "{lifecycle}: {error}"
            );
            assert!(!exec.ran(&["aws", "ssm", "send-command"]));
            run(&exec, &["i-0bbb"], true).unwrap();
            assert!(exec.ran(&["aws", "ssm", "send-command"]));
        }
    }

    /// A one-slot stack whose tunnel reaches a fresh guardian with `KEY`, then with `then` from its second read on, over a
    /// log bucket that holds no completed ceremony, then `after` from its second listing on.
    fn ceremony_world(then: &'static str, after: u64) -> Fake {
        let stack = crate::stack::tests::stack_world(
            json!({
                "hashi-commit": COMMIT,
                "eif-pcr0": "0c".repeat(48),
                "refill-rate-sats-per-sec": "11574",
                "max-bucket-capacity-sats": "1000000000",
            }),
            json!({
                "active_slot": "a",
                "enclave_instance_id": "i-0aaa",
                "standby_instance_id": "",
                "s3_bucket_name": "guardian-bucket",
                "s3_bucket_region": "us-west-2",
                "s3_access_key_id": "test-access-key",
            }),
        );
        let reads = std::cell::Cell::new(0);
        let listings = std::cell::Cell::new(0);
        Fake::new(move |words| {
            let w: Vec<&str> = words.iter().map(String::as_str).collect();
            match w.as_slice() {
                ["pulumi", "-C", _, "stack", "output", "s3_secret_access_key", ..] => {
                    Some((true, "test-secret-key\n".to_owned()))
                }
                ["pulumi", ..] => stack
                    .output(&Cmd::new("pulumi").args(&words[1..]))
                    .ok()
                    .map(|output| (output.success, output.stdout)),
                ["cargo", "build", ..] => Some((
                    true,
                    r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#
                        .to_owned(),
                )),
                [
                    "grpcurl",
                    ..,
                    "sui.hashi.v1alpha.GuardianService/GetGuardianInfo",
                ] => {
                    reads.set(reads.get() + 1);
                    let key = if reads.get() > 1 { then } else { KEY };
                    Some((
                        true,
                        json!({ "info": info_json(key, None, "none") }).to_string(),
                    ))
                }
                ["curl", ..] => Some((true, json!({ "signingPubKey": KEY }).to_string())),
                ["aws", "s3api", "list-objects-v2", ..] => {
                    listings.set(listings.get() + 1);
                    let count = if listings.get() > 1 { after } else { 0 };
                    Some((true, format!("{count}\n")))
                }
                ["/x/hashi-guardian-init", "operator", "ceremony", ..] => Some((true, String::new())),
                _ => None,
            }
        })
    }

    /// Renders slot a and runs the ceremony on it, answering its question yes.
    fn ceremony(exec: &Fake) -> Result<()> {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let roster =
            crate::render::tests::roster_dir(&repo.path().join("roster"), &["alice", "bob"], "v1");
        let mut env = stack_env();
        env.extend([
            ("KP_ROSTER_DIR", roster.as_str()),
            ("KP_THRESHOLD", "2"),
            ("SUI_RPC", "https://fullnode.testnet.sui.io:443"),
            ("HASHI_PACKAGE_ID", "0x1"),
            ("HASHI_OBJECT_ID", "0x2"),
            ("BITCOIN_NETWORK", "signet"),
            ("RETENTION_ENVIRONMENT", "testnet"),
        ]);
        let ask = Scripted::new(&["yes"]);
        let ctx = Ctx::for_test(repo.path(), exec, &env).with_ask(&ask);
        let stack = crate::stack::Stack::load(&ctx).unwrap();
        let view = stack.slot(&ctx, Slot::A).unwrap();
        crate::render::SlotRender::new(&ctx, &stack, &view)
            .unwrap()
            .rendered
            .write(&view.dir)
            .unwrap();
        operator(&ctx, None, OperatorStep::Ceremony)
    }

    #[test]
    fn runs_the_ceremony_only_on_what_it_checked() {
        let ran = |exec: &Fake| exec.ran(&["/x/hashi-guardian-init", "operator", "ceremony"]);
        let exec = ceremony_world(KEY, 0);
        ceremony(&exec).unwrap();
        assert!(ran(&exec));
        // Another guardian's tunnel takes the port while the question waits.
        let exec = ceremony_world(OTHER_KEY, 0);
        assert!(ceremony(&exec).is_err());
        assert!(!ran(&exec));
        // A ceremony completes on the bucket meanwhile.
        let exec = ceremony_world(KEY, 1);
        assert_eq!(
            ceremony(&exec).unwrap_err().to_string(),
            "s3://guardian-bucket already holds a completed key ceremony. A new guardian key needs a new s3-bucket-name."
        );
        assert!(!ran(&exec));
    }

    #[test]
    fn restarts_nothing_that_changed_while_it_asked() {
        let exec = world_changing(
            "ceremony/COMPLETED",
            "withdraw/PROVISIONER_INITIALIZED",
            1,
            KEY,
        );
        let error = run(&exec, &["i-0bbb"], false).unwrap_err().to_string();
        assert!(
            error.starts_with("Slot b's guardian changed while this step waited for you"),
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

    /// A two-slot stack whose slot a guardian is in `before` until its `operator activate` exits with `cli_succeeds`,
    /// and in `after`, with the signing key `after_key`, from then on.
    fn activation_world(
        before: &'static str,
        cli_succeeds: bool,
        after: &'static str,
        after_key: &'static str,
    ) -> Fake {
        let stack = crate::stack::tests::two_slots();
        let activated = std::cell::Cell::new(false);
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
                ] => {
                    let (key, lifecycle) = if activated.get() {
                        (after_key, after)
                    } else {
                        (KEY, before)
                    };
                    Some((
                        true,
                        json!({ "info": info_json(key, None, lifecycle) }).to_string(),
                    ))
                }
                ["/x/hashi-guardian-init", "operator", "activate", ..] => {
                    activated.set(true);
                    Some((cli_succeeds, String::new()))
                }
                _ => None,
            }
        })
    }

    #[test]
    fn activates_despite_a_post_check_the_guardian_contradicts() {
        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(COMMIT)).unwrap();
        let guardian_init = GuardianInit {
            path: "/x/hashi-guardian-init".into(),
        };
        let provisioned = "withdraw/PROVISIONER_INITIALIZED";
        for (before, cli_succeeds, after, after_key, expected) in [
            (provisioned, false, "withdraw/ACTIVATED", KEY, None),
            (
                provisioned,
                true,
                provisioned,
                KEY,
                Some(
                    "Slot a's guardian is withdraw/PROVISIONER_INITIALIZED, not activated. Run this step again once it can activate.",
                ),
            ),
            // A failed activation can't pass on another guardian's word.
            (
                provisioned,
                false,
                "withdraw/ACTIVATED",
                OTHER_KEY,
                Some(
                    "http://127.0.0.1:3000 now reaches a guardian with other keys than the one activation ran on. Check that the tunnel is slot a's.",
                ),
            ),
            (
                "withdraw/OPERATOR_INITIALIZED",
                true,
                "withdraw/ACTIVATED",
                KEY,
                Some(
                    "Slot a's guardian is withdraw/OPERATOR_INITIALIZED, not provisioned and waiting for activation.",
                ),
            ),
            ("withdraw/ACTIVATED", false, "withdraw/ACTIVATED", KEY, None),
        ] {
            let exec = activation_world(before, cli_succeeds, after, after_key);
            let ctx = Ctx::for_test(repo.path(), &exec, &stack_env());
            let stack = crate::stack::Stack::load(&ctx).unwrap();
            let view = stack.slot(&ctx, Slot::A).unwrap();
            let tree = Tree::at(&ctx, COMMIT, "the commit slot a's guardian runs").unwrap();
            let result = activate(&ctx, &tree, &guardian_init, &view);
            assert_eq!(
                result.err().map(|error| error.to_string()).as_deref(),
                expected
            );
            let ran = exec.ran(&["/x/hashi-guardian-init", "operator", "activate"]);
            assert_eq!(ran, before == provisioned, "{before}");
        }
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
