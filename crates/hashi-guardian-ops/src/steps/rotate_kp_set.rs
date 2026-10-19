// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Re-dealing the guardian's key to a new set of key provisioners on a standby: `rotate-kp-set init`, `submit` the
//! signers' submissions, or `wait` for the new set to confirm.

use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::ask::NOTHING_CHANGED;
use crate::ask::confirm;
use crate::commit::Tree;
use crate::exec::Cmd;
use crate::exec::read;
use crate::guardian::Lifecycle;
use crate::guardian::require_reached;
use crate::kp_bucket::REGION;
use crate::kp_bucket::ROTATION_PREFIX;
use crate::kp_bucket::kp_bucket;
use crate::next;
use crate::print_detail;
use crate::print_info;
use crate::print_warning;
use crate::render::require_fresh;
use crate::render::threshold;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::steps::kp_keys::shown;
use crate::steps::rotate::require_monitor_allows;
use crate::steps::slot;

pub enum Action {
    Init,
    Submit(Vec<PathBuf>),
    Wait,
}

impl Action {
    fn name(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Submit(_) => "submit",
            Self::Wait => "wait",
        }
    }
}

/// Runs `operator rotate-kp-set <action>` on the slot's standby with the re-deal's files, which list both rosters.
pub fn rotate_kp_set(ctx: &Ctx, arg: Option<Slot>, action: Action) -> Result<()> {
    let (stack, view) = slot(ctx, arg)?;
    let slot = view.slot;
    if ctx.env.get("NEW_KP_ROSTER_DIR").is_none() {
        bail!(
            "set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in {}, then render, for a KP-set rotation",
            ctx.env.path().display()
        );
    }
    if view.role != Role::Standby {
        bail!(
            "a KP-set rotation re-deals on a standby guardian, and slot {slot}'s is {}",
            match view.role {
                Role::Absent => "not deployed".to_owned(),
                role => role.to_string(),
            }
        );
    }
    let tree = Tree::at(
        ctx,
        &view.commit,
        &format!("the commit slot {slot}'s guardian runs"),
    )?;
    let guardian_init = tree.guardian_init(ctx)?;
    require_fresh(ctx, &stack, &view)?;
    let reached = require_reached(ctx, &stack, &view, &tree)?;
    require_monitor_allows(ctx, &stack, &[&view])?;
    let lifecycle = &reached.info.lifecycle;
    if lifecycle.is("ceremony/COMPLETED") {
        bail!(
            "slot {slot}'s guardian has completed the re-deal; switch your environment file to the new set, then new-session --slot {slot}"
        );
    }
    let awaiting = lifecycle.is("ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS");
    match &action {
        Action::Init | Action::Submit(_) if awaiting => bail!(
            "slot {slot}'s guardian has the signers' files and waits for the new set's confirmations: rotate-kp-set wait --slot {slot}"
        ),
        Action::Submit(_) if !lifecycle.is("ceremony/OPERATOR_INITIALIZED") => bail!(
            "slot {slot}'s guardian is {lifecycle}, not initialized for a re-deal; next: {}",
            re_deal_step(lifecycle, slot)
        ),
        Action::Wait if !awaiting => bail!(
            "slot {slot}'s guardian is {lifecycle}, waiting for no confirmations; next: {}",
            re_deal_step(lifecycle, slot)
        ),
        _ => {}
    }
    let mut submissions = Vec::new();
    match &action {
        Action::Submit(files) if files.is_empty() => {
            if !uploads_submissions(&tree) {
                bail!(
                    "slot {slot}'s build doesn't upload the signers' submissions to the KP bucket; name the files they sent: rotate-kp-set submit --slot {slot} --submission <file>, once per file"
                );
            }
            submissions = uploaded_submissions(ctx, &view, &reached.signing_key[..16])?;
        }
        Action::Submit(files) => {
            for file in files {
                if !file.is_file() {
                    bail!("no submission file at {}", file.display());
                }
                // The CLI runs from the re-deal's directory, so it gets every path absolute.
                submissions.push(
                    std::fs::canonicalize(file)
                        .with_context(|| format!("could not resolve {}", file.display()))?,
                );
            }
        }
        Action::Init => {
            if !lifecycle.is("none") && !lifecycle.is("ceremony/OPERATOR_INITIALIZED") {
                bail!(
                    "slot {slot}'s guardian is {lifecycle}; a KP-set rotation needs a fresh guardian: start one with new-session --slot {slot}"
                );
            }
            print_warning(&format!(
                "This makes slot {slot}'s guardian a ceremony guardian for good: it never serves withdrawals. Once the new key provisioners have all confirmed, start a fresh session on it with new-session --slot {slot}."
            ));
            confirm(
                ctx.ask,
                &format!("Re-deal the key on slot {slot}'s guardian?"),
                &NOTHING_CHANGED,
            )?;
            // The question can wait any time, while the files, the tunnel, the guardian or the monitor change.
            require_fresh(ctx, &stack, &view)?;
            let now = require_reached(ctx, &stack, &view, &tree)?;
            if now.signing_key != reached.signing_key || now.info.lifecycle != *lifecycle {
                bail!(
                    "slot {slot}'s guardian changed while this step waited for you; nothing was changed: run this step again"
                );
            }
            require_monitor_allows(ctx, &stack, &[&view])?;
        }
        Action::Wait => {}
    }
    next(&match action {
        Action::Init if uploads_submissions(&tree) => format!(
            "once the signers have run key-provisioner rotate-kp-set, rotate-kp-set submit --slot {slot}, which collects what they uploaded to the KP bucket"
        ),
        Action::Init => {
            format!(
                "once the signers have sent their files, rotate-kp-set submit --slot {slot} --submission <file>, once per file"
            )
        }
        // The re-deal leaves the slot's own files as they are, but a render with NEW_KP_* set would point at the
        // signers' publication, whose old roster the new set can't provision with.
        Action::Submit(_) | Action::Wait => format!(
            "once this logs `ceremony proposal published`, publish --slot {slot} in another terminal, and have every key provisioner of the new set confirm into a new --encrypted-shares-path, so an earlier ceremony's file stays. Once this reports the rotation complete, set KP_ROSTER_DIR and KP_THRESHOLD to the new set's and remove NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD, without publishing again; then new-session --slot {slot}"
        ),
    });
    let mut cmd = guardian_init
        .cmd()
        .args([
            "operator",
            "rotate-kp-set",
            action.name(),
            "--config",
            "operator.yaml",
        ])
        // The configuration lists certificates relative to its own directory.
        .cwd(view.dir.join("rotate-kp-set"));
    for submission in &submissions {
        cmd = cmd.arg("--submission").arg(submission);
    }
    Err(anyhow::Error::new(ctx.exec.exec(&cmd)).context("could not run hashi-guardian-init"))
}

/// The step a re-deal's standby is ready for, by its lifecycle.
pub(crate) fn re_deal_step(lifecycle: &Lifecycle, slot: Slot) -> String {
    match lifecycle.to_string().as_str() {
        "none" => format!("rotate-kp-set init --slot {slot}"),
        "ceremony/OPERATOR_INITIALIZED" => format!("rotate-kp-set submit --slot {slot}"),
        "ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS" => {
            format!("rotate-kp-set wait --slot {slot}")
        }
        "ceremony/COMPLETED" => {
            format!("switch your environment file to the new set, then new-session --slot {slot}")
        }
        _ => format!("new-session --slot {slot}, for a fresh guardian to re-deal on"),
    }
}

/// Whether the build's key provisioner command uploads its submission to the KP bucket, which it does from hashi #1464
/// on.
fn uploads_submissions(tree: &Tree) -> bool {
    std::fs::read_to_string(
        tree.dir
            .join("crates/hashi-guardian-init/src/submission.rs"),
    )
    .is_ok_and(|source| source.contains(&format!("\"{ROTATION_PREFIX}\"")))
}

/// Downloads the submissions the signers uploaded for `session`, in place of an earlier download, and stops unless
/// they reach the dealt set's threshold.
fn uploaded_submissions(ctx: &Ctx, view: &SlotView, session: &str) -> Result<Vec<PathBuf>> {
    let source = format!("s3://{}/{ROTATION_PREFIX}/{session}/", kp_bucket(ctx)?);
    let dir = view
        .dir
        .join("rotate-kp-set")
        .join("submissions")
        .join(session);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    print_info("Collecting the signers' submissions");
    read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["s3", "cp", "--recursive", "--only-show-errors"])
            .args(["--region", REGION])
            .arg(&source)
            .arg(format!("{}/", dir.display())),
    )
    .with_context(|| format!("could not download the submissions in {source}"))?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "rotation")
        {
            files.push(std::fs::canonicalize(&path)?);
        }
    }
    files.sort();
    let signers: Vec<String> = files
        .iter()
        .filter_map(|file| file.file_stem())
        .map(|stem| shown(&stem.to_string_lossy()))
        .collect();
    let threshold = threshold(ctx, "KP_THRESHOLD")?;
    if signers.len() < threshold as usize {
        bail!(
            "found {} of the {threshold} submissions the current set's threshold needs in {source}{}; run this again once more key provisioners have run key-provisioner rotate-kp-set",
            signers.len(),
            if signers.is_empty() {
                String::new()
            } else {
                format!(", from {}", signers.join(", "))
            }
        );
    }
    print_info(&format!("Submissions in {source}, by signer:"));
    for signer in &signers {
        print_detail(&format!("  {signer}"));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::tests::roster_dir;
    use crate::world;
    use crate::world::Run;

    /// Puts slot b's guardian in `lifecycle`.
    fn standby_at(run: &Run, lifecycle: &str) {
        let standby = run.state.borrow().deployed["b"].clone();
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .session
            .lifecycle = lifecycle.to_owned();
    }

    /// Slot b armed next to slot a, with a new roster to re-deal to.
    fn armed_for_a_re_deal() -> Run {
        let mut run = Run::new();
        let new = roster_dir(
            &run.repo.path().join("new-roster"),
            &["alice", "bob", "carol"],
            "v1",
        );
        run.env.push(("NEW_KP_ROSTER_DIR".to_owned(), new));
        run.env
            .push(("NEW_KP_THRESHOLD".to_owned(), "2".to_owned()));
        run.step(&["yes"], |ctx| crate::steps::rotate::arm(ctx, Slot::B))
            .0
            .unwrap();
        run.step(&["yes"], crate::steps::rotate::proxy_update)
            .0
            .unwrap();
        run.render(Slot::B);
        run
    }

    #[test]
    fn hands_init_to_the_cli_once_confirmed() {
        let run = armed_for_a_re_deal();
        let (result, prompts) = run.step(&["no"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "not confirmed; nothing was changed"
        );
        assert_eq!(prompts, ["Re-deal the key on slot b's guardian? [y/N] "]);
        // The exec is what fails in a test, after the confirmation.
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "could not run hashi-guardian-init"
        );
        let log = run.exec.log.borrow();
        assert_eq!(
            log.last().unwrap()[..],
            [
                "/x/hashi-guardian-init",
                "operator",
                "rotate-kp-set",
                "init",
                "--config",
                "operator.yaml"
            ]
        );
        // There, operator.yaml is the one listing both rosters.
        assert_eq!(
            run.exec.exec_dirs.borrow().last().unwrap().as_deref(),
            Some(
                run.repo
                    .path()
                    .join(".hashi/guardian/testnet/b/rotate-kp-set")
                    .as_path()
            )
        );
    }

    /// An operator who answers yes once something has changed meanwhile.
    struct Meanwhile<'a>(&'a Run, fn(&Run));

    impl crate::ask::Ask for Meanwhile<'_> {
        fn interactive(&self) -> bool {
            true
        }

        fn line(&self, _prompt: &str) -> std::io::Result<Option<String>> {
            (self.1)(self.0);
            Ok(Some("yes".to_owned()))
        }
    }

    #[test]
    fn inits_only_the_guardian_it_asked_about() {
        let mut run = armed_for_a_re_deal();
        world::monitor(&mut run.env);
        run.state.borrow_mut().monitor_builds =
            Some(vec![(world::COMMIT.to_owned(), "0c".repeat(48))]);
        let ran = run.exec.log.borrow().len();
        let init = |meanwhile: fn(&Run)| {
            run.step_asking(&Meanwhile(&run, meanwhile), |ctx| {
                rotate_kp_set(ctx, Some(Slot::B), Action::Init)
            })
            .unwrap_err()
            .to_string()
        };
        // Another run initializes the standby for a re-deal.
        let error = init(|run| standby_at(run, "ceremony/OPERATOR_INITIALIZED"));
        assert!(
            error.starts_with("slot b's guardian changed while this step waited for you;"),
            "{error}"
        );
        standby_at(&run, "none");
        let error = init(|run| run.state.borrow_mut().monitor_builds = Some(Vec::new()));
        assert!(
            error.starts_with(&format!(
                "hashi-monitor does not allowlist {} with PCR0",
                world::COMMIT
            )),
            "{error}"
        );
        assert!(
            !run.exec.log.borrow()[ran..]
                .iter()
                .any(|words| words[0] == "/x/hashi-guardian-init")
        );
    }

    #[test]
    fn re_deals_only_once_hashi_monitor_allowlists_the_build() {
        let mut run = armed_for_a_re_deal();
        world::monitor(&mut run.env);
        run.state.borrow_mut().monitor_builds = Some(Vec::new());
        let ran = run.exec.log.borrow().len();
        let (result, prompts) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert!(result.unwrap_err().to_string().starts_with(&format!(
            "hashi-monitor does not allowlist {} with PCR0",
            world::COMMIT
        )));
        assert!(prompts.is_empty());
        assert!(
            !run.exec.log.borrow()[ran..]
                .iter()
                .any(|words| words[0] == "/x/hashi-guardian-init")
        );

        run.state.borrow_mut().monitor_builds =
            Some(vec![(world::COMMIT.to_owned(), "0c".repeat(48))]);
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "could not run hashi-guardian-init"
        );
        assert_eq!(
            run.exec.log.borrow().last().unwrap()[..4],
            [
                "/x/hashi-guardian-init",
                "operator",
                "rotate-kp-set",
                "init"
            ]
        );
    }

    #[test]
    fn passes_the_signers_files_absolute() {
        let run = armed_for_a_re_deal();
        standby_at(&run, "ceremony/OPERATOR_INITIALIZED");
        let signed = run.repo.path().join("alice.rotation");
        std::fs::write(&signed, "signed").unwrap();
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![signed.clone()]))
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "could not run hashi-guardian-init"
        );
        let last = run.exec.log.borrow().last().unwrap().clone();
        assert_eq!(last[6], "--submission");
        assert!(std::path::Path::new(&last[7]).is_absolute());
    }

    #[test]
    fn submits_what_the_signers_uploaded_for_the_session() {
        let run = armed_for_a_re_deal();
        standby_at(&run, "ceremony/OPERATOR_INITIALIZED");
        // A build before the upload has signers send their files instead.
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![]))
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .ends_with("name the files they sent: rotate-kp-set submit --slot b --submission <file>, once per file")
        );
        let source_dir = run
            .repo
            .path()
            .join(".hashi/guardian-init")
            .join(world::COMMIT)
            .join("crates/hashi-guardian-init/src");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(
            source_dir.join("submission.rs"),
            "pub const BUCKET_PREFIX: &str = \"_rotate-kp-set\";\n",
        )
        .unwrap();
        let session = {
            let state = run.state.borrow();
            state.hosts[&state.deployed["b"]].session.key[..16].to_owned()
        };
        let source = format!("s3://kp-bucket/_rotate-kp-set/{session}/");
        let upload = |key: String| {
            run.state
                .borrow_mut()
                .kp_uploads
                .insert(key, b"signed".to_vec());
        };
        upload(format!("_rotate-kp-set/{session}/AAAA.rotation"));
        upload("_rotate-kp-set/ffffffffffffffff/CCCC.rotation".to_owned());
        // Only a file counts, whatever its name.
        upload(format!("_rotate-kp-set/{session}/DDDD.rotation/inside"));
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![]))
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "found 1 of the 2 submissions the current set's threshold needs in {source}, from AAAA; run this again once more key provisioners have run key-provisioner rotate-kp-set"
            )
        );
        assert!(
            !run.exec
                .log
                .borrow()
                .iter()
                .any(|words| words[0] == "/x/hashi-guardian-init")
        );

        upload(format!("_rotate-kp-set/{session}/BBBB.rotation"));
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![]))
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "could not run hashi-guardian-init"
        );
        let last = run.exec.log.borrow().last().unwrap().clone();
        assert_eq!(
            last[..6],
            [
                "/x/hashi-guardian-init",
                "operator",
                "rotate-kp-set",
                "submit",
                "--config",
                "operator.yaml"
            ]
        );
        let files: Vec<&str> = last[6..]
            .chunks(2)
            .map(|pair| {
                assert_eq!(pair[0], "--submission");
                pair[1].as_str()
            })
            .collect();
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with(&format!(
            "rotate-kp-set/submissions/{session}/AAAA.rotation"
        )));
        assert!(files[1].ends_with(&format!(
            "rotate-kp-set/submissions/{session}/BBBB.rotation"
        )));
    }

    #[test]
    fn refuses_a_guardian_that_cannot_re_deal() {
        let run = armed_for_a_re_deal();
        let (result, _) = run.step(&[], |ctx| rotate_kp_set(ctx, Some(Slot::A), Action::Wait));
        assert_eq!(
            result.unwrap_err().to_string(),
            "a KP-set rotation re-deals on a standby guardian, and slot a's is active"
        );
        standby_at(&run, "withdraw/OPERATOR_INITIALIZED");
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "slot b's guardian is withdraw/OPERATOR_INITIALIZED; a KP-set rotation needs a fresh guardian: start one with new-session --slot b"
        );
    }

    #[test]
    fn names_the_step_the_re_deal_has_reached() {
        let run = armed_for_a_re_deal();
        let step = |action| {
            run.step(&["yes"], |ctx| rotate_kp_set(ctx, Some(Slot::B), action))
                .0
                .unwrap_err()
                .to_string()
        };
        let signed = || Action::Submit(vec![run.repo.path().join("README")]);
        assert!(step(Action::Wait).ends_with("next: rotate-kp-set init --slot b"));
        standby_at(&run, "ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS");
        for action in [Action::Init, signed()] {
            assert!(
                step(action).ends_with(
                    "waits for the new set's confirmations: rotate-kp-set wait --slot b"
                )
            );
        }
        // Publishing the signers' configuration again would ask them to sign what the guardian already has.
        assert!(
            run.step(&[], |ctx| crate::steps::configs::publish(
                ctx,
                Some(Slot::B),
                true
            ))
            .0
            .unwrap_err()
            .to_string()
            .ends_with(
                "goes out before rotate-kp-set submit --slot b; next: rotate-kp-set wait --slot b"
            )
        );
        standby_at(&run, "ceremony/COMPLETED");
        assert!(step(Action::Wait).ends_with("then new-session --slot b"));
        // Done, the new set's configuration waits for the switch of the environment file.
        assert!(
            run.step(&[], |ctx| crate::steps::configs::publish(
                ctx,
                Some(Slot::B),
                false
            ))
            .0
            .unwrap_err()
            .to_string()
            .ends_with(
                "next: switch your environment file to the new set, then new-session --slot b"
            )
        );
        // The active slot keeps the roster that holds the key.
        for refused in [
            run.step(&[], |ctx| crate::steps::configs::render(ctx, Some(Slot::A)))
                .0,
            run.step(&[], |ctx| {
                crate::steps::configs::publish(ctx, Some(Slot::A), false)
            })
            .0,
        ] {
            let error = refused.unwrap_err().to_string();
            assert!(
                error.starts_with("testnet.env sets NEW_KP_ROSTER_DIR for a KP-set rotation"),
                "{error}"
            );
        }
        // The new set confirms only into a proposal the guardian has published.
        standby_at(&run, "ceremony/OPERATOR_INITIALIZED");
        assert!(
            run.step(&[], |ctx| crate::steps::configs::publish(
                ctx,
                Some(Slot::B),
                false
            ))
            .0
            .unwrap_err()
            .to_string()
            .contains(
                "the new set's configuration goes out once rotate-kp-set submit --slot b logs"
            )
        );
    }
}
