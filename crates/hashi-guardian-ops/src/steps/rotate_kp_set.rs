// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Re-dealing the guardian's key to a new set of key provisioners on a standby: `rotate-kp-set init`, `submit` the
//! signers' submissions, or `wait` for the new set to confirm.

use std::io::Write;
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
use crate::guardian::require_reached;
use crate::kp_bucket::KpBucket;
use crate::kp_bucket::REGION;
use crate::kp_bucket::ROTATION_PREFIX;
use crate::next;
use crate::render::require_fresh;
use crate::render::threshold;
use crate::say;
use crate::stack::Role;
use crate::stack::Slot;
use crate::stack::SlotView;
use crate::steps::rotate::require_monitor_allows;
use crate::steps::slot;
use crate::warn;

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
    let (stack, view) = slot(ctx, arg, "rotate-kp-set")?;
    let slot = view.slot;
    if ctx.env.get("NEW_KP_ROSTER_DIR").is_none() {
        bail!(
            "Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in {}, then render, for a KP-set rotation.",
            ctx.env.path().display()
        );
    }
    if view.role != Role::Standby {
        bail!(
            "A KP-set rotation re-deals on a standby guardian, and slot {slot}'s is {}.",
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
    require_monitor_allows(&stack, &view)?;
    let mut submissions = Vec::new();
    match &action {
        Action::Submit(files) if files.is_empty() => {
            submissions = uploaded_submissions(ctx, &view, &reached.signing_key[..16])?;
        }
        Action::Submit(files) => {
            for file in files {
                if !file.is_file() {
                    bail!("No submission file at {}.", file.display());
                }
                // The CLI runs from the re-deal's directory, so it gets every path absolute.
                submissions.push(
                    std::fs::canonicalize(file)
                        .with_context(|| format!("Could not resolve {}.", file.display()))?,
                );
            }
        }
        Action::Init => {
            let lifecycle = &reached.info.lifecycle;
            if !lifecycle.is("none") && !lifecycle.is("ceremony/OPERATOR_INITIALIZED") {
                bail!(
                    "Slot {slot}'s guardian is {lifecycle}. A KP-set rotation needs a fresh guardian: start one with new-session {slot}."
                );
            }
            warn(&format!(
                "This makes slot {slot}'s guardian a ceremony guardian for good: it never serves withdrawals. Once the new key provisioners have all confirmed, start a fresh session on it with new-session {slot}."
            ));
            confirm(
                ctx.ask,
                &format!("Re-deal the key on slot {slot}'s guardian?"),
                &NOTHING_CHANGED,
            )?;
        }
        Action::Wait => {}
    }
    next(&match action {
        Action::Init => format!(
            "once the signers have run key-provisioner rotate-kp-set, rotate-kp-set {slot} submit, which collects what they uploaded to the KP bucket"
        ),
        // The re-deal leaves the slot's own files as they are, but a render with NEW_KP_* set would point at the
        // signers' publication, whose old roster the new set can't provision with.
        Action::Submit(_) | Action::Wait => format!(
            "once this logs `ceremony proposal published`, publish {slot} in another terminal, and have every key provisioner of the new set confirm into a new --encrypted-shares-path, so an earlier ceremony's file stays. Once this reports the rotation complete, set KP_ROSTER_DIR and KP_THRESHOLD to the new set's and remove NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD, without publishing again; then new-session {slot}"
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
    std::io::stdout().flush()?;
    Err(anyhow::Error::new(ctx.exec.exec(&cmd)).context("Could not run hashi-guardian-init."))
}

/// Downloads the submissions the signers uploaded for `session`, in place of an earlier download, and stops unless
/// they reach the dealt set's threshold.
fn uploaded_submissions(ctx: &Ctx, view: &SlotView, session: &str) -> Result<Vec<PathBuf>> {
    let kp = KpBucket::from_env(ctx)?;
    let source = format!("s3://{}/{ROTATION_PREFIX}/{session}/", kp.bucket);
    let dir = view
        .dir
        .join("rotate-kp-set")
        .join("submissions")
        .join(session);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    say("Collect the signers' submissions");
    read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["s3", "cp", "--recursive", "--only-show-errors"])
            .args(["--region", REGION])
            .arg(&source)
            .arg(format!("{}/", dir.display())),
    )
    .with_context(|| format!("Could not download the submissions in {source}."))?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path
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
        .map(|stem| stem.to_string_lossy().into_owned())
        .collect();
    let threshold = threshold(ctx, "KP_THRESHOLD")?;
    if signers.len() < threshold as usize {
        bail!(
            "Found {} of the {threshold} submissions the current set's threshold needs in {source}{}. Run this again once more key provisioners have run key-provisioner rotate-kp-set.",
            signers.len(),
            if signers.is_empty() {
                String::new()
            } else {
                format!(", from {}", signers.join(", "))
            }
        );
    }
    println!("Submissions in {source}, by signer:");
    for signer in &signers {
        println!("  {signer}");
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::ask::scripted::Scripted;
    use crate::exec::fake::Fake;
    use crate::render::SlotRender;
    use crate::render::tests::roster_dir;
    use crate::stack::Stack;
    use crate::world;
    use crate::world::State;

    struct Run {
        repo: tempfile::TempDir,
        state: Rc<RefCell<State>>,
        exec: Fake,
        env: Vec<(String, String)>,
    }

    impl Run {
        /// Slot b armed next to slot a, with a new roster to re-deal to.
        fn new() -> Self {
            let repo = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(world::COMMIT))
                .unwrap();
            let state = world::serving_world();
            let exec = world::exec(&state);
            let mut env = world::env(repo.path());
            let new = roster_dir(
                &repo.path().join("new-roster"),
                &["alice", "bob", "carol"],
                "v1",
            );
            env.push(("NEW_KP_ROSTER_DIR".to_owned(), new));
            env.push(("NEW_KP_THRESHOLD".to_owned(), "2".to_owned()));
            let run = Self {
                repo,
                state,
                exec,
                env,
            };
            run.step(&["yes"], |ctx| crate::steps::rotate::arm(ctx, Slot::B))
                .0
                .unwrap();
            run.step(&["yes"], crate::steps::rotate::proxy_update)
                .0
                .unwrap();
            run.render(Slot::B);
            run
        }

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
    }

    #[test]
    fn hands_init_to_the_cli_once_confirmed() {
        let run = Run::new();
        let (result, prompts) = run.step(&["no"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "Not confirmed; nothing was changed."
        );
        assert_eq!(
            prompts,
            ["Re-deal the key on slot b's guardian? Type y/yes to continue: "]
        );
        // The exec is what fails in a test, after the confirmation.
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not run hashi-guardian-init."
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

    #[test]
    fn re_deals_only_once_hashi_monitor_allowlists_the_build() {
        let run = Run::new();
        let dir = run.repo.path().join("pulumi/services/hashi-monitor");
        std::fs::create_dir_all(&dir).unwrap();
        let monitor = dir.join("Pulumi.testnet.yaml");
        std::fs::write(&monitor, "prev_builds: []\n").unwrap();
        let ran = run.exec.log.borrow().len();
        let (result, prompts) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert!(result.unwrap_err().to_string().starts_with(&format!(
            "hashi-monitor does not allowlist {}. Add it",
            world::COMMIT
        )));
        assert!(prompts.is_empty());
        assert!(
            !run.exec.log.borrow()[ran..]
                .iter()
                .any(|words| words[0] == "/x/hashi-guardian-init")
        );

        std::fs::write(
            &monitor,
            format!(
                "current_build:\n  git_revision: \"{}\"\n  pcr0: \"{}\"\n",
                world::COMMIT,
                "0c".repeat(48)
            ),
        )
        .unwrap();
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not run hashi-guardian-init."
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
        let run = Run::new();
        let signed = run.repo.path().join("alice.rotation");
        std::fs::write(&signed, "signed").unwrap();
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![signed.clone()]))
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "Could not run hashi-guardian-init."
        );
        let last = run.exec.log.borrow().last().unwrap().clone();
        assert_eq!(last[6], "--submission");
        assert!(std::path::Path::new(&last[7]).is_absolute());
    }

    #[test]
    fn submits_what_the_signers_uploaded_for_the_session() {
        let run = Run::new();
        let session = {
            let state = run.state.borrow();
            state.hosts[&state.deployed["b"]].session.key[..16].to_owned()
        };
        let source = format!("s3://mysten-hashi-kp-pubkeys-testnet/_rotate-kp-set/{session}/");
        let upload = |key: String| {
            run.state
                .borrow_mut()
                .kp_uploads
                .insert(key, b"signed".to_vec());
        };
        upload(format!("_rotate-kp-set/{session}/AAAA.rotation"));
        upload("_rotate-kp-set/ffffffffffffffff/CCCC.rotation".to_owned());
        let (result, _) = run.step(&[], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Submit(vec![]))
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "Found 1 of the 2 submissions the current set's threshold needs in {source}, from AAAA. Run this again once more key provisioners have run key-provisioner rotate-kp-set."
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
            "Could not run hashi-guardian-init."
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
        let run = Run::new();
        let (result, _) = run.step(&[], |ctx| rotate_kp_set(ctx, Some(Slot::A), Action::Wait));
        assert_eq!(
            result.unwrap_err().to_string(),
            "A KP-set rotation re-deals on a standby guardian, and slot a's is active."
        );
        let standby = run.state.borrow().deployed["b"].clone();
        run.state
            .borrow_mut()
            .hosts
            .get_mut(&standby)
            .unwrap()
            .session
            .lifecycle = "withdraw/OPERATOR_INITIALIZED".to_owned();
        let (result, _) = run.step(&["yes"], |ctx| {
            rotate_kp_set(ctx, Some(Slot::B), Action::Init)
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "Slot b's guardian is withdraw/OPERATOR_INITIALIZED. A KP-set rotation needs a fresh guardian: start one with new-session b."
        );
    }
}
