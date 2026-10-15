// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian's own commit. Everything that must match the guardian (its CLI, its protos, the key provisioners'
//! scripts) comes from the tree at that commit, never from the checkout this tool runs from.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;

pub struct Tree {
    pub commit: String,
    pub dir: PathBuf,
}

impl Tree {
    /// The tree at `commit`, extracted once into `.hashi/guardian-init/<commit>/`. `whose` names what runs the
    /// commit, for the message when this checkout doesn't have it.
    pub fn at(ctx: &Ctx, commit: &str, whose: &str) -> Result<Self> {
        let root = ctx.repo.join(".hashi/guardian-init");
        let dir = root.join(commit);
        if !dir.is_dir() {
            let has_commit = ctx
                .exec
                .output(&git(&ctx.repo).args(["cat-file", "-e", &format!("{commit}^{{commit}}")]))
                .with_context(|| format!("Could not run git in {}.", ctx.repo.display()))?
                .success;
            if !has_commit {
                bail!("This checkout does not have {commit}, {whose}. Fetch it first.");
            }
            extract(ctx, commit, &root, &dir)
                .with_context(|| format!("Could not extract {commit} into {}.", dir.display()))?;
        }
        Ok(Self {
            commit: commit.to_owned(),
            dir,
        })
    }

    /// The protos the guardian at this commit speaks, for grpcurl's `-import-path`.
    pub fn protos(&self) -> PathBuf {
        self.dir.join("crates/hashi-types/proto")
    }

    /// Builds `hashi-guardian-init` from this tree with its own toolchain and lock file. The first build of a commit
    /// takes minutes; later ones only confirm it is current.
    pub fn guardian_init(&self, ctx: &Ctx) -> Result<GuardianInit> {
        let cargo = |args: &[&str]| {
            build_overrides()
                .into_iter()
                .fold(Cmd::new("cargo").args(args).cwd(&self.dir), Cmd::env_remove)
        };
        if let Some(channel) = toolchain_channel(&self.dir)? {
            let version = read(ctx.exec, &cargo(&["--version"]))?;
            if !uses_channel(&version, &channel) {
                bail!(
                    "cargo in {} is {}, not toolchain {channel}, which {} pins.",
                    self.dir.display(),
                    version.trim(),
                    self.commit
                );
            }
        }
        let target = self.dir.join("target");
        let target = target.to_str().context("The tree's path is not UTF-8.")?;
        let messages = read(
            ctx.exec,
            &cargo(&[
                "build",
                "--release",
                "--locked",
                "-p",
                "hashi-guardian-init",
                "--message-format=json-render-diagnostics",
                "--target-dir",
                target,
            ]),
        )
        .with_context(|| format!("Could not build hashi-guardian-init at {}.", self.commit))?;
        Ok(GuardianInit {
            path: executable(&messages)?,
        })
    }
}

/// `hashi-guardian-init`, built from the guardian's commit.
pub struct GuardianInit {
    pub path: PathBuf,
}

impl GuardianInit {
    pub fn cmd(&self) -> Cmd {
        Cmd::new(&self.path)
    }

    /// Whether this build has `tools <name>`; older builds lack some.
    pub fn has_tool(&self, ctx: &Ctx, name: &str) -> Result<bool> {
        let help = read(ctx.exec, &self.cmd().args(["tools", "--help"]))
            .context("Could not run the guardian's tools.")?;
        Ok(help.contains(name))
    }
}

/// Environment variables that would build with another toolchain or configuration. A parent `cargo run` sets
/// `RUSTUP_TOOLCHAIN`, which outranks the tree's `rust-toolchain.toml`.
fn is_build_override(name: &str) -> bool {
    matches!(
        name,
        "RUSTUP_TOOLCHAIN" | "CARGO" | "CARGO_TARGET_DIR" | "CARGO_ENCODED_RUSTFLAGS" | "RUSTFLAGS"
    ) || name.starts_with("CARGO_BUILD_")
        || name.starts_with("RUSTC")
}

fn build_overrides() -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.to_str().is_some_and(is_build_override))
        .collect()
}

/// The channel the tree's `rust-toolchain.toml` pins, if it has one.
fn toolchain_channel(dir: &Path) -> Result<Option<String>> {
    let path = dir.join("rust-toolchain.toml");
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    let channel = text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "channel").then(|| value.trim().trim_matches('"').to_owned())
    });
    channel
        .map(Some)
        .with_context(|| format!("{} names no channel.", path.display()))
}

/// Whether `cargo --version` output is the pinned channel. Only a version number can be checked this way.
fn uses_channel(version: &str, channel: &str) -> bool {
    if !channel.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return true;
    }
    version
        .strip_prefix("cargo ")
        .and_then(|rest| rest.strip_prefix(channel))
        .is_some_and(|rest| rest.starts_with(['.', ' ', '-']))
}

/// The path of the `hashi-guardian-init` binary in cargo's JSON messages.
fn executable(messages: &str) -> Result<PathBuf> {
    #[derive(serde::Deserialize)]
    struct Message {
        reason: String,
        target: Option<Target>,
        executable: Option<PathBuf>,
    }
    #[derive(serde::Deserialize)]
    struct Target {
        name: String,
    }
    messages
        .lines()
        .filter_map(|line| serde_json::from_str::<Message>(line).ok())
        .filter(|message| message.reason == "compiler-artifact")
        .filter(|message| {
            message
                .target
                .as_ref()
                .is_some_and(|target| target.name == "hashi-guardian-init")
        })
        .find_map(|message| message.executable)
        .context("cargo built no hashi-guardian-init binary.")
}

/// Extracts beside `dir` and renames into place, so an interrupted extraction never looks complete. Each process
/// extracts into its own directory, since two steps can reach a new commit at once.
fn extract(ctx: &Ctx, commit: &str, root: &Path, dir: &Path) -> Result<()> {
    let partial = root.join(format!(".{commit}.partial-{}", std::process::id()));
    if partial.exists() {
        std::fs::remove_dir_all(&partial)?;
    }
    let tree = partial.join("tree");
    std::fs::create_dir_all(&tree)?;
    let archive = partial.join("tree.tar");
    read(
        ctx.exec,
        &git(&ctx.repo)
            .args(["archive", "--format=tar", "-o"])
            .arg(&archive)
            .arg(commit),
    )?;
    read(
        ctx.exec,
        &Cmd::new("tar")
            .arg("-x")
            .arg("-f")
            .arg(&archive)
            .arg("-C")
            .arg(&tree),
    )?;
    let renamed = std::fs::rename(&tree, dir);
    std::fs::remove_dir_all(&partial)?;
    match renamed {
        // Another step's extraction finished first.
        Err(_) if dir.is_dir() => Ok(()),
        renamed => Ok(renamed?),
    }
}

fn git(repo: &Path) -> Cmd {
    Cmd::new("git").arg("-C").arg(repo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::fake::Fake;

    #[test]
    fn refuses_a_commit_the_checkout_lacks() {
        let repo = tempfile::tempdir().unwrap();
        let exec = Fake::new(|words| (words[3] == "cat-file").then(|| (false, String::new())));
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let commit = "ab".repeat(20);
        let error = Tree::at(&ctx, &commit, "the commit slot b's guardian runs")
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "This checkout does not have {commit}, the commit slot b's guardian runs. Fetch it first."
            )
        );
    }

    #[test]
    fn reuses_an_extracted_tree() {
        let repo = tempfile::tempdir().unwrap();
        let commit = "cd".repeat(20);
        std::fs::create_dir_all(repo.path().join(".hashi/guardian-init").join(&commit)).unwrap();
        let exec = Fake::new(|_| None);
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let tree = Tree::at(&ctx, &commit, "").unwrap();
        assert_eq!(
            tree.protos(),
            repo.path()
                .join(".hashi/guardian-init")
                .join(&commit)
                .join("crates/hashi-types/proto")
        );
        assert!(exec.log.borrow().is_empty());
    }

    #[test]
    fn extracts_the_real_tree() {
        // Archives this checkout's HEAD for real, so the extraction is checked against git and tar themselves.
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let head = read(
            &crate::exec::System,
            &git(&repo).args(["rev-parse", "HEAD"]),
        )
        .unwrap()
        .trim()
        .to_owned();
        let scratch = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(&repo, &crate::exec::System, &[]);
        let root = scratch.path().join("guardian-init");
        let dir = root.join(&head);
        let proto = dir.join("crates/hashi-types/proto/sui/hashi/v1alpha/guardian_service.proto");
        extract(&ctx, &head, &root, &dir).unwrap();
        assert!(proto.is_file());
        // A step that finishes second keeps the first one's tree.
        extract(&ctx, &head, &root, &dir).unwrap();
        assert!(proto.is_file());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    }

    #[test]
    fn builds_with_the_trees_own_toolchain() {
        for name in [
            "RUSTUP_TOOLCHAIN",
            "CARGO",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET",
            "RUSTC_WRAPPER",
            "RUSTFLAGS",
        ] {
            assert!(is_build_override(name), "{name}");
        }
        for name in ["CARGO_HOME", "RUSTUP_HOME", "PATH", "HOME"] {
            assert!(!is_build_override(name), "{name}");
        }
        assert!(uses_channel(
            "cargo 1.96.0 (e7f5a0a2b 2026-08-25)\n",
            "1.96"
        ));
        assert!(!uses_channel(
            "cargo 1.95.0 (1e2a8f2c4 2026-07-14)\n",
            "1.96"
        ));
        assert!(!uses_channel("cargo 1.960.0\n", "1.96"));
        assert!(uses_channel("cargo 1.97.0-nightly\n", "nightly-2026-09-01"));
    }

    #[test]
    fn reads_the_pinned_channel() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(toolchain_channel(dir.path()).unwrap(), None);
        std::fs::write(
            dir.path().join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96\"\n",
        )
        .unwrap();
        assert_eq!(
            toolchain_channel(dir.path()).unwrap().as_deref(),
            Some("1.96")
        );
    }

    #[test]
    fn finds_the_built_binary() {
        let messages = [
            r#"{"reason":"compiler-artifact","target":{"name":"hashi-types"},"executable":null}"#,
            r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/t/release/hashi-guardian-init"}"#,
            r#"{"reason":"build-finished","success":true}"#,
        ]
        .join("\n");
        assert_eq!(
            executable(&messages).unwrap(),
            PathBuf::from("/t/release/hashi-guardian-init")
        );
        assert!(executable(r#"{"reason":"build-finished","success":true}"#).is_err());
    }

    #[test]
    fn builds_in_the_tree() {
        let repo = tempfile::tempdir().unwrap();
        let commit = "ef".repeat(20);
        let dir = repo.path().join(".hashi/guardian-init").join(&commit);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.96\"\n",
        )
        .unwrap();
        let exec = Fake::new(|words| {
            match words.get(1).map(String::as_str) {
            Some("--version") => Some((true, "cargo 1.96.0 (e7f5a0a2b 2026-08-25)\n".to_owned())),
            Some("build") => Some((
                true,
                r#"{"reason":"compiler-artifact","target":{"name":"hashi-guardian-init"},"executable":"/x/hashi-guardian-init"}"#
                    .to_owned(),
            )),
            _ => None,
        }
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let tree = Tree::at(&ctx, &commit, "").unwrap();
        assert_eq!(
            tree.guardian_init(&ctx).unwrap().path,
            PathBuf::from("/x/hashi-guardian-init")
        );
        // Under cargo, rustup has set RUSTUP_TOOLCHAIN for this test too, so the build must leave it out.
        if std::env::var_os("RUSTUP_TOOLCHAIN").is_some() {
            for removed in exec.removed_env.borrow().iter() {
                assert!(removed.iter().any(|name| name == "RUSTUP_TOOLCHAIN"));
            }
        }
        let log = exec.log.borrow();
        assert_eq!(
            log[1][1..],
            [
                "build",
                "--release",
                "--locked",
                "-p",
                "hashi-guardian-init",
                "--message-format=json-render-diagnostics",
                "--target-dir",
                &dir.join("target").display().to_string(),
            ]
        );
    }
}
