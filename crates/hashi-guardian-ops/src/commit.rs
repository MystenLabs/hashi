// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The guardian's own commit. Everything that must match the guardian (its CLI, its protos, the key provisioners'
//! scripts) comes from the tree at that commit, never from the checkout this tool runs from.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;
use crate::print_warning;
use crate::stack::is_hex;

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
            if resolve(ctx, commit)?.is_none() {
                bail!("this checkout does not have {commit}, {whose}; fetch it first");
            }
            extract(ctx, commit, &root, &dir)
                .with_context(|| format!("could not extract {commit} into {}", dir.display()))?;
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
                    "cargo in {} is {}, not toolchain {channel}, which {} pins",
                    self.dir.display(),
                    version.trim(),
                    self.commit
                );
            }
        }
        let path = |relative: &str| {
            self.dir
                .join(relative)
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow!("the tree's path is not UTF-8"))
        };
        let messages = read(
            ctx.exec,
            &cargo(&[
                "build",
                "--manifest-path",
                &path("Cargo.toml")?,
                "--release",
                "--locked",
                "-p",
                "hashi-guardian-init",
                "--message-format=json-render-diagnostics",
                "--target-dir",
                &path("target")?,
            ]),
        )
        .with_context(|| format!("could not build hashi-guardian-init at {}", self.commit))?;
        Ok(GuardianInit {
            path: executable(&messages)?,
        })
    }
}

/// The paths that fix what a guardian sends and what it logs: its protos and the ones they import, and the types its
/// records are made of.
const FORMATS: [&str; 5] = [
    "crates/hashi-types/proto/sui/hashi/v1alpha/guardian_service.proto",
    "crates/hashi-types/proto/sui/hashi/v1alpha/guardian_relay_service.proto",
    "crates/hashi-types/proto/sui/hashi/v1alpha/signature.proto",
    "crates/hashi-types/proto/sui/hashi/v1alpha/utxo.proto",
    "crates/hashi-types/src/guardian",
];

/// The full commit `rev` names in this checkout, if it names one.
pub fn resolve(ctx: &Ctx, rev: &str) -> Result<Option<String>> {
    let output = ctx
        .exec
        .output(&git(&ctx.repo).args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{rev}^{{commit}}"),
        ]))
        .with_context(|| format!("could not run git in {}", ctx.repo.display()))?;
    Ok(output.success.then(|| output.stdout.trim().to_owned()))
}

/// Stops unless `commit` has the guardian protos and log types of `other`, `whose` build: each guardian must read the
/// records the other wrote. A difference passes only for a pair that `GUARDIAN_FORMATS_REVIEWED` lists.
pub fn require_same_formats(ctx: &Ctx, commit: &str, other: &str, whose: &str) -> Result<()> {
    let mut full = Vec::new();
    for rev in [commit, other] {
        let Some(resolved) = resolve(ctx, rev)? else {
            bail!(
                "this checkout does not have {rev}, so it cannot compare {commit} with {whose}; fetch it first"
            );
        };
        full.push(resolved);
    }
    let changed = read(
        ctx.exec,
        &git(&ctx.repo)
            .args(["diff", "--name-only", other, commit, "--"])
            .args(FORMATS),
    )
    .with_context(|| format!("could not compare {commit} with {other}"))?;
    if changed.trim().is_empty() {
        return Ok(());
    }
    let changed = changed.split_whitespace().collect::<Vec<_>>().join(", ");
    let (commit_full, other_full) = (&full[0], &full[1]);
    let reviewed = reviewed_pairs(ctx)?.iter().any(|(a, b)| {
        (a == commit_full && b == other_full) || (a == other_full && b == commit_full)
    });
    if reviewed {
        print_warning(&format!(
            "{commit} changes the guardian's protos or log records from {whose}, {other}: {changed}; going on, as GUARDIAN_FORMATS_REVIEWED lists this pair as reviewed"
        ));
        return Ok(());
    }
    bail!(
        "{commit} changes the guardian's protos or log records from {whose}, {other}: {changed}; a rotation cannot move the key across that without a compatibility review. Once a review finds both builds still read each other's messages and records, add {other_full}..{commit_full} to GUARDIAN_FORMATS_REVIEWED"
    );
}

/// The build pairs `GUARDIAN_FORMATS_REVIEWED` lists, each as `<commit>..<commit>` with full commits, in either order.
fn reviewed_pairs(ctx: &Ctx) -> Result<Vec<(String, String)>> {
    let Some(text) = ctx.env.get("GUARDIAN_FORMATS_REVIEWED") else {
        return Ok(Vec::new());
    };
    text.split_whitespace()
        .map(|entry| {
            entry
                .split_once("..")
                .filter(|(a, b)| is_hex(a, 40) && is_hex(b, 40))
                .map(|(a, b)| (a.to_owned(), b.to_owned()))
                .ok_or_else(|| {
                    anyhow!(
                        "GUARDIAN_FORMATS_REVIEWED lists {entry}, not <commit>..<commit> with full commits"
                    )
                })
        })
        .collect()
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
            .context("could not run the guardian's tools")?;
        Ok(help.contains(name))
    }
}

/// Environment variables that would build with another toolchain or configuration: all of cargo's but where it finds
/// its home, its network and its registries. A parent `cargo run` sets `RUSTUP_TOOLCHAIN`, which outranks the tree's
/// `rust-toolchain.toml`.
fn is_build_override(name: &str) -> bool {
    let keeps = name == "CARGO_HOME"
        || [
            "CARGO_NET_",
            "CARGO_HTTP_",
            "CARGO_REGISTRIES_",
            "CARGO_REGISTRY_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix));
    matches!(name, "RUSTUP_TOOLCHAIN" | "RUSTFLAGS" | "RUSTDOCFLAGS")
        || name.starts_with("RUSTC")
        || (name.starts_with("CARGO") && !keeps)
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
        .with_context(|| format!("{} names no channel", path.display()))
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
        .context("cargo built no hashi-guardian-init binary")
}

/// Extracts beside `dir` and renames into place, so an interrupted extraction never looks complete. Each process
/// extracts into its own directory, since two steps can reach a new commit at once.
fn extract(ctx: &Ctx, commit: &str, root: &Path, dir: &Path) -> Result<()> {
    let partial = root.join(format!(".{commit}.partial-{}", std::process::id()));
    if partial.exists() {
        std::fs::remove_dir_all(&partial)?;
    }
    let renamed = unpack(ctx, commit, &partial).map(|tree| std::fs::rename(tree, dir));
    // The partial directory goes whether or not the extraction finished.
    let cleaned = std::fs::remove_dir_all(&partial);
    match renamed? {
        // Another step's extraction finished first.
        Err(_) if dir.is_dir() => {}
        renamed => renamed?,
    }
    Ok(cleaned?)
}

/// Unpacks `commit` into `partial`'s `tree/`.
fn unpack(ctx: &Ctx, commit: &str, partial: &Path) -> Result<PathBuf> {
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
    Ok(tree)
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
        let exec = Fake::new(|words| (words[3] == "rev-parse").then(|| (false, String::new())));
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let commit = "ab".repeat(20);
        let error = Tree::at(&ctx, &commit, "the commit slot b's guardian runs")
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "this checkout does not have {commit}, the commit slot b's guardian runs; fetch it first"
            )
        );
    }

    #[test]
    fn passes_a_format_difference_only_for_a_reviewed_pair() {
        let repo = tempfile::tempdir().unwrap();
        // Every revision resolves to itself, and the builds differ in one guardian type.
        let exec = Fake::new(|words| match words[3].as_str() {
            "rev-parse" => Some((true, format!("{}\n", words[6].strip_suffix("^{commit}")?))),
            "diff" => Some((
                true,
                "crates/hashi-types/src/guardian/errors.rs\n".to_owned(),
            )),
            _ => None,
        });
        let (new, old, third) = ("aa".repeat(20), "bb".repeat(20), "cc".repeat(20));
        let check = |reviewed: &str| {
            let ctx = Ctx::for_test(
                repo.path(),
                &exec,
                &[("GUARDIAN_FORMATS_REVIEWED", reviewed)],
            );
            require_same_formats(&ctx, &new, &old, "slot b's build").map_err(|e| e.to_string())
        };
        let refused = check("").unwrap_err();
        assert!(
            refused.starts_with(&format!(
                "{new} changes the guardian's protos or log records from slot b's build, {old}: crates/hashi-types/src/guardian/errors.rs;"
            )),
            "{refused}"
        );
        assert!(
            refused.ends_with(&format!("add {old}..{new} to GUARDIAN_FORMATS_REVIEWED")),
            "{refused}"
        );
        check(&format!("{old}..{new}")).unwrap();
        check(&format!("{third}..{old} {new}..{old}")).unwrap();
        // A review of one of the builds against a third covers nothing between these two.
        assert!(
            check(&format!("{new}..{third}"))
                .unwrap_err()
                .contains("without a compatibility review")
        );
        assert_eq!(
            check(&format!("{new}...{old}")).unwrap_err(),
            format!(
                "GUARDIAN_FORMATS_REVIEWED lists {new}...{old}, not <commit>..<commit> with full commits"
            )
        );
        assert!(
            check(&format!("{}..{old}", &new[..12]))
                .unwrap_err()
                .starts_with("GUARDIAN_FORMATS_REVIEWED lists")
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
    fn leaves_nothing_behind_when_the_extraction_fails() {
        let repo = tempfile::tempdir().unwrap();
        let commit = "ef".repeat(20);
        let exec = Fake::new(|words| match words[3].as_str() {
            "rev-parse" => Some((true, format!("{}\n", "ef".repeat(20)))),
            "archive" => Some((false, String::new())),
            _ => None,
        });
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        assert!(Tree::at(&ctx, &commit, "").is_err());
        let root = repo.path().join(".hashi/guardian-init");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
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
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS",
            "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS",
            "CARGO_UNSTABLE_BUILD_STD",
            "RUSTC_WRAPPER",
            "RUSTFLAGS",
            "RUSTDOCFLAGS",
        ] {
            assert!(is_build_override(name), "{name}");
        }
        for name in [
            "CARGO_HOME",
            "CARGO_NET_OFFLINE",
            "CARGO_HTTP_CAINFO",
            "CARGO_REGISTRIES_CRATES_IO_PROTOCOL",
            "RUSTUP_HOME",
            "PATH",
            "HOME",
        ] {
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
                "--manifest-path",
                &dir.join("Cargo.toml").display().to_string(),
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
