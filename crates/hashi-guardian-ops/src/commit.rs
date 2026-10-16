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
            if resolve(ctx, commit)?.is_none() {
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
}

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
        .with_context(|| format!("Could not run git in {}.", ctx.repo.display()))?;
    Ok(output.success.then(|| output.stdout.trim().to_owned()))
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
}
