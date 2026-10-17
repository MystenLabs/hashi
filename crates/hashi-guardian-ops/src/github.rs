// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! GitHub Actions runs: the guardian's PCR0 measurement, which must come from two independent runners, and the proxy
//! image build.

use std::fmt;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use serde::Deserialize;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;
use crate::exec::read_json;

/// A workflow file of a GitHub repository.
#[derive(Debug, PartialEq, Eq)]
pub struct Workflow {
    pub repo: String,
    pub file: String,
}

impl Workflow {
    /// Reads `<owner>/<repo>/.github/workflows/<file>`, as a `uses:` line names a workflow, and the `@<ref>` after it.
    fn parse(text: &str) -> Option<(Self, Option<&str>)> {
        let (path, git_ref) = match text.split_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (text, None),
        };
        let (owner, rest) = path.split_once('/')?;
        let (repo, rest) = rest.split_once('/')?;
        let file = rest.strip_prefix(".github/workflows/")?;
        let named = |part: &str| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        };
        let workflow = Self {
            repo: format!("{owner}/{repo}"),
            file: file.to_owned(),
        };
        (named(owner) && named(repo) && !file.is_empty() && !file.contains('/'))
            .then_some((workflow, git_ref))
    }
}

impl fmt::Display for Workflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/.github/workflows/{}", self.repo, self.file)
    }
}

/// `GUARDIAN_PROXY_WORKFLOW`, the workflow the proxy step dispatches, and the branch or tag it runs at.
pub fn proxy_workflow(ctx: &Ctx) -> Result<(Workflow, String)> {
    let text = ctx.env.require("GUARDIAN_PROXY_WORKFLOW")?;
    match Workflow::parse(text) {
        Some((workflow, Some(git_ref)))
            if !git_ref.is_empty()
                && !workflow.file.contains('*')
                && (workflow.file.ends_with(".yml") || workflow.file.ends_with(".yaml")) =>
        {
            Ok((workflow, git_ref.to_owned()))
        }
        _ => bail!(
            "GUARDIAN_PROXY_WORKFLOW is not <owner>/<repo>/.github/workflows/<file>@<branch or tag>: {text}"
        ),
    }
}

/// Stops unless `gh` reports the run a dispatch starts, which it does from 2.87 on.
pub fn require_run_urls(ctx: &Ctx) -> Result<()> {
    let version = read(ctx.exec, &Cmd::new("gh").arg("--version"))
        .context("Could not read the GitHub CLI's version.")?;
    let first = version.lines().next().unwrap_or("");
    let numbers: Vec<u32> = first
        .strip_prefix("gh version ")
        .unwrap_or("")
        .split(|c: char| !c.is_ascii_digit())
        .take(2)
        .filter_map(|part| part.parse().ok())
        .collect();
    match numbers[..] {
        [major, minor] if major > 2 || (major == 2 && minor >= 87) => Ok(()),
        _ => bail!(
            "This step needs GitHub CLI 2.87 or later, which reports the run it dispatches. Found: {first}"
        ),
    }
}

/// Dispatches a workflow and returns the ID of the run it started.
pub fn dispatch(
    ctx: &Ctx,
    repo: &str,
    workflow: &str,
    git_ref: &str,
    inputs: &[(&str, &str)],
) -> Result<String> {
    let mut cmd = Cmd::new("gh").args([
        "workflow", "run", workflow, "--repo", repo, "--ref", git_ref,
    ]);
    for (key, value) in inputs {
        cmd = cmd.arg("-f").arg(format!("{key}={value}"));
    }
    // A failure may come after GitHub has started the run, so neither message reads as though dispatching again were
    // safe.
    let printed = read(ctx.exec, &cmd).with_context(|| {
        format!(
            "Could not tell whether {workflow} was dispatched. Check {repo}'s runs before going on."
        )
    })?;
    let url = printed.trim().lines().last().unwrap_or("");
    // GitHub spells the owner and repository its own way, whatever case the environment file used.
    let runs = format!("https://github.com/{repo}/actions/runs/");
    let id = url
        .get(..runs.len())
        .filter(|start| start.eq_ignore_ascii_case(&runs))
        .and_then(|_| url.get(runs.len()..))
        .unwrap_or("");
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Dispatched {workflow}, but could not tell which run it started: {url}");
    }
    Ok(id.to_owned())
}

/// What GitHub says of a run.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub event: String,
    pub workflow_name: String,
    pub conclusion: String,
}

pub fn run(ctx: &Ctx, repo: &str, run_id: &str) -> Result<Run> {
    read_json(
        ctx.exec,
        &Cmd::new("gh")
            .args(["run", "view", run_id, "--repo", repo])
            .args(["--json", "event,workflowName,conclusion"]),
    )
    .with_context(|| format!("Could not read run {run_id} of {repo}."))
}

/// Waits for a run to finish, and stops unless it succeeded. A watch that fails tells nothing of the run itself, which
/// may still be going or may have succeeded, so its conclusion is asked for then.
pub fn watch(ctx: &Ctx, repo: &str, run_id: &str) -> Result<()> {
    let watched = read(
        ctx.exec,
        &Cmd::new("gh").args(["run", "watch", run_id, "--repo", repo, "--exit-status"]),
    );
    if watched.is_ok() {
        return Ok(());
    }
    let url = format!("https://github.com/{repo}/actions/runs/{run_id}");
    match run(ctx, repo, run_id) {
        Ok(run) if run.conclusion == "success" => Ok(()),
        Ok(run) if !run.conclusion.is_empty() => bail!("Run {url} ended in {}.", run.conclusion),
        _ => bail!("Could not tell how run {url} ends. Check it there before going on."),
    }
}

/// The PCR0 both runners of a measurement agree on, from their `nitro.pcrs` files.
pub fn agreed_pcr0(pcrs: &[String]) -> Result<String> {
    let measured: Vec<&str> = pcrs
        .iter()
        .flat_map(|file| file.lines())
        .filter(|line| line.contains("PCR0"))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    match measured[..] {
        [first, second] if first == second && crate::stack::is_hex(first, 96) => {
            Ok(first.to_owned())
        }
        _ => bail!(
            "The two runners did not agree on one PCR0: {}",
            measured.join(" ")
        ),
    }
}

/// Stops unless a measurement run's log shows it built `commit` on both runners, with no feature that changes the
/// image, such as `non-enclave-dev`.
pub fn require_canonical_build(log: &str, run_id: &str, commit: &str) -> Result<()> {
    let checkout = format!("checkout --progress --force {commit}");
    let checkouts = log.lines().filter(|line| line.contains(&checkout)).count();
    if checkouts != 2 {
        bail!("Run {run_id} did not build {commit} on both runners.");
    }
    // Each runner's steps print their environment, FEATURES among it; the build recipe's own `${FEATURES:+...}` has no
    // space after the colon.
    let features: Vec<&str> = log
        .lines()
        .filter_map(|line| line.split_once("FEATURES:").map(|(_, rest)| rest))
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .collect();
    if features.len() < 2 {
        bail!(
            "Run {run_id}'s log does not show the features of both builds, so it cannot tell they had none."
        );
    }
    if features.iter().any(|rest| !rest.trim().is_empty()) {
        bail!(
            "Run {run_id} built with extra features, so it does not measure the guardian's image."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow(file: &str) -> Workflow {
        Workflow {
            repo: "org/infra".to_owned(),
            file: file.to_owned(),
        }
    }

    #[test]
    fn reads_workflows_as_uses_names_them() {
        let repo = tempfile::tempdir().unwrap();
        let exec = crate::exec::fake::Fake::new(|_| None);
        let proxy = |text: &str| {
            let ctx = Ctx::for_test(repo.path(), &exec, &[("GUARDIAN_PROXY_WORKFLOW", text)]);
            proxy_workflow(&ctx).map_err(|error| error.to_string())
        };
        assert_eq!(
            proxy("org/infra/.github/workflows/proxy.yaml@main").unwrap(),
            (workflow("proxy.yaml"), "main".to_owned())
        );
        assert_eq!(
            proxy("org/infra/.github/workflows/proxy.yml@release/1").unwrap(),
            (workflow("proxy.yml"), "release/1".to_owned())
        );
        for bad in [
            "org/infra/.github/workflows/proxy.yaml",
            "org/infra/.github/workflows/proxy.yaml@",
            "org/infra/.github/workflows/proxy-*@main",
            "org/infra/.github/workflows/nested/proxy.yaml@main",
            "org/infra/workflows/proxy.yaml@main",
            "org/infra/.github/workflows/proxy.json@main",
            "org/in fra/.github/workflows/proxy.yaml@main",
        ] {
            assert_eq!(
                proxy(bad).unwrap_err(),
                format!(
                    "GUARDIAN_PROXY_WORKFLOW is not <owner>/<repo>/.github/workflows/<file>@<branch or tag>: {bad}"
                )
            );
        }
    }

    #[test]
    fn dispatches_only_into_a_run_of_the_workflows_repository() {
        let repo = tempfile::tempdir().unwrap();
        let dispatched = |printed: &'static str, succeeds: bool| {
            let exec = crate::exec::fake::Fake::new(move |_| Some((succeeds, printed.to_owned())));
            let ctx = Ctx::for_test(repo.path(), &exec, &[]);
            dispatch(&ctx, "org/infra", "proxy.yaml", "main", &[])
                .map_err(|error| error.to_string())
        };
        assert_eq!(
            dispatched("https://github.com/org/infra/actions/runs/456\n", true).unwrap(),
            "456"
        );
        assert_eq!(
            dispatched("https://github.com/Org/Infra/actions/runs/456\n", true).unwrap(),
            "456"
        );
        assert!(
            dispatched("https://github.com/org/other/actions/runs/456\n", true)
                .unwrap_err()
                .starts_with("Dispatched proxy.yaml, but could not tell which run it started")
        );
        assert_eq!(
            dispatched("", false).unwrap_err(),
            "Could not tell whether proxy.yaml was dispatched. Check org/infra's runs before going on."
        );
    }

    #[test]
    fn needs_both_runners_to_agree() {
        let pcr0 = "0c".repeat(48);
        let file = |value: &str| format!("{value} PCR0\n{} PCR1\n", "1".repeat(96));
        assert_eq!(agreed_pcr0(&[file(&pcr0), file(&pcr0)]).unwrap(), pcr0);
        assert!(agreed_pcr0(&[file(&pcr0), file(&"0d".repeat(48))]).is_err());
        assert!(agreed_pcr0(&[file(&pcr0)]).is_err());
        assert!(agreed_pcr0(&[file(&pcr0), file(&pcr0), file(&pcr0)]).is_err());
    }

    #[test]
    fn reads_what_the_runners_built() {
        let commit = "0873917ea3daf0ac99e123215808ad602eb5fafb";
        let log = format!(
            "a\tgit checkout --progress --force {commit}\nb\tgit checkout --progress --force {commit}\na\tFEATURES: \nb\tFEATURES: \na\tRUN cargo build ${{FEATURES:+--features \"$FEATURES\"}}\n"
        );
        require_canonical_build(&log, "1", commit).unwrap();
        // A log that doesn't show the features can't show they were empty.
        let unshown = format!(
            "a\tgit checkout --progress --force {commit}\nb\tgit checkout --progress --force {commit}\n"
        );
        assert!(require_canonical_build(&unshown, "1", commit).is_err());
        let one = format!("a\tgit checkout --progress --force {commit}\n");
        assert!(require_canonical_build(&one, "1", commit).is_err());
        let featured = format!("{log}b\tFEATURES:   non-enclave-dev\n");
        assert!(require_canonical_build(&featured, "1", commit).is_err());
    }
}
