// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! GitHub Actions runs: the guardian's PCR0 measurement, which must come from two independent runners, and the proxy
//! image build. Nothing in a rotation runs there.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;

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

/// Stops while a sui-operations workflow that applies the guardian stacks runs, since it would race this step.
pub fn require_no_guardian_runs(ctx: &Ctx) -> Result<()> {
    for workflow in [
        "hashi-guardian-proxy-deploy.yaml",
        "hashi-guardian-rotate.yaml",
    ] {
        for status in ["queued", "in_progress"] {
            let runs = read(
                ctx.exec,
                &Cmd::new("gh")
                    .args(["run", "list", "--repo", "MystenLabs/sui-operations"])
                    .args(["--workflow", workflow, "--status", status])
                    .args(["--json", "databaseId", "--jq", "length"]),
            )
            .with_context(|| format!("Could not list the runs of sui-operations' {workflow}."))?;
            if runs.trim() != "0" {
                bail!(
                    "sui-operations' {workflow} has a run {status}, and it applies the guardian stacks too. Wait for it to finish."
                );
            }
        }
    }
    Ok(())
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
    let url = read(ctx.exec, &cmd).with_context(|| format!("Could not dispatch {workflow}."))?;
    let url = url.trim();
    let id = url.rsplit('/').next().unwrap_or("");
    // The run exists by now, so the message must not read as though dispatching again were safe.
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) {
        bail!("Dispatched {workflow}, but could not tell which run it started: {url}");
    }
    Ok(id.to_owned())
}

/// Waits for a run to finish, and stops unless it succeeded.
pub fn watch(ctx: &Ctx, repo: &str, run_id: &str) -> Result<()> {
    read(
        ctx.exec,
        &Cmd::new("gh").args(["run", "watch", run_id, "--repo", repo, "--exit-status"]),
    )?;
    Ok(())
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
    let featured = log.lines().any(|line| {
        line.split_once("FEATURES:").is_some_and(|(_, rest)| {
            rest.starts_with(char::is_whitespace) && !rest.trim().is_empty()
        })
    });
    if featured {
        bail!(
            "Run {run_id} built with extra features, so it does not measure the guardian's image."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            "a\tgit checkout --progress --force {commit}\nb\tgit checkout --progress --force {commit}\na\tFEATURES: \n"
        );
        require_canonical_build(&log, "1", commit).unwrap();
        let one = format!("a\tgit checkout --progress --force {commit}\n");
        assert!(require_canonical_build(&one, "1", commit).is_err());
        let featured = format!("{log}b\tFEATURES:   non-enclave-dev\n");
        assert!(require_canonical_build(&featured, "1", commit).is_err());
    }
}
