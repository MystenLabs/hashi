// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Commands on a guardian host, through SSM.

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::Ctx;
use crate::exec::Cmd;
use crate::exec::read;

/// The host's units: the enclave, the bridge that serves its gRPC port, and its vsock proxies to S3.
pub const UNITS: &str = "hashi-guardian-enclave.service hashi-guardian-bridge.service hashi-vsock-proxy-8101.service hashi-vsock-proxy-8102.service hashi-vsock-proxy-8103.service";

pub struct HostOutput {
    /// What the commands printed, stdout then stderr.
    pub text: String,
    pub success: bool,
}

/// Runs shell commands on a guardian host as one script and returns what they printed, and whether the script ended in
/// success. SSM reports only the last command's status, so a check that must fail the run exits non-zero itself.
pub fn run(ctx: &Ctx, region: &str, instance: &str, commands: &[&str]) -> Result<HostOutput> {
    let command_id = read(
        ctx.exec,
        &aws_ssm(region, "send-command")
            .args(["--instance-ids", instance])
            .args(["--document-name", "AWS-RunShellScript"])
            .args(["--query", "Command.CommandId", "--output", "text"])
            .arg("--parameters")
            .arg(format!("commands={}", serde_json::to_string(commands)?)),
    )
    .with_context(|| {
        format!(
            "Could not send commands to {instance}. A new instance takes a minute to accept them."
        )
    })?
    .trim()
    .to_owned();
    let success = ctx
        .exec
        .output(
            &Cmd::new("aws")
                .args(["ssm", "wait", "command-executed", "--region", region])
                .args(["--command-id", &command_id, "--instance-id", instance]),
        )
        .context("Could not wait for the host's commands.")?
        .success;
    let text = read(
        ctx.exec,
        &aws_ssm(region, "get-command-invocation")
            .args(["--command-id", &command_id, "--instance-id", instance])
            .args(["--query", "[StandardOutputContent, StandardErrorContent]"])
            .args(["--output", "text"]),
    )
    .with_context(|| format!("Could not read what the commands printed on {instance}."))?;
    Ok(HostOutput { text, success })
}

/// The EC2 state of a host, such as `running` or `terminated`, or `None` once EC2 no longer knows it. EC2 says the
/// same of an instance in another account, so `None` needs credentials for `account`, the host's.
pub fn instance_state(
    ctx: &Ctx,
    region: &str,
    instance: &str,
    account: &str,
) -> Result<Option<String>> {
    let output = ctx.exec.output(
        &Cmd::new("aws")
            .args(["ec2", "describe-instances", "--region", region])
            .args(["--instance-ids", instance])
            .args(["--query", "Reservations[].Instances[].State.Name"])
            .args(["--output", "text"])
            .capture_stderr(),
    )?;
    if output.success {
        return Ok(Some(output.stdout.trim().to_owned()));
    }
    if !output.stderr.contains("InvalidInstanceID.NotFound") {
        bail!(
            "Could not read the state of {instance}: {}",
            output.stderr.trim()
        );
    }
    let caller = read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["sts", "get-caller-identity", "--region", region])
            .args(["--query", "Account", "--output", "text"]),
    )
    .context("Could not read which AWS account your credentials are for.")?;
    if caller.trim() != account {
        bail!(
            "EC2 does not know {instance}, but your AWS credentials are for account {}, not {account}, which runs it.",
            caller.trim()
        );
    }
    Ok(None)
}

fn aws_ssm(region: &str, action: &str) -> Cmd {
    Cmd::new("aws").args(["ssm", action, "--region", region])
}

/// The commands the host step runs: the end of the boot log, whether the boot finished, the enclave and the units.
pub fn report_commands() -> Vec<String> {
    vec![
        "tail -n 12 /var/log/hashi-guardian-bootstrap.log".to_owned(),
        // The boot log traces its own commands, so match only the lines the boot itself prints.
        r"grep -E '^\[[^]]*\] hashi-guardian user-data (complete|FAILED)' /var/log/hashi-guardian-bootstrap.log || echo 'The boot has not finished.'".to_owned(),
        "nitro-cli describe-enclaves".to_owned(),
        format!("systemctl is-active {UNITS} || true"),
    ]
}

/// The PCR0 a host's `nitro-cli describe-enclaves` reports.
pub fn reported_pcr0(report: &str) -> Option<&str> {
    const KEY: &str = "\"PCR0\": \"";
    let start = report.find(KEY)? + KEY.len();
    let value = report.get(start..start + 96)?;
    (report[start + 96..].starts_with('"') && crate::stack::is_hex(value, 96)).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::fake::Fake;

    #[test]
    fn runs_commands_as_bash_did() {
        let exec = Fake::new(|words| match (words[2].as_str(), words[3].as_str()) {
            ("send-command", _) => Some((true, "cmd-1\n".to_owned())),
            ("wait", "command-executed") => Some((false, String::new())),
            ("get-command-invocation", _) => Some((true, "out\terr\n".to_owned())),
            _ => None,
        });
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        let commands = report_commands();
        let commands: Vec<&str> = commands.iter().map(String::as_str).collect();
        let output = run(&ctx, "us-west-2", "i-0aaa", &commands).unwrap();
        assert!(!output.success);
        assert_eq!(output.text, "out\terr\n");
        let log = exec.log.borrow();
        assert_eq!(
            log[0][..12],
            [
                "aws",
                "ssm",
                "send-command",
                "--region",
                "us-west-2",
                "--instance-ids",
                "i-0aaa",
                "--document-name",
                "AWS-RunShellScript",
                "--query",
                "Command.CommandId",
                "--output",
            ]
        );
        // SSM reads the JSON array; the grep's backslashes reach the host's shell as one each.
        let parameters: Vec<String> =
            serde_json::from_str(log[0][14].strip_prefix("commands=").unwrap()).unwrap();
        assert_eq!(
            parameters[1],
            r"grep -E '^\[[^]]*\] hashi-guardian user-data (complete|FAILED)' /var/log/hashi-guardian-bootstrap.log || echo 'The boot has not finished.'"
        );
        assert_eq!(
            log[1][6..],
            ["--command-id", "cmd-1", "--instance-id", "i-0aaa"]
        );
    }

    #[test]
    fn takes_a_host_for_gone_only_in_its_own_account() {
        let exec = |account: &'static str| {
            Fake::with_stderr(move |words| {
                match words[1].as_str() {
                "ec2" => Some(crate::exec::Output {
                    success: false,
                    stdout: String::new(),
                    stderr: "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation".to_owned(),
                }),
                "sts" => Some(crate::exec::Output {
                    success: true,
                    stdout: format!("{account}\n"),
                    stderr: String::new(),
                }),
                _ => None,
            }
            })
        };
        let repo = tempfile::tempdir().unwrap();
        let same = exec("111111111111");
        let ctx = Ctx::for_test(repo.path(), &same, &[]);
        assert_eq!(
            instance_state(&ctx, "us-west-2", "i-0aaa", "111111111111").unwrap(),
            None
        );
        let other = exec("222222222222");
        let ctx = Ctx::for_test(repo.path(), &other, &[]);
        assert_eq!(
            instance_state(&ctx, "us-west-2", "i-0aaa", "111111111111")
                .unwrap_err()
                .to_string(),
            "EC2 does not know i-0aaa, but your AWS credentials are for account 222222222222, not 111111111111, which runs it."
        );
    }

    #[test]
    fn finds_the_reported_pcr0() {
        let pcr0 = "0c".repeat(48);
        let report = format!("[\n  {{\n    \"Measurements\": {{\n      \"PCR0\": \"{pcr0}\",\n");
        assert_eq!(reported_pcr0(&report), Some(pcr0.as_str()));
        assert_eq!(reported_pcr0("[]"), None);
        assert_eq!(reported_pcr0("\"PCR0\": \"0c\""), None);
    }
}
