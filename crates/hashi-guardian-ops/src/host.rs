// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! A guardian host: the user-data it was launched with, and commands on it through SSM.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use base64ct::Base64;
use base64ct::Encoding;

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
            "could not send commands to {instance}; a new instance takes a minute to accept them"
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
        .context("could not wait for the host's commands")?
        .success;
    let text = read(
        ctx.exec,
        &aws_ssm(region, "get-command-invocation")
            .args(["--command-id", &command_id, "--instance-id", instance])
            .args(["--query", "[StandardOutputContent, StandardErrorContent]"])
            .args(["--output", "text"]),
    )
    .with_context(|| format!("could not read what the commands printed on {instance}"))?;
    Ok(HostOutput { text, success })
}

fn aws_ssm(region: &str, action: &str) -> Cmd {
    Cmd::new("aws").args(["ssm", action, "--region", region])
}

/// The user-data the host was launched with, which names the commit it builds its guardian from.
pub fn user_data(ctx: &Ctx, region: &str, instance: &str) -> Result<String> {
    let encoded = read(
        ctx.exec,
        &Cmd::new("aws")
            .args(["ec2", "describe-instance-attribute", "--region", region])
            .args(["--instance-id", instance, "--attribute", "userData"])
            .args(["--query", "UserData.Value", "--output", "text"]),
    )
    .with_context(|| format!("could not read the user-data of {instance}"))?;
    let decoded = Base64::decode_vec(encoded.trim())
        .map_err(|_| anyhow!("the user-data of {instance} is not base64"))?;
    Ok(String::from_utf8_lossy(&decoded).into_owned())
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
    fn reads_the_user_data_a_host_was_launched_with() {
        let exec = Fake::new(|words| {
            (words[1] == "ec2").then(|| {
                (
                    true,
                    format!("{}\n", Base64::encode_string(b"#!/bin/bash\necho hi\n")),
                )
            })
        });
        let repo = tempfile::tempdir().unwrap();
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        assert_eq!(
            user_data(&ctx, "us-west-2", "i-0bbb").unwrap(),
            "#!/bin/bash\necho hi\n"
        );
        assert_eq!(
            exec.log.borrow()[0][1..],
            [
                "ec2",
                "describe-instance-attribute",
                "--region",
                "us-west-2",
                "--instance-id",
                "i-0bbb",
                "--attribute",
                "userData",
                "--query",
                "UserData.Value",
                "--output",
                "text",
            ]
        );

        let exec = Fake::new(|_| Some((true, "not base64!\n".to_owned())));
        let ctx = Ctx::for_test(repo.path(), &exec, &[]);
        assert_eq!(
            user_data(&ctx, "us-west-2", "i-0bbb")
                .unwrap_err()
                .to_string(),
            "the user-data of i-0bbb is not base64"
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
