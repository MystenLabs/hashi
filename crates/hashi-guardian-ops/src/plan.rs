// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pulumi previews and updates. A target that names nothing is no error to Pulumi, so every step compares a plan's
//! changes with exactly what it expects before applying it.

use std::collections::BTreeMap;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde::Deserialize;
use serde_json::Value;

use crate::Ctx;
use crate::stack::Stack;
use crate::stack::pulumi;

#[derive(Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(rename = "changeSummary", default)]
    pub change_summary: BTreeMap<String, u64>,
}

#[derive(Clone, Deserialize)]
pub struct Step {
    pub op: String,
    pub urn: String,
    #[serde(rename = "oldState")]
    pub old_state: Option<Value>,
    #[serde(rename = "newState")]
    pub new_state: Option<Value>,
    #[serde(rename = "detailedDiff")]
    pub detailed_diff: Option<Value>,
}

/// One resource change: its operation and URN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub op: String,
    pub urn: String,
}

impl Change {
    pub fn new(op: &str, urn: &str) -> Self {
        Self {
            op: op.to_owned(),
            urn: urn.to_owned(),
        }
    }
}

impl Plan {
    /// The plan's resource changes, leaving out the stack's own outputs and reads, such as the proxy's reference to
    /// the enclave stack.
    pub fn changes(&self) -> Vec<Change> {
        self.steps
            .iter()
            .filter(|step| !matches!(step.op.as_str(), "same" | "read" | "refresh"))
            .filter(|step| !step.urn.contains("::pulumi:pulumi:Stack::"))
            .map(|step| Change::new(&step.op, &step.urn))
            .collect()
    }

    /// Prints the changes, as a step shows what it is about to apply.
    pub fn print_changes(&self, target: &str) {
        let changes = self.changes();
        if changes.is_empty() {
            println!("Plan for {target}:\nno resource changes");
        } else {
            println!("Plan for {target}:");
            for change in changes {
                println!("{} {}", change.op, change.urn);
            }
        }
    }
}

/// Previews an up of the stack in `dir`, or of `target` and what depends on it.
pub fn preview(ctx: &Ctx, dir: &str, stack: &str, target: Option<&str>) -> Result<Plan> {
    let mut cmd = pulumi(dir).args(["preview", "--stack", stack]);
    if let Some(target) = target {
        cmd = cmd.args(["--target", target, "--target-dependents"]);
    }
    let output = ctx.exec.output(&cmd.arg("--json"))?;
    if !output.success {
        // With --json, Pulumi reports what failed inside the plan it prints.
        #[derive(Deserialize)]
        struct Failed {
            #[serde(default)]
            diagnostics: Vec<Diagnostic>,
        }
        #[derive(Deserialize)]
        struct Diagnostic {
            message: Option<String>,
        }
        match serde_json::from_str::<Failed>(&output.stdout) {
            Ok(failed) => {
                for message in failed.diagnostics.into_iter().filter_map(|d| d.message) {
                    eprintln!("{message}");
                }
            }
            Err(_) => eprintln!("{}", output.stdout),
        }
        bail!("Could not preview stack {stack}.");
    }
    serde_json::from_str(&output.stdout)
        .map_err(|error| anyhow!("Pulumi printed a plan this step cannot read: {error}"))
}

/// Applies the stack in `dir`, or `target` and what depends on it, with Pulumi's progress on the terminal.
pub fn up(ctx: &Ctx, dir: &str, stack: &str, target: Option<&str>) -> Result<bool> {
    let mut cmd = pulumi(dir).args(["up", "--stack", stack]);
    if let Some(target) = target {
        cmd = cmd.args(["--target", target, "--target-dependents"]);
    }
    Ok(ctx.exec.run(&cmd.arg("--yes"))?)
}

/// Previews a targeted up of one guardian instance and what depends on it, and prints it.
pub fn preview_slot(ctx: &Ctx, stack: &Stack, urn: &str) -> Result<Vec<Change>> {
    let plan = preview(ctx, &stack.dir, &stack.name, Some(urn))?;
    plan.print_changes(urn);
    Ok(plan.changes())
}

/// Applies a targeted up of one guardian instance.
pub fn up_slot(ctx: &Ctx, stack: &Stack, urn: &str) -> Result<()> {
    if !up(ctx, &stack.dir, &stack.name, Some(urn))? {
        bail!(
            "The update of stack {} did not finish. Run this step again: it previews the stack first.",
            stack.name
        );
    }
    Ok(())
}

/// Stops unless Pulumi is the version that last wrote the stack's state. sui-operations' workflows pin a Pulumi CLI,
/// and a newer one can write state that CLI cannot read.
pub fn require_pulumi_version(ctx: &Ctx, dir: &str, stack: &Stack) -> Result<()> {
    let written = crate::stack::written_by(ctx, dir, &stack.name)?;
    let current = crate::stack::pulumi_version(ctx)?;
    if written.is_empty() || written != current {
        bail!(
            "Stack {} in {dir} was last written by Pulumi {}, but this is Pulumi {current}. Put Pulumi {} first on your PATH.",
            stack.name,
            if written.is_empty() {
                "unknown"
            } else {
                &written
            },
            if written.is_empty() {
                "the version sui-operations pins"
            } else {
                &written
            }
        );
    }
    Ok(())
}

/// A preview's JSON with these steps, as Pulumi prints it, for tests.
#[cfg(test)]
pub fn plan_json(steps: &[(&str, &str)]) -> String {
    let mut steps: Vec<Value> = steps
        .iter()
        .map(|(op, urn)| serde_json::json!({ "op": op, "urn": urn }))
        .collect();
    // As real previews list them: the stack itself, and the proxy's read of the enclave stack.
    steps.push(serde_json::json!({ "op": "same", "urn": "urn:pulumi:testnet::hashi-guardian-enclave::pulumi:pulumi:Stack::hashi-guardian-enclave-testnet" }));
    steps.push(serde_json::json!({ "op": "read", "urn": "urn:pulumi:testnet::hashi-guardian-proxy::pulumi:pulumi:StackReference::mysten/hashi-guardian-enclave/testnet" }));
    serde_json::json!({ "steps": steps, "changeSummary": { "same": 15 } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_out_the_stack_and_its_reads() {
        let plan: Plan = serde_json::from_str(&plan_json(&[
            ("same", "urn:a"),
            ("create", "urn:pulumi:testnet::hashi-guardian-enclave::aws:ec2/instance:Instance::hashi-guardian-enclave-b"),
            ("refresh", "urn:c"),
        ]))
        .unwrap();
        assert_eq!(
            plan.changes(),
            [Change::new(
                "create",
                "urn:pulumi:testnet::hashi-guardian-enclave::aws:ec2/instance:Instance::hashi-guardian-enclave-b"
            )]
        );
    }
}
