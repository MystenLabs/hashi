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
use crate::print_detail;
use crate::print_info;
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

    /// The URNs of the resources the plan creates. A replacement isn't one: it plans `create-replacement`.
    pub fn creates(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter(|step| step.op == "create")
            .map(|step| step.urn.as_str())
            .collect()
    }

    /// Prints the changes, as a step shows what it is about to apply.
    pub fn print_changes(&self, target: &str) {
        let changes = self.changes();
        if changes.is_empty() {
            print_info(&format!("Plan for {target}:\nno resource changes"));
        } else {
            print_info(&format!("Plan for {target}:"));
            for change in changes {
                print_detail(&format!("{} {}", change.op, change.urn));
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
                    print_detail(&message);
                }
            }
            Err(_) => print_detail(&output.stdout),
        }
        bail!("could not preview stack {stack}");
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
            "the update of stack {} did not finish; run this step again: it previews the stack first",
            stack.name
        );
    }
    Ok(())
}

/// Stops unless Pulumi is the version `PULUMI_VERSION` pins: the stacks' own automation applies them too, and a newer
/// CLI can write state an older one cannot read.
pub fn require_pulumi_version(ctx: &Ctx) -> Result<()> {
    let pinned = crate::stack::pulumi_pin(ctx)?;
    let current = crate::stack::pulumi_version(ctx)?;
    if current != pinned {
        bail!(
            "this is Pulumi {current}, but PULUMI_VERSION is {pinned}; put Pulumi {pinned} first on your PATH"
        );
    }
    Ok(())
}

/// A resource's type, from its URN `urn:pulumi:<stack>::<project>::<type>::<name>`, where a child's type follows its
/// parents' after a `$`.
pub fn urn_type(urn: &str) -> Option<&str> {
    urn.split("::").nth(2)?.rsplit('$').next()
}

/// A preview's JSON with these steps, as Pulumi prints it, for tests.
#[cfg(test)]
pub fn plan_json(steps: &[(&str, &str)]) -> String {
    let mut steps: Vec<Value> = steps
        .iter()
        .map(|(op, urn)| serde_json::json!({ "op": op, "urn": urn }))
        .collect();
    // As real previews list them: the stack itself, and the proxy's read of the enclave stack.
    steps.push(
        serde_json::json!({ "op": "same", "urn": "urn:pulumi:testnet::enclave::pulumi:pulumi:Stack::enclave-testnet" }),
    );
    steps.push(serde_json::json!({ "op": "read", "urn": "urn:pulumi:testnet::proxy::pulumi:pulumi:StackReference::org/enclave/testnet" }));
    serde_json::json!({ "steps": steps, "changeSummary": { "same": 15 } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCE_B: &str = "urn:pulumi:testnet::enclave::aws:ec2/instance:Instance::guardian-b";

    #[test]
    fn leaves_out_the_stack_and_its_reads() {
        let plan: Plan = serde_json::from_str(&plan_json(&[
            ("same", "urn:a"),
            ("create", INSTANCE_B),
            ("refresh", "urn:c"),
        ]))
        .unwrap();
        assert_eq!(plan.changes(), [Change::new("create", INSTANCE_B)]);
        assert_eq!(plan.creates(), [INSTANCE_B]);
        let replaced: Plan =
            serde_json::from_str(&plan_json(&[("create-replacement", INSTANCE_B)])).unwrap();
        assert!(replaced.creates().is_empty());
    }

    #[test]
    fn reads_a_resources_type_from_its_urn() {
        assert_eq!(urn_type(INSTANCE_B), Some(crate::stack::INSTANCE));
        assert_eq!(
            urn_type("urn:pulumi:testnet::enclave::pkg:index:Host$aws:ec2/instance:Instance::a::b"),
            Some(crate::stack::INSTANCE)
        );
        assert_eq!(urn_type("urn:a"), None);
    }
}
