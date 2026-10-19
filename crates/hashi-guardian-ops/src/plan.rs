// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pulumi previews and updates.

use std::collections::BTreeMap;

use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use serde::Deserialize;

use crate::Ctx;
use crate::print_detail;
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
}

/// Previews an up of the stack in `dir`.
pub fn preview(ctx: &Ctx, dir: &str, stack: &str) -> Result<Plan> {
    let cmd = pulumi(dir).args(["preview", "--stack", stack]);
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

/// Applies the stack in `dir`, with Pulumi's progress on the terminal.
pub fn up(ctx: &Ctx, dir: &str, stack: &str) -> Result<bool> {
    let cmd = pulumi(dir).args(["up", "--stack", stack]);
    Ok(ctx.exec.run(&cmd.arg("--yes"))?)
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
