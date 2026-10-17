// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::bail;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use hashi_guardian_ops::Ctx;
use hashi_guardian_ops::ask::Terminal;
use hashi_guardian_ops::exec::System;
use hashi_guardian_ops::exec::require_programs;
use hashi_guardian_ops::stack::Slot;
use hashi_guardian_ops::steps::configs;
use hashi_guardian_ops::steps::deploy;
use hashi_guardian_ops::steps::inspect;
use hashi_guardian_ops::steps::kp_keys;

/// Runs one operator step against the guardian stack an environment file names. With two guardian slots, name the
/// slot.
#[derive(Parser)]
#[command(name = "hashi-guardian-ops")]
struct Cli {
    /// The environment file: a copy of crates/hashi-guardian-ops/guardian.env.sample.
    env_file: PathBuf,
    #[command(subcommand)]
    step: Step,
}

#[derive(Subcommand)]
enum Step {
    /// Print the stack's slots, the proxy and the relay, changing nothing.
    Status,
    /// Print a slot's guardian through its tunnel, once the proxy is shown to lead to it.
    Info { slot: Option<Slot> },
    /// Print a slot's host: the end of its boot log, its enclave and its units.
    Host { slot: Option<Slot> },
    /// Forward a local port to a slot's guardian. Leave it running in its own terminal.
    Tunnel { slot: Option<Slot> },
    /// Write a slot's configuration for the operator and the key provisioners, and check it with the guardian's tools.
    Render { slot: Option<Slot> },
    /// Publish a slot's configuration to the key provisioners' bucket.
    Publish { slot: Option<Slot> },
    /// Measure a slot's build on GitHub's two runners, or check a run: `measure [slot] [run-id]`.
    Measure {
        #[arg(value_name = "SLOT] [RUN_ID")]
        args: Vec<String>,
    },
    /// Apply the whole enclave stack, for a guardian's first deployment.
    Deploy,
    /// Build the proxy at the active slot's commit and roll it, through the workflow GUARDIAN_PROXY_WORKFLOW names.
    Proxy,
    /// Download and verify every key provisioner's uploaded public key, then write the roster.
    DownloadKpPubkeys {
        /// A directory that doesn't exist yet. Defaults to .hashi/kp-pubkeys/<KP_BUCKET>-<UTC time>.
        out: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("\nERROR: {error}");
            for cause in error.chain().skip(1) {
                eprintln!("  {cause}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let ctx = Ctx::new(&cli.env_file, &System, &Terminal)?;
    require_programs(&System)?;
    match cli.step {
        Step::Status => inspect::status(&ctx),
        Step::Info { slot } => inspect::info(&ctx, slot),
        Step::Host { slot } => inspect::host(&ctx, slot),
        Step::Tunnel { slot } => inspect::tunnel(&ctx, slot),
        Step::Render { slot } => configs::render(&ctx, slot),
        Step::Publish { slot } => configs::publish(&ctx, slot),
        Step::Measure { args } => {
            let (slot, rest) = leading_slot(&args);
            match rest {
                [] => deploy::measure(&ctx, slot, None),
                [run_id] => deploy::measure(&ctx, slot, Some(run_id.clone())),
                _ => bail!("Usage: measure [slot] [run-id]"),
            }
        }
        Step::Deploy => deploy::deploy(&ctx),
        Step::Proxy => deploy::proxy(&ctx),
        Step::DownloadKpPubkeys { out } => kp_keys::download_kp_pubkeys(&ctx, out),
    }
}

/// A step's optional leading slot, which clap can't tell from the positional arguments after it.
fn leading_slot(args: &[String]) -> (Option<Slot>, &[String]) {
    match args.split_first() {
        Some((first, rest)) => match Slot::from_str(first, false) {
            Ok(slot) => (Some(slot), rest),
            Err(_) => (None, args),
        },
        None => (None, args),
    }
}
