// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;
use hashi_guardian_ops::Ctx;
use hashi_guardian_ops::exec::System;
use hashi_guardian_ops::exec::require_programs;
use hashi_guardian_ops::stack::Slot;
use hashi_guardian_ops::steps::inspect;

/// Runs one operator step against the guardian stack an environment file names. With two guardian slots, name the
/// slot.
#[derive(Parser)]
#[command(name = "hashi-guardian-ops")]
struct Cli {
    /// The environment file: a copy of operator/guardian.env.sample.
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
    let ctx = Ctx::new(&cli.env_file, &System)?;
    require_programs(&System)?;
    match cli.step {
        Step::Status => inspect::status(&ctx),
        Step::Info { slot } => inspect::info(&ctx, slot),
        Step::Host { slot } => inspect::host(&ctx, slot),
        Step::Tunnel { slot } => inspect::tunnel(&ctx, slot),
    }
}
